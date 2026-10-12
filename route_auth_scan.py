#!/usr/bin/env python3
"""route_auth_scan.py (lite) - heuristic scan for routes that may be missing auth middleware.

Read-only. No network access. Writes nothing (only prints to the terminal).

Supports (line-based pattern matching, NOT a parser):
  * Node/Express:  app.get('/x', auth, handler)   router.use(auth)  /  app.use('/api', auth)
  * Flask:         @app.route('/x') / @bp.get('/x') with decorators, before_request hooks
  * FastAPI:       @router.get('/x') with Depends(...) in the signature

Per route it reports one of:
  PROTECTED         an auth-looking name appears in the route's middleware/decorators
  PROTECTED_VIA_USE an auth-looking router-level use()/dependency/before_request was seen earlier
  PUBLIC_EXPECTED   path looks public (/login, /health, ...) or the line is marked  noauth-ok
  MISSING_AUTH      nothing auth-looking found -> review by hand

This is a heuristic aid with false positives and false negatives.
It is not a security audit and not a guarantee.
"""
import argparse
import os
import re
import sys

DEFAULT_AUTH = (
    r"auth|jwt|token|passport|session|login_?required|requires?_?(auth|login|user|role|admin|perm)\w*"
    r"|permission|guard|protect|current_?user|bearer|api_?key|\bacl\b|rbac|isLoggedIn|ensureLoggedIn"
)
DEFAULT_PUBLIC = r"^/?(api/)?(v\d+/)?(health|healthz|ping|status|login|logout|register|signup|auth|public|docs|openapi|favicon)"
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "env", "__pycache__", "dist", "build",
             ".tox", ".mypy_cache", "coverage", "site-packages", "__tests__", "tests", "test"}
EXTS = {".js", ".jsx", ".ts", ".mjs", ".cjs", ".py"}
MAX_BYTES = 2_000_000
NOT_ROUTERS = {"axios", "http", "https", "request", "superagent", "session", "cache", "map", "redis",
               "headers", "req", "res", "client", "fetch", "supertest", "agent", "params", "searchparams"}

ROUTE_JS = re.compile(
    r"""^\s*(?P<obj>[A-Za-z_$][\w$]*)\.(?P<m>get|post|put|patch|delete|all)\s*\(\s*"""
    r"""(?P<q>['"`])(?P<path>[^'"`]*)(?P=q)(?P<rest>.*)$""")
USE_JS = re.compile(r"""^\s*(?P<obj>[A-Za-z_$][\w$]*)\.use\((?P<args>.*)\)\s*;?\s*$""")
ROUTE_PY = re.compile(
    r"""^\s*@(?P<obj>[\w.]+)\.(?P<m>route|get|post|put|patch|delete|api_route)\(\s*"""
    r"""(?P<q>['"])(?P<path>[^'"]*)(?P=q)(?P<rest>.*)$""")
DEF_PY = re.compile(r"^\s*(async\s+)?def\s")
STRING_RE = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""")
STATUSES = ["MISSING_AUTH", "PROTECTED_VIA_USE", "PUBLIC_EXPECTED", "PROTECTED"]


def strip_strings(text):
    return STRING_RE.sub("''", text)


def is_comment(stripped):
    return stripped.startswith(("//", "#", "/*", "*"))


def finding(rel, line, method, path, status, note):
    return {"file": rel, "line": line, "method": method, "path": path, "status": status, "note": note}


def decide(rel, lineno, method, path, protected, covered, public_re, suppressed):
    if suppressed:
        return finding(rel, lineno, method, path, "PUBLIC_EXPECTED", "marked noauth-ok")
    if protected:
        return finding(rel, lineno, method, path, "PROTECTED", "auth-looking name in route")
    if covered:
        return finding(rel, lineno, method, path, "PROTECTED_VIA_USE",
                       "router-level auth seen on line %d" % covered)
    if public_re.search(path):
        return finding(rel, lineno, method, path, "PUBLIC_EXPECTED", "path matches public pattern")
    return finding(rel, lineno, method, path, "MISSING_AUTH", "no auth-looking middleware/decorator found")


def scan_js(lines, rel, auth_re, public_re):
    out, uses = [], []
    n = len(lines)
    for i, line in enumerate(lines):
        if is_comment(line.strip()):
            continue
        mu = USE_JS.match(line)
        if mu:
            args = mu.group("args")
            mp = re.match(r"""\s*(['"`])([^'"`]*)\1\s*,""", args)
            prefix = mp.group(2) if mp else ""
            if auth_re.search(strip_strings(args)):
                uses.append((i + 1, mu.group("obj"), prefix))
            continue
        m = ROUTE_JS.match(line)
        if not m:
            continue
        obj, path = m.group("obj"), m.group("path")
        if obj.lower() in NOT_ROUTERS or not (path.startswith("/") or path.startswith("*")):
            continue
        buf, j = m.group("rest"), i
        while (not re.search(r"=>|\bfunction\b", buf) and not re.search(r"\)\s*;?\s*$", buf.rstrip())
               and j < i + 6 and j + 1 < n):
            j += 1
            buf += " " + lines[j].strip()
        cut = re.search(r"=>|\bfunction\b", buf)
        if cut:
            mw = buf[:cut.start()]
        else:
            body = re.sub(r"\)\s*;?\s*$", "", buf.strip()).lstrip(",")
            mw = ",".join(body.split(",")[:-1])
        protected = bool(auth_re.search(strip_strings(mw)))
        covered = 0
        for (uline, uobj, prefix) in uses:
            if uobj == obj and uline < i + 1 and path.startswith(prefix):
                covered = uline
        suppressed = "noauth-ok" in line or (i > 0 and "noauth-ok" in lines[i - 1])
        out.append(decide(rel, i + 1, m.group("m").upper(), path, protected, covered, public_re, suppressed))
    return out


def scan_py(lines, rel, auth_re, public_re):
    out, hooks = [], []
    n = len(lines)
    for i, line in enumerate(lines):
        s = line.strip()
        if is_comment(s) and "noauth-ok" not in s:
            continue
        if re.search(r"dependencies\s*=", line) and auth_re.search(strip_strings(line)):
            hooks.append(i + 1)
        if "before_request" in line and s.startswith("@"):
            block = " ".join(lines[i + 1:i + 16])
            if auth_re.search(strip_strings(block)):
                hooks.append(i + 1)
        m = ROUTE_PY.match(line)
        if not m:
            continue
        chunks = [m.group("rest")]
        k = i - 1
        while k >= 0 and lines[k].strip().startswith("@"):
            chunks.append(lines[k])
            k -= 1
        j = i + 1
        while j < n and j < i + 30 and not DEF_PY.match(lines[j]):
            if lines[j].strip().startswith("@"):
                chunks.append(lines[j])
            j += 1
        if j < n and DEF_PY.match(lines[j]):
            sig, e = lines[j], j
            while not sig.rstrip().endswith(":") and e + 1 < n and e < j + 15:
                e += 1
                sig += " " + lines[e].strip()
            chunks.append(sig[sig.find("("):] if "(" in sig else "")
        protected = bool(auth_re.search(strip_strings(" ".join(chunks))))
        covered = max([h for h in hooks if h < i + 1], default=0)
        if m.group("m") == "route":
            mm = re.search(r"methods\s*=\s*\[(.*?)\]", m.group("rest"))
            methods = re.findall(r"[A-Za-z]+", mm.group(1)) if mm else ["GET"]
        else:
            methods = [m.group("m")]
        suppressed = "noauth-ok" in line or (i > 0 and "noauth-ok" in lines[i - 1])
        for meth in methods:
            out.append(decide(rel, i + 1, meth.upper(), m.group("path"), protected, covered, public_re, suppressed))
    return out


def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p, os.path.basename(p)
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for f in sorted(files):
                low = f.lower()
                if os.path.splitext(low)[1] in EXTS and ".test." not in low and ".spec." not in low \
                        and not low.startswith("test_") and not low.endswith("_test.py"):
                    full = os.path.join(root, f)
                    yield full, os.path.relpath(full, p)


def scan_paths(paths, auth_pattern=DEFAULT_AUTH, public_pattern=DEFAULT_PUBLIC):
    auth_re = re.compile(auth_pattern, re.I)
    public_re = re.compile(public_pattern, re.I)
    results, files = [], 0
    for full, rel in iter_files(paths):
        try:
            if os.path.getsize(full) > MAX_BYTES:
                continue
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        files += 1
        if full.lower().endswith(".py"):
            results += scan_py(lines, rel, auth_re, public_re)
        else:
            results += scan_js(lines, rel, auth_re, public_re)
    return results, files


def main(argv=None):
    ap = argparse.ArgumentParser(description="Heuristic scan for routes missing auth middleware (read-only).")
    ap.add_argument("paths", nargs="+", help="route files or folders to scan")
    ap.add_argument("--auth-pattern", default=DEFAULT_AUTH,
                    help="regex (case-insensitive) for your auth middleware names, e.g. 'requireUser|checkJwt'")
    ap.add_argument("--public-pattern", default=DEFAULT_PUBLIC, help="regex for paths that are public on purpose")
    ap.add_argument("--show-all", action="store_true", help="also list PROTECTED routes")
    ap.add_argument("--fail-on-findings", action="store_true", help="exit 1 if any MISSING_AUTH is found (for CI)")
    a = ap.parse_args(argv)
    for p in a.paths:
        if not os.path.exists(p):
            print("error: path not found: " + p, file=sys.stderr)
            return 2
    try:
        results, files = scan_paths(a.paths, a.auth_pattern, a.public_pattern)
    except re.error as e:
        print("error: invalid regex: %s" % e, file=sys.stderr)
        return 2
    counts = {k: 0 for k in STATUSES}
    for r in results:
        counts[r["status"]] += 1
    print("route_auth_scan: %d files, %d routes (heuristic - review every line by hand)" % (files, len(results)))
    last = None
    for r in sorted(results, key=lambda x: (x["file"], x["line"])):
        if r["status"] == "PROTECTED" and not a.show_all:
            continue
        if r["file"] != last:
            print("\n" + r["file"])
            last = r["file"]
        print("  L%-5d %-7s %-32s %-18s %s" % (r["line"], r["method"], r["path"], r["status"], r["note"]))
    print("\nSummary: " + ", ".join("%s=%d" % (k, v) for k, v in counts.items()))
    print("Reminder: a clean result does NOT mean the API is safe. Auth names are matched by pattern only.")
    if a.fail_on_findings and counts["MISSING_AUTH"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
