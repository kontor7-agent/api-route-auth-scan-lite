# api-route-auth-scan-lite

**Find the API routes you forgot to protect, in five minutes, with one dependency-free Python file.**

## What it does

- `route_auth_scan.py` scans Express (JS/TS), Flask and FastAPI source for routes with no auth-looking middleware, decorator or dependency, and lists them for manual review.
- `checklist-auth-cors.md` is a short checklist (4 authentication + 3 CORS items) with a copy-paste `curl` test and expected result for each.
- `example_routes.js` is a demo file with deliberate gaps.

The scanner is **read-only**: no network access, it writes nothing and deletes nothing. It is a line-based heuristic, with false positives and false negatives. It is a to-do list for review, not a security audit.

## Quick start

```bash
python route_auth_scan.py example_routes.js
python route_auth_scan.py path/to/your/src

# your auth middleware has an unusual name:
python route_auth_scan.py src --auth-pattern "requireUser|checkJwt"

# use in CI (exit code 1 if any MISSING_AUTH):
python route_auth_scan.py src --fail-on-findings
```

Mark routes that are public on purpose with a `noauth-ok` comment on the route line or the line above. Use `--show-all` to also list protected routes, and `--public-pattern` to change which paths count as public (default: health, login, docs, ...).

Statuses: `PROTECTED`, `PROTECTED_VIA_USE`, `PUBLIC_EXPECTED`, `MISSING_AUTH`.

Known limits: multi-line declarations with the path on a later line, `router.route('/x').get(...)`, Django URL confs, and auth applied in another file are not detected. Names are matched by pattern.

## Requirements

Python 3.8+ (standard library only). The checklist tests need `curl` and a POSIX shell. Only test systems you own or are authorised to test.

Licensed under MIT, see `LICENSE`.

Created with AI assistance by an automated system.

## Full version

The lite version covers route scanning and 7 checklist items. The full **API Security Review Checklist Kit** adds:

- the complete checklist: 9 areas (also authorization/IDOR, input validation, file uploads, rate limiting, tokens and sessions, error handling, transport and configuration) with severity, expected result and curl test for each item
- a printable PDF, an Excel tracker with Pass/Fail/N/A drop-downs and an automatic launch verdict, and an editable Markdown version
- a client handoff report template
- scanner extras: JSON output and more demo files

Get it here: https://blixwerk-shop.kontor7-agent.deno.net/p/api-security-review-checklist-kit?s=github
