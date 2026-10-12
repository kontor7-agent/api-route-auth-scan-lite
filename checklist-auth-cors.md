# API Security Checklist (Lite): Authentication & CORS

Use against **your own staging** system only. Set `BASE` (e.g. `export BASE=https://staging.example.com`) and `TOKEN` (a normal user's access token). Tick each box when the EXPECT line holds. A failed Critical item should block launch.

This is a checklist, not a security audit and not a guarantee.

## Authentication

- [ ] **AUTH-01 (Critical) Every non-public route requires authentication.**
  Run `route_auth_scan.py`, then read the routes. Each is on a written public list or behind auth.
  EXPECT: 401 without credentials on protected routes.
  ```
  curl -i "$BASE/api/users"
  curl -i -X POST "$BASE/api/orders" -H "Content-Type: application/json" -d '{}'
  ```

- [ ] **AUTH-02 (Critical) Default-deny: auth is applied at router/app level.**
  Auth is mounted on the router/app (`router.use(auth)`, `Depends` on the APIRouter, `before_request`); public routes are the exception.
  EXPECT: every method returns 401 without credentials (not 200, 404 or 500).
  ```
  for m in GET POST PUT PATCH DELETE; do
    curl -s -o /dev/null -w "$m %{http_code}\n" -X $m "$BASE/api/users/1"
  done
  ```

- [ ] **AUTH-03 (High) Auth cannot be bypassed with path or method tricks.**
  Trailing slash, upper case, double slash, encoding, HEAD, old `/v1` paths.
  EXPECT: 401 or 404 for every variant, never the data.
  ```
  curl -i "$BASE/api/users/"
  curl -i "$BASE//api/users"
  curl -i "$BASE/API/users"
  curl -i -I "$BASE/api/users"
  ```

- [ ] **AUTH-04 (High) Debug, admin and docs endpoints are removed or protected.**
  EXPECT: 401, 403 or 404 in production.
  ```
  for p in /debug /admin /actuator/env /swagger.json /docs /openapi.json /graphql /metrics /.env; do
    curl -s -o /dev/null -w "$p %{http_code}\n" "$BASE$p"
  done
  ```

## CORS

- [ ] **CORS-01 (Critical) Origin allowlist; no wildcard with credentials; no reflection.**
  EXPECT: no `Access-Control-Allow-Origin` header for the evil origin.
  ```
  curl -s -D - -o /dev/null "$BASE/api/me" -H "Origin: https://evil.example" -H "Authorization: Bearer $TOKEN" | grep -i "access-control"
  ```

- [ ] **CORS-02 (High) The `null` origin is not allowed.**
  EXPECT: no `Access-Control-Allow-Origin: null`.
  ```
  curl -s -D - -o /dev/null "$BASE/api/me" -H "Origin: null" | grep -i "access-control"
  ```

- [ ] **CORS-03 (High) Allowlist matching is exact (no substring / endsWith / loose regex).**
  EXPECT: look-alike origins get no CORS headers. Replace `app.example.com` with your origin.
  ```
  curl -s -D - -o /dev/null "$BASE/api/me" -H "Origin: https://app.example.com.evil.example" | grep -i "access-control"
  curl -s -D - -o /dev/null "$BASE/api/me" -H "Origin: https://evilapp.example.com" | grep -i "access-control"
  ```

## Notes

Reviewer: ____________  Date: ____________  Result: ____________
