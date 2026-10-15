# Security model

attacksurf is a defensive tool that sends traffic to the internet on behalf of users and handles
their security data. Both make it a target. These rules apply to all code.

## Responsible use

- **Passive checks** (public DNS, Certificate Transparency, RDAP) may run on any registered domain.
- **Active checks** (zone transfer now; port/web probing later) run **only on assets whose
  ownership is verified** (DNS TXT token). ScopeGuard enforces this; scanners cannot bypass it.
- **Out of scope, always:** exploitation, brute forcing, credential attacks, DoS, actually
  claiming takeover-able resources, and scanning of third-party targets.

## Protecting the platform

| Threat | Control |
|---|---|
| SSRF via user targets, redirects, custom LLM `base_url` | ScopeGuard blocks private, loopback, link-local (incl. `169.254.169.254`), CGNAT, reserved and IPv6-equivalent ranges; the safe HTTP client pins the resolved IP and re-checks every redirect |
| Cross-tenant data access | `org_id` on every tenant row, scoped queries, an isolation test per endpoint; links between tenant rows (asset parent, asset relations) use composite foreign keys `(id, org_id)`, so the database itself rejects a link to another org's row; Postgres RLS later |
| XSS from scan data (TXT records, HTML, banners) | Jinja autoescape, never `|safe` on scan data; CSP `default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'` (no `unsafe-inline`/`unsafe-eval`; Alpine CSP build; a test rejects inline script/style/handlers in rendered pages) |
| CSRF | Flask-WTF `CSRFProtect` on every POST/PUT/PATCH/DELETE: hidden `csrf_token` in forms, `X-CSRFToken` header for HTMX via `<body hx-headers>`; `SameSite=Lax` session cookie; logout is POST-only |
| Clickjacking, sniffing, downgrade | `X-Frame-Options: DENY` + `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, HSTS in prod (`web/security.py`) |
| Tampered front-end dependencies | HTMX/Alpine vendored from verified npm tarballs, pinned by `static/vendor/SHA256SUMS` (checked by a test) |
| Information leaks in errors | error pages show static text only; 500s show the request ID, details go to logs |
| Credentials in asset values | URL assets with `user:pass@` are rejected, never stored; error messages don't echo them |
| Prompt injection via scan data | scan data is delimited and size-capped in prompts, output is schema-validated, AI cannot take actions |
| Secret leakage / forged sessions | env vars and connection URLs typed as `SecretStr` (masked in repr); `ENV=prod` refuses to start unless `SECRET_KEY` is ≥ 32 chars and not a placeholder such as `change-me`; org API keys encrypted at rest (Fernet/MultiFernet); structlog redacts secret-looking keys; keys never rendered back in full |
| Log injection | client `X-Request-ID` accepted only if it matches `[A-Za-z0-9-]{1,64}`, otherwise replaced; structured (JSON) logs |
| Malicious uploads *(later)* | never executed; analysis in gVisor sandboxes without network |
| Account attacks | argon2id hashing (`infra/crypto.py`, argon2-cffi defaults, rehash on login when parameters change); passwords 12–1024 chars (upper bound limits hashing DoS), never logged or echoed in errors; emails normalized to lowercase and unique; login passwords over 1024 chars are rejected without hashing the submitted value (a fixed dummy value is hashed instead, so the path costs the same argon2 work for known and unknown accounts; known accounts are audited with reason `password_too_long`); one generic "Invalid email or password" for every failure and equal argon2 work for unknown emails (no account enumeration via login or timing); inactive users can't log in and lose access on their next request; audit log of `user.login`, `user.login_failed` (with reason), `user.logout` (`details` never holds secrets) |
| Brute force | Flask-Limiter (Redis, in-memory fallback): login 5/min and 20/h per IP plus 10/h per email across IPs, signup 5/h per IP, 429 with `Retry-After`; real client IP behind the proxy via `PROXY_COUNT` (`ProxyFix`) |
| Session theft / fixation | signed cookie session cleared on login and logout; `HttpOnly`, `SameSite=Lax`, prod: `Secure` + `__Host-` prefix; absolute lifetime `SESSION_LIFETIME_HOURS` (12h) counted from login and checked server-side (`auth_at` in the session), so activity can't extend it; cookie not re-issued on every request; no remember-me. Known limit: a stolen cookie stays valid until it expires (server-side revocation later) |
| Open redirect | login `next` accepts only same-site paths (`/…`, not `//…`, no scheme/host) |
| Unauthenticated access | default deny (the login gate runs before CSRF validation, so anonymous writes get 401/redirect): every route needs login except `/login`, `/signup`, `/healthz`, static; HTML redirects to login, HTMX gets `HX-Redirect`, `/api/` gets 401 JSON; roles via `@require_role` |
| Supply chain | locked deps (`uv.lock`), only releases at least two weeks old (transitive ones pinned via `[tool.uv] constraint-dependencies`), `pip-audit` in CI, pinned MCP server versions, minimal dependencies |

## Accounts

Signup is open by default (`ALLOW_SIGNUP=true`). With `ALLOW_SIGNUP=false` only the first user
can sign up (the instance admin); everyone else gets 404. The first-user check runs under a
Postgres advisory lock inside the signup transaction, so concurrent bootstrap signups can't both win. Signup reveals whether an email is
already registered (rate-limited); login never does.

## Data sent to LLM providers

Only normalized findings (rule, severity, asset name, trimmed evidence) and aggregate stats.
Never: credentials, API keys, raw uploads. Each AI feature documents its payload here as it is
added. Orgs can disable AI or bring their own provider key.

## Reporting a vulnerability

Open a private security advisory on GitHub rather than a public issue.
