# 0009. Session auth with Flask-Login, CSRF and rate limits

- Status: accepted
- Date: 2026-10-14

## Context
The web UI needs login (#7). It is server-rendered with HTMX under a strict CSP, single VPS,
multi-tenant schema. Accounts and argon2 hashing exist (#5).

## Decision
- **Flask-Login** for the user session; identity is reloaded per request
  (`services.auth.load_session_user`) so deactivation takes effect immediately.
- **Flask's signed cookie session**, cleared on login and logout, `HttpOnly`, `SameSite=Lax`,
  `Secure` + `__Host-` prefix in prod, 12h lifetime, no remember-me.
- **Flask-WTF `CSRFProtect`** only (no WTForms classes): token in forms and, for HTMX, in
  `<body hx-headers>`; input validation stays in `domain.accounts`.
- **Flask-Limiter** with Redis (in-memory fallback): per-IP and per-email login limits,
  per-IP signup limit. `PROXY_COUNT` + `ProxyFix` give the real client IP behind Caddy.
- **Default deny:** a `before_request` gate; public endpoints are an explicit allow-list.
- Signup toggle `ALLOW_SIGNUP`; the first user can always sign up (instance admin).

## Consequences
- No session store to run, but a stolen cookie can't be revoked before it expires; add a
  server-side session/version check when account management (password change) lands.
- Three small, widely used dependencies (MIT/BSD).
- API (`/api/v1`) gets 401 for anonymous requests; API tokens are a later decision.
