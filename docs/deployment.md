# Deployment

Production runs on one VPS behind a **Cloudflare Tunnel** (issue #132). No inbound ports are
published: `cloudflared` dials out to Cloudflare, and everything else is on a private Docker
network.

```
Browser ── TLS ──► Cloudflare edge ──► cloudflared ══ TLS ══► caddy:80 ──► web:5000 (gunicorn)
                        (proxied)        (tunnel)      (re-originated)
```

Cloudflare terminates the visitor's TLS and `cloudflared` re-originates a TLS connection to the
edge. Caddy therefore listens plain HTTP on the private network and does **not** manage a public
certificate; the zone only needs SSL mode **Full** (Cloudflare validates the tunnel's own origin
certificate, which this stack never sees). The app sees one proxy hop (Cloudflare), so
`PROXY_COUNT=1`.

## Files

| File | Purpose |
|---|---|
| `compose.prod.yaml` | the stack: `cloudflared`, `caddy`, `web`, `postgres`, `redis`, one-off `migrate` |
| `deploy/Caddyfile` | `www` → apex redirect, security headers, visitor IP forwarding, proxy to `web` |
| `deploy/Caddy.Dockerfile` | Caddy with this Caddyfile baked in (no plugins needed) |
| `deploy/attacksurf.env.example` | copy of the app env file; filled copy lives on the host |
| `/etc/attacksurf/*` (host, mode 600) | secrets: `tunnel.token`, `postgres_password`, `redis_password` |

## Cloudflare setup (once)

1. **Create the tunnel**: Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared.
   Copy the token (`eyJ...`), not the `cfat_` API token.
2. **Public hostnames** (tunnel → Public Hostnames), both `HTTP` to `caddy:80`:
   - `attacksurf.dev` (apex)
   - `www.attacksurf.dev`
   Cloudflare creates proxied CNAMEs to `<tunnel-id>.cfargotunnel.com`.
3. **SSL/TLS mode**: **Full**. The tunnel presents Cloudflare's own origin certificate, which
   Caddy never handles, so Full (strict) has nothing to validate. Enable **Always Use HTTPS**.

## Host setup (once)

```bash
sudo install -d -m 700 /etc/attacksurf
# Each file: one line, nothing else. `install` sets mode 600 and owner root.
sudo sh -c 'printf %s "$TOKEN" > /etc/attacksurf/tunnel.token'
sudo sh -c 'printf %s "$(openssl rand -hex 32)" > /etc/attacksurf/postgres_password'
sudo sh -c 'printf %s "$(openssl rand -hex 32)" > /etc/attacksurf/redis_password'
sudo chmod 600 /etc/attacksurf/tunnel.token /etc/attacksurf/postgres_password /etc/attacksurf/redis_password
```

Passwords are hex because they are embedded in the `DATABASE_URL`/`REDIS_URL` values; a random
string with `@`, `/` or `:` would need percent-encoding instead.

Compose binds these files into `/run/secrets/`, which is an ordinary mount, not a Swarm secret:
ownership and mode stay those of the host file. Containers that read a secret as non-root cannot
read a root-only file (`cloudflared` runs as uid `65532`, the app as `10001`; `postgres` and
`redis` start as root and do not need this). Grant the reading group only:

```bash
sudo chown 0:65532 /etc/attacksurf/tunnel.token        && sudo chmod 640 /etc/attacksurf/tunnel.token
sudo chown 0:10001 /etc/attacksurf/postgres_password   && sudo chmod 640 /etc/attacksurf/postgres_password
sudo chown 0:10001 /etc/attacksurf/redis_password      && sudo chmod 640 /etc/attacksurf/redis_password
```

Verify with
`docker compose -f compose.prod.yaml exec web sh -c 'id; wc -c < /run/secrets/postgres_password'`.

Then the app env file, from the template (it holds `SECRET_KEY` and `ACME_EMAIL`, never the
passwords above):

```bash
git clone https://github.com/cpt9m0/attacksurf.git /opt/attacksurf
cd /opt/attacksurf
sudo install -m 640 -g "$(id -gn)" deploy/attacksurf.env.example /etc/attacksurf/attacksurf.env
sudo chgrp "$(id -gn)" /etc/attacksurf && sudo chmod 750 /etc/attacksurf
sudoedit /etc/attacksurf/attacksurf.env      # set SECRET_KEY (openssl rand -base64 48), ACME_EMAIL
ln -s /etc/attacksurf/attacksurf.env deploy/attacksurf.env
```

`deploy/attacksurf.env` is git-ignored; the symlink keeps it out of the repo while Compose can
read it as your user. Compose interpolates it even for services that do not load it, so the
symlink (not a copy) is required — otherwise "variable is not set" warnings appear on every call.

## Deploy / update

```bash
cd /opt/attacksurf
git pull
docker compose -f compose.prod.yaml build
docker compose -f compose.prod.yaml run --rm migrate      # alembic upgrade head
docker compose -f compose.prod.yaml up -d
docker compose -f compose.prod.yaml ps
curl -sS -o /dev/null -w '%{http_code}\n' https://attacksurf.dev/healthz   # 200
```

`up -d` replaces `caddy` only after the new image builds; a Caddyfile error makes the container
restart in a loop and the site returns 502. Check the config before deploying:

```bash
docker compose -f compose.prod.yaml run --rm --no-deps --entrypoint caddy caddy \
  validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

`postgres_password` and `redis_password` are read on first start; changing them later means
updating the database's own password too (Redis has no persistence here, so it restarts clean).

## Verifying the entry

```bash
# The site answers through Cloudflare with the app's own response, and www redirects to the apex.
curl -sS -o /dev/null -w '%{http_code}\n' https://attacksurf.dev/healthz       # 200
curl -sSI https://www.attacksurf.dev/ | grep -E '^(HTTP|location)'             # 308 -> apex

# The tunnel is connected (four registered connections) and the stack is healthy.
docker compose -f compose.prod.yaml logs --tail=20 cloudflared | grep -c Registered
docker compose -f compose.prod.yaml ps
```

If the site returns a Cloudflare error, check `cloudflared` logs first (token/route problems),
then Caddy (DNS name `web` unreachable means `web` is not healthy). If a page 308-loops on
itself, the tunnel route points at an HTTPS URL instead of `caddy:80`.

## Rotating secrets

| Secret | How to rotate |
|---|---|
| Tunnel token | Dashboard → tunnel → Refresh token → replace `/etc/attacksurf/tunnel.token` → `up -d cloudflared` |
| `SECRET_KEY` | Replace in `/etc/attacksurf/attacksurf.env` → `up -d web` (all sessions log out) |
| DB/Redis passwords | Update the secret file, change the password in the server, restart both |

## Verifying `attacksurf.dev` as a monitored asset

The instance also scans the project's own domain. After signing in, add `attacksurf.dev` and
choose ownership verification:

- **DNS TXT (preferred)**: the app shows a name like `_attacksurf-challenge.attacksurf.dev`.
  Add it in Cloudflare DNS as **TXT** with the given value, **DNS only** is fine (the check
  queries authoritative DNS directly).
- **HTTP file**: served through Cloudflare's cache, so it can return a stale 404 right after
  you add it. If you must use it, purge the URL in Cloudflare (Caching → Purge) first, then
  re-run verification.

Only the TXT method avoids cache surprises; prefer it.

## Known gaps on this host

The stack covers the web app and its database only. **No Celery workers or beat are running**,
so scans, ownership checks and AI jobs stay queued. Adding `worker-passive`, `worker-ai` and
`beat` is part of #29, together with backups and monitoring; the `x-app` anchor in
`compose.prod.yaml` can be reused for their services.
