# Deployment

Production runs on one VPS behind a **Cloudflare Tunnel** (issue #132). No inbound ports are
published: `cloudflared` dials out to Cloudflare, and everything else is on a private Docker
network.

```
Browser ── TLS ──► Cloudflare edge ──► cloudflared ──► caddy:80 ──► web:5000 (gunicorn)
                        (proxied)        (tunnel)      (DNS-01 cert)
```

Caddy still holds a publicly trusted certificate (issued with Cloudflare's **DNS-01** challenge),
which lets the zone run **Full (strict)** even though the tunnel could serve plain HTTP. The app
sees one proxy hop (Cloudflare), so `PROXY_COUNT=1`.

## Files

| File | Purpose |
|---|---|
| `compose.prod.yaml` | the stack: `cloudflared`, `caddy`, `web`, `postgres`, `redis`, one-off `migrate` |
| `deploy/Caddyfile` | TLS, `www` → apex redirect, security headers, proxy to `web` |
| `deploy/Caddy.Dockerfile` | Caddy + `caddy-dns/cloudflare` plugin |
| `deploy/attacksurf.env.example` | copy of the app env file; filled copy lives on the host |
| `/etc/attacksurf/*` (host, mode 600) | secrets: `tunnel.token`, `cloudflare-dns-token`, `postgres_password`, `redis_password` |

## Cloudflare setup (once)

1. **Create the tunnel**: Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared.
   Copy the token (`eyJ...`), not the `cfat_` API token.
2. **Public hostnames** (tunnel → Public Hostnames), both `HTTP` to `caddy:80`:
   - `attacksurf.dev` (apex)
   - `www.attacksurf.dev`
   Cloudflare creates proxied CNAMEs to `<tunnel-id>.cfargotunnel.com`.
3. **SSL/TLS mode**: Full, then **Full (strict)** once the origin certificate is issued.
   Enable **Always Use HTTPS**.
4. **DNS API token** for Caddy: My Profile → API Tokens → Create Token with
   **Zone → DNS → Edit** and **Zone → Zone → Read**, limited to the `attacksurf.dev` zone.
   Do not use an account-wide token.

## Host setup (once)

```bash
sudo install -d -m 700 /etc/attacksurf
# Each file: one line, nothing else. `install` sets mode 600 and owner root.
sudo sh -c 'printf %s "$TOKEN" > /etc/attacksurf/tunnel.token'
sudo sh -c 'printf %s "$CF_TOKEN" > /etc/attacksurf/cloudflare-dns-token'
sudo sh -c 'printf %s "$(openssl rand -hex 32)" > /etc/attacksurf/postgres_password'
sudo sh -c 'printf %s "$(openssl rand -hex 32)" > /etc/attacksurf/redis_password'
sudo chmod 600 /etc/attacksurf/*
```

Compose binds these files into `/run/secrets/`, which is an ordinary mount, not a Swarm secret:
ownership and mode stay those of the host file. Containers that read a secret as non-root cannot
read a root-only file (`cloudflared` runs as uid `65532`, the app as `10001`; `caddy`,
`postgres` and `redis` start as root and do not need this). Grant the reading group only:

```bash
sudo chown 0:65532 /etc/attacksurf/tunnel.token        && sudo chmod 640 /etc/attacksurf/tunnel.token
sudo chown 0:10001 /etc/attacksurf/postgres_password   && sudo chmod 640 /etc/attacksurf/postgres_password
sudo chown 0:10001 /etc/attacksurf/redis_password      && sudo chmod 640 /etc/attacksurf/redis_password
```

`cloudflare-dns-token` stays root-only (`600`): only Caddy reads it, and it runs as root.
Verify with `docker compose -f compose.prod.yaml exec web sh -c 'id; wc -c < /run/secrets/postgres_password'`.

Then the app env file, from the template (it holds `SECRET_KEY`, never the passwords above):

```bash
git clone https://github.com/cpt9m0/attacksurf.git ~/attacksurf
cd ~/attacksurf
mkdir -p deploy
sudo install -m 600 deploy/attacksurf.env.example /etc/attacksurf/attacksurf.env
sudoedit /etc/attacksurf/attacksurf.env      # set SECRET_KEY (openssl rand -base64 48)
ln -s /etc/attacksurf/attacksurf.env deploy/attacksurf.env
```

`deploy/attacksurf.env` is git-ignored; the symlink keeps it out of the repo while Compose can
read it.

## Deploy / update

```bash
cd ~/attacksurf
git pull
docker compose -f compose.prod.yaml build
docker compose -f compose.prod.yaml run --rm migrate      # alembic upgrade head
docker compose -f compose.prod.yaml up -d
docker compose -f compose.prod.yaml ps
curl -sS -o /dev/null -w '%{http_code}\n' https://attacksurf.dev/healthz   # 200
```

`postgres_password` and `redis_password` are read on first start; changing them later means
updating the database's own password too (Redis has no persistence here, so it restarts clean).

## Verifying TLS and proxying

```bash
# Origin certificate is trusted (this is what allows Full (strict)):
docker compose -f compose.prod.yaml exec caddy \
  sh -c 'echo | openssl s_client -connect 127.0.0.1:443 -servername attacksurf.dev 2>/dev/null | openssl x509 -noout -subject -issuer -dates'

# Visitor IP reaches the app rather than Cloudflare's edge (logs show client_ip).
docker compose -f compose.prod.yaml logs caddy | tail
```

If issuance fails, the Caddy logs name the reason (usually a token lacking `#dns_records:edit`
or wrong zone scope). Caddy retries; no action is needed beyond fixing the token file and
`docker compose -f compose.prod.yaml restart caddy`.

## Rotating secrets

| Secret | How to rotate |
|---|---|
| Cloudflare DNS token | New token in the dashboard → replace `/etc/attacksurf/cloudflare-dns-token` → `restart caddy` |
| Tunnel token | Dashboard → tunnel → Refresh token → replace file → `up -d cloudflared` |
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

## Out of scope (still #29)

Nightly off-box `pg_dump` and restore test, Sentry, log rotation, GHCR-based deploys, host
hardening checklist, and moving to a dedicated VPS.
