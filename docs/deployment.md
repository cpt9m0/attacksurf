# Deployment

Production runs on one VPS behind a **Cloudflare Tunnel** (issue #132). No inbound ports are
published: `cloudflared` dials out to Cloudflare, and everything else is on a private Docker
network.

```
Browser ── TLS ──► Cloudflare edge ◄══ TLS ══► cloudflared ── HTTP ──► caddy:80 ──► web:5000
                    (proxied)      (tunnel's own leg)  (private network)
```

Cloudflare terminates the visitor's TLS, and `cloudflared`'s encrypted leg is to the Cloudflare
edge, not to Caddy. The local service leg is plain HTTP on a private Docker network, so Caddy does
**not** manage a certificate and the public hostname must point at `http://caddy:80`, never
`https://caddy:443`. The zone only needs SSL mode **Full**; the app still sees one proxy hop
(Cloudflare), so `PROXY_COUNT=1`.

## How a change reaches production

Deploys are **pull-based**: the host checks `origin/main` every few minutes and converges on it.
Nothing dials in — no inbound port, no GitHub secret, no self-hosted runner.

```
merge to main
     │
     ▼
attacksurf-deploy.timer   (3 min after the previous run started, + up to 45 s jitter)
     │
     ▼
attacksurf-deploy.service (Type=oneshot, root, flock)
     │
     ▼
scripts/deploy.sh  ──► fetch ──► build attacksurf-web:<sha> ──► migrate ──► up -d --wait
                          ▲                                                      │
                          └──────────── roll back to the previous SHA ◄── /healthz fails
```

The script records the SHA it deployed in `/var/lib/attacksurf/deployed-sha` and prints it to the
journal, so "what is live" is one command away. A failed build, migration or health check leaves
the previous version serving and exits non-zero; a timer tick that lands while a deploy is still
running exits immediately without doing anything.

## Files

| File | Purpose |
|---|---|
| `compose.prod.yaml` | the stack: `cloudflared`, `caddy`, `web`, `worker-passive`, `worker-ai`, `beat`, `postgres`, `redis`, one-off `migrate`; all hardened with `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, resource/PID caps, `internal` network isolation, and bounded `json-file` log rotation |
| `deploy/Caddyfile` | `www` → apex redirect, security headers, visitor IP forwarding, proxy to `web` |
| `deploy/Caddy.Dockerfile` | non-root Caddy (`uid 10001`) with this Caddyfile baked in (no plugins needed) |
| `deploy/attacksurf.env.example` | copy of the app env file; filled copy lives on the host |
| `deploy/backup.env.example` | template for `/etc/attacksurf/backup.env` (`0600` rclone S3/R2/B2 + optional `age` key) |
| `scripts/deploy.sh` | the deploy: bootstrap checkout, fetch, build, migrate, replace the long-running services, smoke test, roll back, prune older `attacksurf-web` tags |
| `scripts/backup.sh` | nightly `pg_dump --format=custom`, `pg_restore --list` check, optional `age` encryption, SHA-256 sidecar, `rclone` upload, retention prune |
| `scripts/restore.sh` | `--verify-only` restore drill into throwaway DB, or `--live` recovery with pre-restore safety dump |
| `deploy/systemd/attacksurf-deploy.*` | pull-based CD units (`flock` + `3 min` timer) |
| `deploy/systemd/attacksurf-backup.*` | nightly backup units (`flock` + `03:15 UTC` timer) |
| `deploy/systemd/README.md` | unit installation, operation and troubleshooting in isolation |
| `.github/workflows/release.yml` | tag-triggered (`v*.*.*`) multi-arch (`amd64`/`arm64`) prod image publish to GHCR |
| `/etc/attacksurf/*` (host, mode 600) | secrets: `tunnel.token`, `postgres_password`, `redis_password`, `backup.env` |
| `/var/lib/attacksurf/deployed-sha` (host) | full SHA of the last successful deploy |
| `/var/lock/attacksurf-*.lock` (host) | `flock` targets: deploys and backups never overlap |

## Cloudflare setup (once)

1. **Create the tunnel**: Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared.
   Copy the **tunnel token** (`eyJ...`). No Cloudflare API token is needed: this stack never
   issues certificates of its own.
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
# Read the token with `read -rs` so it stays out of the shell history; sudo does not carry the
# variable over, so pipe it in rather than using `sudo sh -c '... $TOKEN ...'` (that writes "").
read -rsp 'Tunnel token: ' TOKEN && echo
printf %s "$TOKEN" | sudo tee /etc/attacksurf/tunnel.token >/dev/null
unset TOKEN
# `tr -d '\n'`: `tee` adds a newline, and it would be embedded in the connection URLs.
openssl rand -hex 32 | tr -d '\n' | sudo tee /etc/attacksurf/postgres_password >/dev/null
openssl rand -hex 32 | tr -d '\n' | sudo tee /etc/attacksurf/redis_password >/dev/null
sudo chmod 600 /etc/attacksurf/tunnel.token /etc/attacksurf/postgres_password /etc/attacksurf/redis_password
sudo wc -c /etc/attacksurf/tunnel.token   # non-zero: an empty file breaks cloudflared
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

Then the app env file, from the template (it holds `SECRET_KEY`, never the
passwords above):

```bash
git clone https://github.com/cpt9m0/attacksurf.git /opt/attacksurf
cd /opt/attacksurf
sudo install -m 640 -g "$(id -gn)" deploy/attacksurf.env.example /etc/attacksurf/attacksurf.env
sudo chgrp "$(id -gn)" /etc/attacksurf && sudo chmod 750 /etc/attacksurf
sudoedit /etc/attacksurf/attacksurf.env      # set SECRET_KEY (openssl rand -base64 48)
ln -s /etc/attacksurf/attacksurf.env deploy/attacksurf.env
```

`deploy/attacksurf.env` is git-ignored; the symlink keeps it out of the repo while Compose can
read it as your user. Compose interpolates it even for services that do not load it, so the
symlink (not a copy) is required — otherwise "variable is not set" warnings appear on every call.

`/opt/attacksurf` is the checkout the deploy works in. A host that still carries the pre-CD copied
tree (no `.git`) needs one manual step first, because the script cannot fetch itself — copy it
from a clone of the repo:

```bash
sudo install -D -m 755 scripts/deploy.sh /opt/attacksurf/scripts/deploy.sh
```

After that the script bootstraps the checkout itself: it runs `git init`, adds `origin`, fetches,
and checks out the target commit in place. Tracked files that drifted are overwritten; ignored
files (`deploy/attacksurf.env`) and untracked files are left alone, so a deploy never deletes
local state.

### Install the deploy units

The timer is the entry point; the service unit has no `[Install]` section on purpose.

```bash
cd /opt/attacksurf
sudo install -m 644 deploy/systemd/attacksurf-deploy.service \
                     deploy/systemd/attacksurf-deploy.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

**Do not enable the timer yet** — read "Before you enable the timer" below. First run the deploy
once by hand; that creates `/var/lib/attacksurf/` and the first `deployed-sha` file:

```bash
sudo make deploy
```

Then:

```bash
sudo systemctl enable --now attacksurf-deploy.timer
systemctl list-timers attacksurf-deploy.timer      # NEXT / LAST / PASSED
```

## Continuous deployment (primary flow)

### What the timer does

- **Interval**: `OnBootSec=2min`, then `OnUnitActiveSec=3min`, `RandomizedDelaySec=45s`,
  `AccuracySec=1s`. `OnUnitActiveSec` counts from the previous *start*, so a slow build delays
  the next tick instead of stacking runs. A merge to `main` is live within ~3 minutes (plus up
  to 45 s jitter), or as soon as the running build finishes.
- **Lock**: the unit runs
  `flock --nonblock --conflict-exit-code 0 /var/lock/attacksurf-deploy.lock`. A second run — a
  manual `systemctl start` or a tick that lands mid-build — exits 0 immediately. A tick with no
  journal output is that guard working, not a failed deploy.
- **Root unit**: `Type=oneshot`, `User=root`, `WorkingDirectory=/opt/attacksurf`,
  `Wants=network-online.target docker.service`, `TimeoutStartSec=30min`, `Nice=10`. Root is
  required because the secrets in `/etc/attacksurf/` are mode 600 root-owned and the docker
  socket is root-equivalent. Do not replace it with a `docker`-group user. `Wants=` (not
  `Requires=`) means a docker restart never SIGTERMs a deploy halfway; a run that cannot reach
  docker fails on its own and the next tick retries.
- **What the script does**, in order:
  1. bootstrap/refresh the checkout in `/opt/attacksurf` and `git fetch origin main`;
  2. resolve the target — `origin/main`, or the SHA you passed — and refuse anything that is not
     merged into `origin/main`;
  3. refuse to deploy from a dirty tracked tree, from local commits not on `main`, or from a
     checkout that is behind `main` and is not what production runs (untracked files are fine
     and are left in place);
  4. exit 0 with no container churn if that SHA is already deployed and its image is running;
  5. `git checkout --detach <sha>`, build `web` as `attacksurf-web:<short-sha>`, rebuild `caddy`
     (a cache no-op unless the Caddyfile changed);
  6. run the one-off `migrate` service **before** `web` is replaced — a migration failure exits
     non-zero with the old `web` still serving;
  7. `up -d --wait` on the long-running services (no `down`, no `-v`: `postgres`/`redis` and
     their volumes keep running);
  8. smoke-test `/healthz` through Caddy to `web:5000` (15 attempts, 2 s apart); on a failed
     `up` or a failed smoke test, roll back to the previously deployed SHA, rebuild and
     `up -d --wait` it again, then exit non-zero;
  9. write the full SHA to `/var/lib/attacksurf/deployed-sha` and log it.

  Rollback does **not** reverse migrations: schema changes are forward-only, and the previous
  code is expected to run against the migrated database. A `[deploy] CRITICAL:` line means the
  automatic rollback also failed — go to "Manual deploy and recovery".

Environment overrides (all optional, see `sudo scripts/deploy.sh --help`): `APP_DIR`
(`/opt/attacksurf`), `REPO_URL`, `BRANCH` (`main`), `COMPOSE_FILE` (`compose.prod.yaml`),
`STATE_DIR` (`/var/lib/attacksurf`), `HEALTH_ATTEMPTS` / `HEALTH_DELAY` (15 / 2).

### Check what is live

```bash
cat /var/lib/attacksurf/deployed-sha                     # what the script last deployed
git -C /opt/attacksurf rev-parse HEAD                    # what the checkout holds
journalctl -u attacksurf-deploy -n 50 --no-pager         # the deploy log, SHA included
systemctl list-timers attacksurf-deploy.timer            # is the timer firing?
docker inspect --format '{{.Config.Image}}' attacksurf-prod-web-1   # attacksurf-web:<sha>
curl -sS -o /dev/null -w '%{http_code}\n' https://attacksurf.dev/healthz   # 200
```

The journal line for a successful run reads
`[deploy] deployed <full-sha> (attacksurf-web:<short-sha>) — recorded in /var/lib/attacksurf/deployed-sha`;
an idempotent run logs `[deploy] already deployed: ... is live; nothing to do`.

Compare what is live with `main`:

```bash
git ls-remote https://github.com/cpt9m0/attacksurf.git refs/heads/main
```

If the two differ, either the timer has not fired yet (wait one interval) or the deploy failed —
`journalctl -u attacksurf-deploy` says which.

### Deploy by hand

```bash
cd /opt/attacksurf
sudo make deploy                 # deploy origin/main, same script the timer runs
sudo make deploy SHA=<sha>       # deploy a specific commit; it must be on origin/main
```

`sudo scripts/deploy.sh [SHA]` is the same thing without `make`, and
`sudo systemctl start attacksurf-deploy` runs it through the unit (journal included). The manual
run takes the same lock as the timer: if a deploy is already running, it exits 0 without doing
anything, so check `journalctl` afterwards.

`make deploy` needs root — the script reads `/etc/attacksurf` and drives the Docker daemon — and
refuses to run otherwise. It is not the dev `make up`: it targets `compose.prod.yaml` only.

### Before you enable the timer

**Branch protection + required CI checks are the actual safety gate.** The timer deploys
whatever lands on `main`; the script's rollback covers a failed *deploy*, not a bad-but-green
*change*.

Confirm protection is on (a 404 means it is not):

```bash
gh api repos/cpt9m0/attacksurf/branches/main/protection
```

Enable it in Settings → Branches → `main` with:

- require a pull request before merging (no direct pushes),
- require the CI checks to pass: `lint`, `test`, `secrets`, `compose`,
- block force pushes and deletions.

Do not enable the timer until that is in place.

## Manual deploy and recovery

These are the pre-CD steps, kept as the recovery path. The script automates them; use them when
the timer, the script, or a deploy has gone wrong. All of them run on the host as root.

### Deploy by hand, step by step (script broken)

```bash
cd /opt/attacksurf
sudo systemctl stop attacksurf-deploy.timer     # keep the timer from racing the manual run

sudo git fetch origin
sudo git checkout --detach <sha>                # a commit on origin/main
SHORT=$(git rev-parse --short=12 HEAD)

# WEB_IMAGE is what tags the image; without it Compose falls back to attacksurf:prod and the
# running container stops matching what deploy.sh records.
sudo env WEB_IMAGE="attacksurf-web:$SHORT" docker compose -f compose.prod.yaml build web
sudo env WEB_IMAGE="attacksurf-web:$SHORT" docker compose -f compose.prod.yaml run --rm migrate
sudo env WEB_IMAGE="attacksurf-web:$SHORT" docker compose -f compose.prod.yaml up -d --wait web
sudo docker compose -f compose.prod.yaml ps
curl -sS -o /dev/null -w '%{http_code}\n' https://attacksurf.dev/healthz   # 200

# Record what you deployed, so the script and the timer agree with reality.
git rev-parse HEAD | sudo tee /var/lib/attacksurf/deployed-sha
sudo systemctl start attacksurf-deploy.timer
```

Writing `deployed-sha` by hand matters: it is the script's "already deployed" marker, and a
stale value makes the next tick rebuild and replace `web` for nothing.

`up -d --wait` replaces `caddy` only after the new image builds; a Caddyfile error makes the
container restart in a loop and the site returns 502. Check the config before deploying:

```bash
sudo docker compose -f compose.prod.yaml run --rm --no-deps --entrypoint caddy caddy \
  validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

`postgres_password` and `redis_password` are read on first start; changing them later means
updating the database's own password too (Redis has no persistence here, so it restarts clean).

### Roll back to a previous SHA

Use this when a deploy is live but wrong (500s, a broken page) and the automatic rollback did not
fire, or when you need to go back further than one commit.

1. **Find the SHA that was good.** The journal records every deploy; `git log` shows the
   candidates:

   ```bash
   journalctl -u attacksurf-deploy --no-pager | grep '\[deploy\] deploying' | tail -20
   cd /opt/attacksurf && git log --oneline -10
   ```

2. **Stop the timer**, or it puts `main` back within 3 minutes:

   ```bash
   sudo systemctl stop attacksurf-deploy.timer
   ```

3. **Deploy the good SHA.** If the bad release added no migration, the script does the whole
   rollback for you and records it:

   ```bash
   cd /opt/attacksurf
   sudo make deploy SHA=<good-sha>
   ```

   If a migration shipped with the bad release, the script's `migrate` step fails: the old code
   does not contain the new migration, so `alembic upgrade head` cannot resolve the database's
   current revision. It exits before touching `web`, and you finish by hand without `migrate`:

   ```bash
   cd /opt/attacksurf
   sudo git checkout --detach <good-sha>
   SHORT=$(git rev-parse --short=12 HEAD)
   sudo env WEB_IMAGE="attacksurf-web:$SHORT" docker compose -f compose.prod.yaml build web
   sudo env WEB_IMAGE="attacksurf-web:$SHORT" docker compose -f compose.prod.yaml up -d --wait web
   ```

   Migrations are forward-only by design: the old code is expected to run against the migrated
   database. Only if it genuinely cannot (a destructive column rename) do you undo the schema,
   and then only after a dump (`pgdata` below):

   ```bash
   sudo env WEB_IMAGE="attacksurf-web:$SHORT" docker compose -f compose.prod.yaml \
     run --rm --no-deps web alembic downgrade -1
   ```

4. **Verify, then record the rollback:**

   ```bash
   sudo docker compose -f compose.prod.yaml ps
   curl -sS -o /dev/null -w '%{http_code}\n' https://attacksurf.dev/healthz   # 200
   git rev-parse HEAD | sudo tee /var/lib/attacksurf/deployed-sha
   ```

5. **Fix forward before restarting the timer.** The timer deploys `origin/main`, so while the bad
   commit is still on `main`, re-enabling it redeploys the bad SHA. Revert it on `main`
   (`git revert <bad-sha>` through a PR) or leave the timer stopped until the fix merges, then:

   ```bash
   sudo systemctl start attacksurf-deploy.timer
   ```

### If the timer or script itself is broken

A failing timer is not an outage: the site keeps serving the last good image. Deploy by hand
with the steps above, then fix the script. To see why a run failed:

```bash
systemctl status attacksurf-deploy.service
journalctl -u attacksurf-deploy -n 100 --no-pager
sudo fuser -v /var/lock/attacksurf-deploy.lock    # a stuck run still holds the lock
```

Common causes, in the order they appear in the journal:

| Journal says | Meaning |
|---|---|
| nothing at all | `flock` skipped the run because a deploy is in progress |
| `working tree in /opt/attacksurf is dirty` | a tracked file was edited in the checkout; `git status` shows it |
| `HEAD (...) has commits that are not on origin/main` | someone committed on the host; move that work to a PR |
| `commit ... is not on origin/main` | you asked for a SHA that is not merged |
| `migration failed; web was not replaced` | the migration is broken; the old version is still live |
| `CRITICAL: ...` | the automatic rollback failed too; roll back by hand |

### `pgdata` must survive rebuilds

`postgres` keeps its data in the named volume `pgdata` — Compose names it
`attacksurf-prod_pgdata`, mounted at `/var/lib/postgresql`. Rebuilding images, `up -d --wait`
and `docker compose down` all keep it; **`docker compose down -v` deletes it**, and the deploy
path never runs `down` or `-v`. If you ever type `down -v` on this host, the database is gone.

Check it is still there:

```bash
sudo docker volume inspect attacksurf-prod_pgdata --format '{{.Name}} {{.Mountpoint}}'
```

Before a risky migration or a downgrade, dump it:

```bash
sudo docker compose -f compose.prod.yaml exec -T postgres \
  pg_dump -U attacksurf attacksurf | gzip > "attacksurf-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
```

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

Rotations are manual; the timer keeps deploying `main` while you do them, and a `web` restart
from a deploy picks up a new `SECRET_KEY` the same way.

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

## Upload size limits

Three limits apply to `POST /assets/upload` and `POST /assets/upload-binary`, and the smallest
wins: **Cloudflare** rejects request bodies over 100 MB on Free and Pro plans,
`deploy/Caddyfile` allows 257 MiB on those paths
(2 MB elsewhere), and the app allows `ARTIFACT_MAX_BYTES` (default 256 MiB) plus framing. So
behind the tunnel an archive over 100 MB fails at the edge with Cloudflare's own 413 page.
Raising `ARTIFACT_MAX_BYTES` also means raising both the Caddyfile value and `web`'s `/tmp` `tmpfs`
(`320m`) + `mem_limit` (`1g`) in `compose.prod.yaml` (Linux cgroups v2 counts `tmpfs` pages against
`mem_limit`). Gunicorn runs with `--timeout 120 --graceful-timeout 30 --max-requests 1000
--max-requests-jitter 100 --worker-tmp-dir /dev/shm` so slow uploads do not hit the 30 s default
worker timeout and worker heartbeats avoid disk writes on the read-only rootfs.

## Uploaded artifacts

Archive uploads are off until `APP_ENCRYPTION_KEY` is set in `/etc/attacksurf/attacksurf.env`
(the Assets page then shows "not configured"). With the key set, ciphertext is written to the
named volume `artifact-store` (`/var/lib/attacksurf/artifact-store` in the app containers), so
it survives deploys; `docker compose down -v` deletes it. The volume is not backed up yet, and
`beat` purges expired artifacts every 10 minutes once the key is set. Keep the key
safe: without it stored artifacts cannot be read.

## Background workers

`worker-passive` consumes the `passive` queue (ownership checks, `dns_passive` scans, the
artifact purge); `beat` schedules the hourly ownership re-verification and the 10-minute purge.
One cannot work without the other: beat only queues, the worker only consumes (#174).
`worker-ai` consumes the `ai` queue, including Settings connection tests (`ai.test_connection`).
Both workers use concurrency 2 and the same application image, env file and secrets as `web`.
The deploy script discovers long-running services from Compose, so it starts both automatically.

```bash
docker compose -f compose.prod.yaml ps                          # both workers and beat healthy
docker compose -f compose.prod.yaml logs worker-passive         # passive.verify_ownership consumed
docker compose -f compose.prod.yaml logs worker-ai              # ai.test_connection consumed
```

`up -d --wait` (and the deploy script's `--wait-timeout 300`) gates a release on all three
healthchecks: worker probes use `celery inspect ping` targeting `passive@$HOSTNAME` and
`ai@$HOSTNAME`; the beat probe checks the broker connection. All substitute the Redis password
from the secret at probe time, the same way the entrypoint does for the main process. An unhealthy worker fails the deploy and rolls back.

## Analysis sandbox (not deployed yet)

Production runs none of the sandbox services: `sandbox-proxy`, `sandbox-launcher` and
`worker-analysis` exist only in the dev `compose.yaml` (ADR 0031). Until #92 adds them, upload
jobs stay queued. This is a checklist for that change, not steps to follow now:

- register `runsc` (gVisor) in the VPS `/etc/docker/daemon.json`; prod refuses `runc`;
- pick a host staging folder and mount it at the same path in the worker and the launcher;
- give the proxy's Docker socket group to uid 10001 (`group_add`);
- remember that `deploy.sh` waits for every service to be healthy, so a sandbox service that
  cannot start fails the deploy and rolls it back.

## Deploying tagged releases from GHCR (self-hosting)

`.github/workflows/release.yml` builds and pushes multi-arch (`linux/amd64`, `linux/arm64`)
`prod` images to `ghcr.io/cpt9m0/attacksurf` whenever a `v*.*.*` tag is pushed.

The primary `attacksurf.dev` instance keeps using pull-based source builds via `scripts/deploy.sh`,
so no registry pull credentials or webhooks are needed on the VPS. Self-hosters who prefer
prebuilt images can set `WEB_IMAGE` and pull directly:

```bash
export WEB_IMAGE=ghcr.io/cpt9m0/attacksurf:v0.1.0
docker compose -f compose.prod.yaml pull web worker-passive worker-ai beat migrate
docker compose -f compose.prod.yaml build caddy
docker compose -f compose.prod.yaml run --rm migrate
docker compose -f compose.prod.yaml up -d --wait
```

## Nightly off-box backups and restore drill

`scripts/backup.sh` streams `pg_dump --format=custom` from `postgres`, verifies the archive
with `pg_restore --list`, optionally encrypts it client-side with `age`, writes a `.sha256`
sidecar, uploads both via `rclone` to S3-compatible object storage (Cloudflare R2, Backblaze B2,
AWS S3), and prunes remote backups older than `BACKUP_RETENTION_DAYS` (default 30) **only after
the upload succeeds**.

### Setup (once)

```bash
sudo apt-get update && sudo apt-get install -y rclone age

# Optional but recommended: generate an age keypair off-box (or print public key and move
# the private key file to a password manager / offline vault, NOT left on the VPS).
age-keygen -o /tmp/attacksurf-backup.key
# Copy the `age1...` public key into BACKUP_AGE_RECIPIENT below, then delete `/tmp/attacksurf-backup.key`
# from the VPS after storing it safely off-box.

sudo install -m 600 deploy/backup.env.example /etc/attacksurf/backup.env
sudoedit /etc/attacksurf/backup.env   # set BACKUP_REMOTE_PATH, RCLONE_CONFIG_BACKUP_*, BACKUP_AGE_RECIPIENT

sudo install -m 644 deploy/systemd/attacksurf-backup.tmpfiles.conf /etc/tmpfiles.d/
sudo systemd-tmpfiles --create /etc/tmpfiles.d/attacksurf-backup.tmpfiles.conf
sudo install -m 644 deploy/systemd/attacksurf-backup.service \
                     deploy/systemd/attacksurf-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now attacksurf-backup.timer
```

Run the first backup by hand and verify it landed in the bucket:

```bash
sudo systemctl start attacksurf-backup
journalctl -u attacksurf-backup -n 30 --no-pager
```

> **Back up `/etc/attacksurf/` separately (off-box).** Database dumps do not contain
> `APP_ENCRYPTION_KEY`, `SECRET_KEY`, or `/etc/attacksurf/postgres_password`. Without
> `APP_ENCRYPTION_KEY`, encrypted org LLM API keys and stored artifacts in backups cannot be
> decrypted. Store `/etc/attacksurf/attacksurf.env` in your password manager/vault.

### Documented restore test (run after setup and quarterly)

`scripts/restore.sh --verify-only` downloads a backup from `BACKUP_REMOTE_PATH` (or reads a local
file), checks its `.sha256` sidecar, decrypts `.age` if needed, restores into a throwaway
database `attacksurf_restore_verify`, prints `alembic_version` and row counts, and drops the
throwaway database automatically on exit:

```bash
# If encrypted with age, supply the off-box private key temporarily:
sudo BACKUP_AGE_IDENTITY=/root/attacksurf-backup.key \
  /opt/attacksurf/scripts/restore.sh --verify-only attacksurf-20261121T031500Z.dump.age
# Remove the temporary private key from the VPS immediately after the drill:
shred -u /root/attacksurf-backup.key
```

For an actual disaster recovery overwrite of the live database (stops app/workers, takes a
pre-restore dump under `/var/lib/attacksurf/`, restores, restarts, and checks `/healthz`):

```bash
sudo BACKUP_AGE_IDENTITY=/root/attacksurf-backup.key \
  /opt/attacksurf/scripts/restore.sh --live attacksurf-20261121T031500Z.dump.age \
  --i-understand-this-replaces-prod
```

## Error tracking (Sentry, optional)

Sentry stays disabled unless `SENTRY_DSN` is set in `/etc/attacksurf/attacksurf.env`. When enabled:

- `send_default_pii=False` and `include_local_variables=False` are enforced.
- `infra/sentry.py` drops request bodies, cookies, and `user` PII (`email`, `ip_address`,
  `username`), and masks `Authorization`, `Cookie`, `Set-Cookie`, `X-CSRFToken`, `X-Api-Key`,
  secret-looking dict keys, and URL credentials (`user:pass@`) before events leave the container.
- `scripts/deploy.sh` injects `SENTRY_RELEASE=<short-sha>` automatically on each deploy.
- Keep `SENTRY_TRACES_SAMPLE_RATE=0.0` unless actively profiling performance.

## Log rotation

- **Container logs:** every service in `compose.prod.yaml` uses Docker's `json-file` driver
  capped at `max-size: 10m`, `max-file: 5`, `compress: true` (at most ~50 MiB per service).
- **Docker daemon default** (`/etc/docker/daemon.json`, for one-off `docker run` / dev):

  ```json
  {
    "log-driver": "json-file",
    "log-opts": { "max-size": "10m", "max-file": "5", "compress": "true" }
  }
  ```

- **systemd journald** (`/etc/systemd/journald.conf.d/size.conf`, caps `attacksurf-deploy` /
  `attacksurf-backup` / SSH logs):

  ```ini
  [Journal]
  SystemMaxUse=500M
  MaxRetentionSec=1month
  ```

  Apply with `sudo systemctl restart systemd-journald`.

## Host hardening checklist

Run through these once on the VPS (and check shared-host services on `lili` before changing
firewall or SSH rules):

1. **SSH keys only** (`/etc/ssh/sshd_config.d/99-hardening.conf`):
   - `PasswordAuthentication no`
   - `KbdInteractiveAuthentication no`
   - `PermitRootLogin prohibit-password` (or `no` if using a sudo user)
   - `PubkeyAuthentication yes`
   - Test with `sudo sshd -t && sudo systemctl reload ssh`, and verify a **new** SSH session
     connects before closing your current shell.
2. **UFW firewall** (because ingress uses outbound Cloudflare Tunnel, no inbound HTTP/HTTPS ports
   are needed for AttackSurf):
   - `sudo ufw default deny incoming`
   - `sudo ufw default allow outgoing`
   - `sudo ufw allow OpenSSH`
   - Check any co-located services on a shared host before `sudo ufw enable`.
   - Note: Docker modifies `iptables` directly for published container ports (`ports:`); AttackSurf
     publishes **no** ports in `compose.prod.yaml`, and `postgres`/`redis`/`caddy`/`migrate` are
     attached only to an `internal: true` Docker network.
3. **Unattended security updates**:
   - `sudo apt-get install -y unattended-upgrades apt-listchanges`
   - `sudo dpkg-reconfigure -plow unattended-upgrades`
   - Confirm `/etc/apt/apt.conf.d/50unattended-upgrades` enables `-security` origins and automatic
     unused dependency cleanup.
4. **Fail2ban** (`sshd` jail with systemd journal backend on Ubuntu 24.04):
   - `sudo apt-get install -y fail2ban`
   - Create `/etc/fail2ban/jail.local`:
     ```ini
     [sshd]
     enabled = true
     backend = systemd
     maxretry = 5
     findtime = 10m
     bantime = 1h
     ```
   - `sudo systemctl enable --now fail2ban && sudo fail2ban-client status sshd`

## Operations summary

`compose.prod.yaml` runs `cloudflared`, non-root `caddy`, `web` (Gunicorn), `worker-passive`,
`worker-ai`, `beat`, `postgres`, and `redis` with read-only root filesystems, dropped capabilities,
PID/CPU/memory limits, bounded log rotation, and `internal` network isolation for DB/Redis/Caddy,
paired with pull-based CD, nightly off-box backups, and optional scrubbed Sentry reporting.
