# Plan: PR 4, commit 5: `feat(infra): add the sandbox proxy and launcher to the dev stack`

Branch `84-analysis-worker` · `Refs #84` · follows `build(infra): ship an empty sandbox images
lock` (commit 4 of PR 4; see `84-pr4-analysis-worker-overall-plan.md`).

## Purpose

**In plain words.** Today, to try the sandbox services locally you start them by hand in two
terminals. This commit adds both to the local Docker Compose setup as opt-in services: they start
only with `docker compose --profile sandbox up`.

They sit on their own private network that can't reach the internet. Only the proxy gets access
to Docker itself. Neither gets the app's database or Redis passwords.

The usual `make up` is unchanged, so the CI check and anyone not working on analysis are
unaffected.

**Technical.** Changes to `compose.yaml`:
- **New anchor:** `x-sandbox: &sandbox`. It uses the same `build` and `image: attacksurf:dev` as
  `x-app`, but has no `env_file`, no app `environment` and no `depends_on`.
- **`sandbox-proxy`:** runs `python -m attacksurf.sandbox_proxy` and mounts
  `/var/run/docker.sock`. Its healthcheck is a TCP connect to `127.0.0.1:8790`.
- **`sandbox-launcher`:** runs `python -m attacksurf.sandbox_launcher` and mounts the staging
  folder read-only. It starts after `sandbox-proxy` is `service_healthy`. Its healthcheck is
  `GET http://127.0.0.1:8791/healthz`.
- **Both services:**
  - carry `profiles: [sandbox]` and join only the new `sandbox` network (`internal: true`);
  - get `ENV: dev`, `SANDBOX_ALLOW_RUNC: ${SANDBOX_ALLOW_RUNC:-true}`, and
    `SANDBOX_ARTIFACT_ROOT: ${SANDBOX_ARTIFACT_ROOT:-/tmp/attacksurf-sandbox}`;
  - mount the same host path at the same path inside the container.

This implements the ADR 0016 topology for dev, minus the worker, which commit 6 adds. Nothing in
`compose.prod.yaml` changes (ADR 0029).

## Context
`SandboxProxySettings` (port 8790, `sandbox_docker_socket`) and `SandboxLauncherSettings` (port
8791, default `sandbox_proxy_url = http://sandbox-proxy:8790`) already exist in `config.py`. The
default proxy URL already uses the Compose service name, so the launcher needs no URL variable.
Commit 4 made the images lock part of the image.

`docs/development.md:185-205` documents today's manual way to run them. `compose.yaml` has no
`profiles:` yet, so this commit introduces the pattern (approved in the planning step).

This is a separate commit from the worker (commit 6) because it needs nothing from PR 3d. The
launcher and proxy have been on `main` since PR 3c.

## Decisions
1. **Opt-in `sandbox` profile.** Without it, every `make up` (and CI's `compose` job) would mount
   the Docker socket and create a host folder. Services in a profile are ignored by `make up`,
   `docker compose build` and `config --services` unless the profile is named.
2. **A separate `x-sandbox` anchor, not `<<: *app`.** ADR 0016: the launcher and proxy hold no
   credentials. `x-app` brings `.env`, `DATABASE_URL`, `REDIS_URL` and `APP_ENCRYPTION_KEY`, and
   these services must not receive any of them. Both services read the process environment only
   (`_SandboxServiceSettings` has no `.env`).
3. **`sandbox` network with `internal: true`.** No route to the internet or the host. The proxy
   reaches Docker through the socket file, not the network. Postgres and Redis are not on this
   network, so these services cannot reach them.
4. **The staging folder uses the same host path inside and outside.** The proxy asks the host's
   Docker to mount `SANDBOX_ARTIFACT_ROOT/{id}` into the analyzer. The host resolves that path,
   not the container, so the path must mean the same thing everywhere.
   - Default `/tmp/attacksurf-sandbox`, overridable through the shell or `.env`.
   - It never overlaps `ARTIFACT_STORE_ROOT` (`/var/lib/attacksurf/artifact-store`), as ADR 0028
     requires.
   - The proxy needs no mount: it only checks paths as text (`policy.py`).
5. **`SANDBOX_ALLOW_RUNC` defaults to `true` in dev.** Most dev machines lack gVisor. Both
   services read it: the proxy for which runtimes it allows (`allowed_runtimes`), the launcher
   for which it picks. On a machine with `runsc` the launcher still prefers it
   (`select_runtime`). `ENV: dev` is set explicitly so the runc refusal for prod can never apply
   by accident.
6. **Healthchecks override the image's.** The `Dockerfile` `HEALTHCHECK` probes port 5000, which
   these services don't serve.
   - **Launcher:** has `/healthz`.
   - **Proxy:** has no health route. Its only read route forwards `/info` to Docker. A plain TCP
     connect proves it is listening without sending anything to Docker.
7. **Hot reload mount kept, read-only.** `./src:/app/src:ro`, like the other dev services, so code
   changes only need `docker compose restart sandbox-launcher`. Read-only because these services
   never write code.
8. **Dev runs as root.** The dev image has no `USER`, so the proxy can open the socket. The prod
   image's uid 10001 will need the socket's group. That is noted for #92 and not solved here.
9. **Docs in this commit.** Only comments in `compose.yaml`. `docs/development.md` comes in
   commit 7.

## Requirements
- [ ] `compose.yaml` gains the `x-sandbox` anchor, the services `sandbox-proxy` and
      `sandbox-launcher`, and a top-level `networks: { sandbox: { internal: true } }`.
- [ ] Both services: `profiles: [sandbox]`, `networks: [sandbox]`, no `env_file`, no `ports`.
- [ ] Only `sandbox-proxy` mounts `/var/run/docker.sock`.
- [ ] `sandbox-launcher` mounts `${SANDBOX_ARTIFACT_ROOT:-/tmp/attacksurf-sandbox}` at the same
      path with `:ro`, and `depends_on: { sandbox-proxy: { condition: service_healthy } }`.
- [ ] Environment on both: `ENV: dev`, `SANDBOX_ALLOW_RUNC`, `SANDBOX_ARTIFACT_ROOT` as above.
      Nothing else.
- [ ] Each service has its own healthcheck (TCP 8790 and `/healthz` on 8791).
- [ ] Existing services, `x-app` and `make up` are unchanged. `compose.prod.yaml` is unchanged.

## Acceptance criteria
- [ ] **Contract (opt-in):** `docker compose config --services` does not list either service.
      `docker compose --profile sandbox config --services` lists both.
- [ ] **Contract (runs):** `docker compose --profile sandbox up -d --wait sandbox-proxy
      sandbox-launcher` ends with both healthy. The launcher logs `sandbox_launcher_started` with
      `analyzers=0` (and `sandbox_launcher_runc_fallback` on a host without gVisor).
- [ ] **Contract (no secrets):** `docker compose --profile sandbox config` shows neither
      `DATABASE_URL`, `REDIS_URL` nor `APP_ENCRYPTION_KEY` under these services.
- [ ] **Negative (isolation):** from the launcher,
      `python -c "import socket; socket.create_connection(('1.1.1.1', 53), 2)"` fails (no route).
      `/var/run/docker.sock` does not exist in the launcher container.
- [ ] **Negative (empty catalog):** `POST /runs` to the launcher (run from inside the container)
      for any analyzer returns 404.
- [ ] **Unchanged:** `make up` and CI's `compose` job behave as before.
- [ ] **Gate:** `ruff`, `pyright`, `lint-imports` and full `pytest` pass (no Python changes).
      Hooks pass without `--no-verify`.

## Changes

### 1. `compose.yaml` (~45 lines)
- `x-sandbox` anchor next to `x-app`, with a comment: "no app env or secrets (ADR 0016)".
- `sandbox-proxy` and `sandbox-launcher` after `beat`. Each has a one-line comment saying what it
  is and why it has (or lacks) the socket.
- `networks:` block before `volumes:`.

### 2. Tests
None in pytest. No test parses the compose files today (`grep -rl compose tests/` finds only
`test_makefile.py` and `e2e/test_worker.py`), and adding a YAML parser dependency for this is not
worth it. The commands in Acceptance criteria are the checks. They are listed in the PR
description's test section.

#### A. Happy path
| Check | Given | Expect |
|---|---|---|
| `docker compose --profile sandbox up -d --wait sandbox-proxy sandbox-launcher` | a dev machine with Docker | both healthy |
| `docker compose --profile sandbox logs sandbox-launcher` | the same | `sandbox_launcher_started`, `analyzers=0` |

#### B. Boundary cases
| Check | Given | Expect |
|---|---|---|
| `SANDBOX_ALLOW_RUNC=false docker compose --profile sandbox up -d --wait …` | a host without `runsc` | launcher exits non-zero ("no permitted container runtime …"); `--wait` reports it unhealthy |
| custom `SANDBOX_ARTIFACT_ROOT=/tmp/x` | the same host | both services see `/tmp/x` |

#### C. Invalid inputs
| Check | Given | Expect |
|---|---|---|
| `SANDBOX_ARTIFACT_ROOT=relative` | an invalid root | both services exit at startup ("must be an absolute path below /") |

#### D. Neighbor rejection and drift guards
| Check | Given | Expect |
|---|---|---|
| `docker compose config --services` | no profile | neither sandbox service listed (protects `make up` and CI) |
| `docker compose exec sandbox-launcher ls /var/run/docker.sock` | running stack | "No such file" |

## Assumptions and risks
- **Assumption: a Linux host with rootful Docker, with the socket at `/var/run/docker.sock`.**
  Checked on this machine: Compose v5.8.0, AppArmor, no SELinux label option. Rootless Docker and
  Podman put the socket somewhere else. Under Docker Desktop (macOS/Windows), the daemon resolves
  bind paths inside its VM, so "the same path inside and outside" (Decision 4) may not hold. On a
  host with SELinux enforcing, the proxy can't open the socket without `label=disable`. None of
  this affects `make up`, because the profile is opt-in. Commit 7's docs say "Linux, rootful
  Docker" and name these cases.
- **Assumption: the sandbox services never read `.env`.** Checked: only the app's `Settings`
  sets `env_file` (`config.py:66`). The image copies no `.env` (`Dockerfile`, the `COPY` lines),
  and `x-sandbox` has no `env_file`. Compose still reads `.env` to fill in `${SANDBOX_*}`, which
  is the intended override (Decision 4). If a later change adds `env_file` to `x-sandbox`, the
  "no secrets" acceptance check catches it.
- **Assumption: the image already contains the lock and the entry points.** Checked: the dev stage
  copies `sandbox-images.lock` (contents `{}`). The launcher reads it relative to `/app`
  (`config.py:283`). Both `__main__` modules exist. The `./src` mount does not cover the lock, so
  changing the lock needs `docker compose build`, not a restart.
- **Assumption: the image has no `curl`.** It is based on `python:3.15-slim`. Both healthchecks
  therefore use `python -c` (`urllib.request` for `/healthz`, `socket.create_connection` for
  8790), like the `Dockerfile`'s own `HEALTHCHECK`. A `curl` healthcheck would never pass.
- **Risk: the Docker socket is root on the host.** Anything that gets the proxy to send a request
  it shouldn't controls the dev machine. Mitigations: the profile keeps the socket out of
  `make up` and CI, only the proxy mounts it (checked under D), and the proxy's allowlist and
  shape checks apply. In this commit only the launcher can reach port 8790. That stops being
  true in commit 6, see "Open decision" under Notes.
- **Risk: `/tmp` can be claimed first by another user on a shared host.** Docker creates a
  missing bind source as `root:root 755`. But if another local user creates
  `/tmp/attacksurf-sandbox` first, they own it. They can then plant symlinks between the
  launcher's check and the proxy's bind. `artifacts.py:3-6` says that check is only safe while
  nothing but the fetcher can write under the root. In dev this is accepted. The fix, if wanted,
  is a default outside `/tmp` (for example `/var/lib/attacksurf/artifacts`, the setting's own
  default, which Docker would also create as root). The trade-off is that the folder survives
  reboots. Decide before committing.
- **Risk: `SANDBOX_ALLOW_RUNC=true` is copied into prod.** Prevented in two places: with
  `ENV=prod` the settings refuse runc at startup (`config.py:288-289`), and `select_runtime` checks
  again (`__main__.py:30-38`). `compose.prod.yaml` stays unchanged (Requirements).
- **Risk: two anchors build the same `attacksurf:dev` tag.** `--profile sandbox up` may rebuild
  the image or race with `make up`'s build. Not verified with Compose v5.8.0. Check that
  `docker compose --profile sandbox build` builds the image once and that `make up` afterwards
  doesn't rebuild it.
- **Weak spot: the proxy healthcheck proves less than it seems.** It only shows the proxy is
  listening, not that the proxy can reach Docker. The launcher fills that gap: at startup it asks
  the proxy for runtimes (`__main__.py:58-61`) and exits if that fails. So "launcher healthy" is
  the real end-to-end check, and Acceptance waits on both services.
- **Weak spot: the empty-catalog 404 never touches the staging folder.** The launcher rejects
  unknown names before it looks at any files (`server.py:157-158`). So no check in this commit
  proves the read-only mount works or that the host's Docker resolves the path. The custom-root
  check (B) only proves the variable arrives. The first analyzer PR owns the end-to-end mount
  check.
- **Weak spot: the isolation check covers only the internet.** Connecting to `1.1.1.1` proves
  there is no internet route. It doesn't prove the services are cut off from the app's network.
  Add one more check in the launcher: `socket.create_connection(('postgres', 5432), 2)` fails
  (the name doesn't resolve).
- **Weak spot: only the runc path can run here.** This host has only `runc` (`docker info`), so
  the acceptance run always logs `sandbox_launcher_runc_fallback`. The preference for `runsc` is
  covered by the `select_runtime` unit tests, not by this commit.
- **Hand-off: the worker must use the same staging root.** The app's `Settings` defaults to
  `/var/lib/attacksurf/artifacts` (`config.py:128`), and `x-app` doesn't set it. If
  `worker-analysis` used a different root, every run would get a 404. Commit 6 sets
  `SANDBOX_ARTIFACT_ROOT` with the same `${…:-/tmp/attacksurf-sandbox}` fallback
  (`06-…md:28`). Both files must keep the same default.
- **Hand-off: `make down` and profile services.** It is not verified whether plain `make down`
  stops the containers started with `--profile sandbox` and removes the `sandbox` network. Until
  commit 6 changes `down`, use `docker compose --profile sandbox down`. Commit 7 documents it.
- **Hand-off: prod.** Prod needs `group_add` for the socket (uid 10001), `runsc` and a real host
  path. All of these belong to #92 (Notes).
- **Out of scope but noticed: possible wrong port in `.env.example`.** STATE.md says the
  `SANDBOX_LAUNCHER_URL` example uses port 8080, but the launcher listens on 8791 (I could not
  read `.env.example` to confirm). Commit 6 rewrites that comment, so fix it there.

## Order of work (red → green)
1. Write down the checks above.
2. Before the change, `docker compose --profile sandbox config --services` lists nothing new (red).
3. Edit `compose.yaml` until every check passes.
4. `docker compose --profile sandbox down`, then `make up` still works alone.
5. Full gate (as in commit 2).
6. `finish-task` deferred to commit 8.
7. Commit. Body: "brings ADR 0016's launcher and proxy into the dev stack, opt-in so `make up`
   and CI never mount the Docker socket; prod is unchanged (ADR 0029)". Footer `Refs #84`,
   Co-Authored-By trailer.

## Reused code
- `src/attacksurf/config.py`: `SandboxProxySettings`, `SandboxLauncherSettings` (their defaults
  give the ports and proxy URL).
- `src/attacksurf/sandbox_launcher/__main__.py`: startup checks and log events used in the checks.
- `compose.yaml`: the healthcheck layout of `beat` and `worker-passive`.

## Verification
- All Acceptance criteria commands.
- `make up && curl -fsS http://127.0.0.1:5000/healthz`: unchanged stack still healthy.
- Scratch check (revert): remove `profiles: [sandbox]` from the proxy. `docker compose config
  --services` now lists it, showing the profile is what keeps `make up` clean.

## Notes for later commits
- **Open decision, settle in this commit: the proxy trusts anyone who can reach it.** It checks the
  image and the container's shape, but it accepts any `Cmd`/`Entrypoint` for an allowlisted image
  (`sandbox_proxy/policy.py:154-155`), allows any input folder under the artifact root, and does
  not authenticate callers. Only the launcher fixes the command. Anything that can reach port 8790
  can skip the launcher and read other orgs' staged artifacts through the container's stdout.
  `internal: true` keeps the network off the internet but does not separate the proxy from
  commit 6's `worker-analysis`, which also joins `sandbox`. Prefer two networks: a proxy-only one
  (proxy + launcher) and a launcher-facing one (launcher + worker); the launcher joins both. If
  that is left for #92, say so in the commit body and in `docs/security.md`.
- **Commit 6:** `worker-analysis` joins the `sandbox` network and the default network. It mounts
  the same staging folder read-write and reaches the launcher at `http://sandbox-launcher:8791`.
- **Commit 6:** `make down` must also stop profile services (`--profile sandbox down`).
  Otherwise the default network can't be removed while `worker-analysis` runs.
- **#92 (prod):** the prod proxy runs as uid 10001 and needs the socket's group (`group_add`).
  Prod also needs `runsc` on the VPS and a real host path for the staging folder.
