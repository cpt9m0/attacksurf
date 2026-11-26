# Development

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (manages Python 3.12+ and dependencies)
- Docker + Docker Compose, with access to the Docker daemon (see [Docker permissions](#docker-permissions-on-linux))
- Node.js (only for the `npx`-based MCP servers used by AI agents)
- `jq` (used by the Claude Code formatting hook)

## Setup

```bash
uv sync
cp .env.example .env                        # local settings (see below)
uv run pre-commit install                   # git hooks: commit, commit-msg, pre-push
uv run flask --app attacksurf run --debug   # http://127.0.0.1:5000
```

## Docker Compose stack

`make up` builds the `dev` image, waits for PostgreSQL and Redis, applies Alembic migrations,
then starts the application services and waits until every service is healthy. A failed build,
dependency or migration stops the command before it starts the application services.
Open http://127.0.0.1:5000/signup to create an account (no default credentials).

| Service | Host port (localhost only) | Notes |
|---|---|---|
| `web` | 5000 | Flask debug server, hot reload (`./src` is bind-mounted) |
| `postgres` | 5432 | PostgreSQL 18, user/password/db `attacksurf` (dev only), volume `pgdata` |
| `redis` | 6379 | Redis 8 |
| `worker-passive`, `worker-ai` | n/a | Celery workers for the `passive` / `ai` queues; no hot reload: `docker compose restart worker-passive worker-ai` after code changes |
| `beat` | n/a | Celery beat: ownership re-verification (hourly), artifact purge (every 10 min) |
| all app services | n/a | share the volume `artifact-store` (encrypted artifacts, ADR 0028) |

Inside compose, `DATABASE_URL` / `REDIS_URL` point at the service names and
`ARTIFACT_STORE_ROOT` at the `artifact-store` volume; your `.env` supplies the rest. Targets: `make up | down | logs | ps | build | shell | test | test-worker | check | migrate |
revision`. `make test-worker` (after `make up`) checks signup against the existing schema
(account writes roll back), then checks real worker jobs; CI's compose job runs the same suite
(`make` lists them). `make down` keeps the database; `docker compose down -v` wipes it.

PostgreSQL 18 stores data in a major-version subdirectory of `/var/lib/postgresql` (mounted as
`pgdata`), so a `pgdata` volume created by PostgreSQL 16 cannot be reused: run
`docker compose down -v` once to start a fresh one (dev data only; restore from a dump if needed).

### Docker permissions on Linux

If `make up` reports `permission denied` connecting to `/var/run/docker.sock`, the current
shell cannot access the Docker daemon. This is a host login/permissions issue, not a Compose
configuration error. Compare the current session's groups with the configured membership:

```bash
id -nG
getent group docker
```

If your username appears in the `docker` group entry but `id -nG` does not list `docker`,
refresh your login session: disconnect and reconnect over SSH, or open a subshell with:

```bash
newgrp docker
docker info
make up
```

For a single command without opening an interactive shell, use `sg docker -c 'make up'`.
Existing shells (including terminal multiplexers and agent sessions) retain their old groups
until restarted; adding the user again will not refresh them.

If your user is not a member, an administrator can grant access on a trusted development host:

```bash
sudo usermod -aG docker "$USER"
```

Then reconnect or run `newgrp docker` as above. **The `docker` group grants root-equivalent
access**; only add trusted users. For environments where that is inappropriate, configure
[rootless Docker](https://docs.docker.com/engine/security/rootless/) instead. Never make the
socket world-writable (`chmod 666`), and do not add automatic `sudo` to the Makefile.

## Database and migrations

| Task | Command |
|---|---|
| Apply migrations | `make migrate` (in compose) or `uv run alembic upgrade head` (uses `DATABASE_URL`) |
| New migration from model changes | `make revision id=0002 m="add assets"` (then review it, see the `db-migration` skill) |
| Current revision / history | `uv run alembic current` / `uv run alembic history` |

The app process never migrates on startup. The dev `make up` command runs `make migrate` before
starting application services (ADR 0012); direct `docker compose up` bypasses this orchestration
and still requires `make migrate`. Re-running migrations is safe. Migrations live in
`src/attacksurf/infra/db/migrations/`. Outside the dev Makefile (including production), apply
migrations explicitly before serving requests.

If signup fails with a missing `users` table on an already-running stack, run `make migrate`,
then retry signup: the failed attempt did not create an account. `/healthz` checks process
liveness only, not whether the schema has been migrated.

**DB tests** (`tests/integration/`) need PostgreSQL via `TEST_DATABASE_URL`; the database name
must end in `_test` because its schema is wiped at the start of the run. Without it they are
skipped locally (and fail in CI). `make test` sets it to compose's `attacksurf_test` database,
which is created when the `pgdata` volume is first initialized (older volume: `docker compose
down -v` once, or `docker compose exec postgres createdb -U attacksurf attacksurf_test`). Outside
compose, with `make up` running:

```bash
TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test uv run pytest
```

Each DB test runs in a transaction that is rolled back (fixture `db_session`).

**Pre-push hook.** `uv run pre-commit install` installs a `pytest` hook that runs the full suite,
DB tests included. It resolves `TEST_DATABASE_URL` in this order: your shell, then `.env`, then
`.env`'s `DATABASE_URL` with the name suffixed `_test` (same host and credentials), then the
local default above. It refuses to run against a database not named `*_test` and stops with one
message if the database is unreachable — so it never "passes" by silently skipping DB tests.
Nothing is needed on a fresh clone with `make up` running.

**Slow machines.** `test_1k_subdomain_scan_completes_within_limits` gives a 1,000-subdomain scan
90 seconds, and coverage tracing, which the full suite uses, slows the scan. If your machine
needs longer, set `SCALE_BUDGET_SECONDS` (90 to 600) in your shell; `.env` is not read for it:

```bash
SCALE_BUDGET_SECONDS=150 git push
```

A longer limit also lets a smaller slowdown pass on that machine, so use the lowest one that
works. CI always uses 90 seconds, and a test keeps the variable out of `.github/`.

## Configuration

All settings live in `src/attacksurf/config.py` and are read from environment variables or `.env`
(see `.env.example`). Leave `SECRET_KEY` empty in dev (an ephemeral key is generated);
`ENV=prod` refuses to start without a random `SECRET_KEY` of ≥ 32 characters. Never commit `.env`.

Artifact storage (ADR 0028): `APP_ENCRYPTION_KEY` (URL-safe base64 of 32 bytes; without it
artifacts can't be stored or read), `ARTIFACT_MAX_BYTES`, `ARTIFACT_ORG_QUOTA_BYTES`,
`ARTIFACT_RETENTION_HOURS` (0 = delete once analysis completes) and `ARTIFACT_STORE_ROOT`
(ciphertext; must not overlap `SANDBOX_ARTIFACT_ROOT`). Archive upload on the Assets page
(#87) and binary upload (#101) need `APP_ENCRYPTION_KEY`; without it the forms show "not
configured". Their scans stay queued: no `analysis.*` task is registered yet (only the opt-in
`worker-analysis` consumes the queue, and it drops what it receives).

Auth settings: `ALLOW_SIGNUP` (default `true`; when `false` only the first user can sign up),
`SESSION_LIFETIME_HOURS` (default 12), `PROXY_COUNT` (trusted proxy hops in front of the app).
`PROXY_COUNT` counts hops, not components: 0 in dev, 1 behind Caddy, and also 1 behind the
production Cloudflare Tunnel (Cloudflare → `cloudflared` → Caddy → app; `cloudflared` does not
add a hop). Set it to 2 only if Cloudflare proxies directly to Caddy without a tunnel. Rate
limits key on the visitor address Cloudflare forwards (`CF-Connecting-IP`, else the leftmost
`X-Forwarded-For` entry), and use Redis (`REDIS_URL`) with an in-memory fallback. Open
http://127.0.0.1:5000, sign up; the first account owns a new org. Production setup:
[deployment.md](deployment.md).

Scans (#21): `SCAN_MAX_STARTS_PER_HOUR` caps scan starts per organization per profile in a
trailing hour (default 10); failed starts count too. Upload scans (`code`, `binary_static`)
have their own profiles and limiter.

Recurring scans (#27): `SCAN_DEFAULT_FREQUENCY` seeds a schedule for **new** root domains
only: `weekly` (default), `daily`, or `off`. Existing roots keep their saved setting; an
admin turns it on or off on the root's overview, and the default does not change domains
that already exist.

### DNS resolution (#16)

`DNS_RESOLVERS` is a comma-separated list of public recursive resolvers (default
`1.1.1.1,8.8.8.8`); private, loopback and link-local addresses are refused at startup.
`DNS_TIMEOUT_SECONDS` and `DNS_LIFETIME_SECONDS` bound each query and each resolution, and
`DNS_MAX_CONCURRENCY` caps concurrent queries per scanner run. Search domains stay disabled.

`IP_ASN_DB_PATH` optionally points at a combined public ip2asn TSV (one
`start end asn country organisation` row per line; IPv4 and IPv6 can be concatenated). The file
is read once per worker process, no network is used, and a missing file simply leaves ASN/
organisation details empty. Reverse DNS is always attempted for resolved addresses.

### AI provider (instance key)

`LLM_PROVIDER` (`anthropic` or `openai_compat`), `LLM_MODEL`, `LLM_BASE_URL` and `LLM_API_KEY`
are the instance config: orgs without their own key use it (ADR 0019), capped per org by
`LLM_MONTHLY_INSTANCE_TOKEN_BUDGET` (default `500000` tokens per UTC month). AI triage skips
`info` findings unless `LLM_TRIAGE_INCLUDE_INFO=true` (ADR 0029). Orgs can configure
their own provider, model, optional `base_url` and BYO API key under `/settings` when
`APP_ENCRYPTION_KEY` is configured (`APP_ENCRYPTION_OLD_KEYS` accepts comma-separated prior keys
for rotation decryption). Custom org `base_url` hosts must be HTTPS and resolve to public IPs
unless listed in `LLM_ALLOWED_BASE_HOSTS` (e.g. `localhost` or `ollama` in dev). The code has no
default model; without a key and a model, AI is off and the app logs a warning saying so at startup.
For development we use Meta's Muse Spark, which speaks both API formats with one key (it starts
with `LLM_`): put this configuration in your own `.env`, replacing the `LLM_*` values copied
from `.env.example`:

```bash
LLM_PROVIDER=openai_compat
LLM_MODEL=muse-spark-1.3
LLM_BASE_URL=https://api.meta.ai/v1          # anthropic format: https://api.meta.ai (no /v1)
LLM_API_KEY=...                              # your own key, only in .env
```

`muse-spark-1.3-contributor` is cheaper because Meta may train on everything you send and get
back: use it only with test fixtures, never with scan results of real domains.

The same key works in both formats. Environment variables override `.env`, so you can run either
adapter's live test without editing `.env`:

```bash
RUN_LLM_TESTS=1 uv run pytest tests/e2e/test_openai_compat_live.py -m llm_live --no-cov
LLM_PROVIDER=anthropic LLM_BASE_URL=https://api.meta.ai RUN_LLM_TESTS=1 \
    uv run pytest tests/e2e/test_anthropic_live.py -m llm_live --no-cov
```

### Evaluating the triage prompt (`make eval`)

`make eval` sends the triage eval set to the LLM in your `.env`, one call per case, and prints
each case's verdict. A case is one asset's batch in `tests/fixtures/ai/triage_eval/` with the
judgments a good model must give (ranges of priority, false-positive likelihood and severity).
It is opt-in (`llm_live`) and never runs in CI; `tests/unit/ai/test_eval_harness.py` checks the
cases and the harness offline. The cases are synthetic, so `muse-spark-1.3-contributor` is fine
here. Before releasing a new prompt version, run both versions and record the model and the
results in the PR. Override the format for one run as above, e.g.
`LLM_PROVIDER=anthropic LLM_BASE_URL=https://api.meta.ai make eval`.

### Running the sandbox services locally

The sandbox proxy, the launcher and `worker-analysis` (ADR 0016) are opt-in: they start only with
the `sandbox` profile, and `make up` leaves them out.

```bash
docker compose --profile sandbox up -d --wait    # proxy, launcher and worker-analysis, all healthy
docker compose --profile sandbox logs sandbox-launcher
make down                                        # stops everything, profile services included
```

- **Runtime:** `SANDBOX_ALLOW_RUNC` defaults to `true` in dev, so a host without gVisor still
  works (a host with `runsc` uses it). Compose reads `.env` for this substitution, so a `.env`
  that sets it to `false` makes the launcher exit with "no permitted container runtime".
- **Staging folder:** `SANDBOX_ARTIFACT_ROOT` (default `/tmp/attacksurf-sandbox`) is mounted at
  the same path on the host and in the containers, because Docker resolves the analyzer's bind
  source on the host.
- **Empty catalog:** no real analyzer ships yet, so a `POST /runs` is a 404 unless the fixtures
  are on and listed in the images lock.
- **Fixture analyzers:** `SANDBOX_FIXTURE_ANALYZERS=true` (default `false`, refused when
  `ENV=prod`) adds `fixture-ok`, `fixture-probe`, `fixture-sleep` and `fixture-flood`. Each runs
  only if the lock at `SANDBOX_IMAGES_LOCK` maps its name to an image. Never add them to the
  committed `sandbox-images.lock`.
- **Launcher URL:** Compose sets `SANDBOX_LAUNCHER_URL` on `worker-analysis` only. The other
  workers keep it unset and refuse every sandbox request.
- **Dropped jobs:** until the analysis tasks are registered, `worker-analysis`
  discards the upload jobs it receives. Their rows stay `queued`, as they do without the worker.

To debug the launcher outside Docker, run `uv run python -m attacksurf.sandbox_launcher` with
`SANDBOX_PROXY_URL` (the proxy, port 8790), `SANDBOX_LAUNCHER_HOST=127.0.0.1`,
`SANDBOX_ARTIFACT_ROOT` and `SANDBOX_IMAGES_LOCK` set in the environment.

### Sandbox runtime tests

`tests/integration/sandbox/` runs real containers through the worker client, the launcher, the
proxy and Docker. The launcher and proxy run inside the test process, so the Compose stack isn't
needed. The tests are skipped unless `RUN_SANDBOX_TESTS=1`; once it is set, a missing Docker or a
failed image build fails them.

```bash
make sandbox-test                          # host with gVisor (`runsc`)
SANDBOX_ALLOW_RUNC=true make sandbox-test  # host without it (weaker isolation)
make sandbox-images                        # only build the fixture image and print its ID
```

The tests build the fixture image (or use `SANDBOX_FIXTURE_IMAGE`, a `sha256:` image ID), write
their own images lock and turn the fixtures on, so you don't set `SANDBOX_FIXTURE_ANALYZERS`.
`SANDBOX_EXPECT_RUNTIME` (`runsc` or `runc`) makes a different runtime a failure. CI's
`sandbox (runsc)` job sets it, installs gVisor with `scripts/install-runsc.sh` (pinned release,
checksum verified) and first checks that a prod launcher refuses to start without `runsc`. A
`runc` run says nothing about gVisor.

`tests/unit/test_sandbox_compose.py` is separate: it renders the dev `compose.yaml` and checks
how the sandbox services are isolated, without starting anything. It runs with the normal suite
and needs Docker Compose (skipped locally without `docker`, a failure in CI).

## Everyday commands

| Task | Command |
|---|---|
| Run tests (+ coverage gate 80%) | `uv run pytest` |
| Lint / autofix | `uv run ruff check --fix .` |
| Format | `uv run ruff format .` |
| Type-check | `uv run pyright` |
| All git hooks on all files | `uv run pre-commit run --all-files` |
| Dependency audit (`pip-audit`) | `make audit` |
| Layer rules (import-linter) | `uv run lint-imports` |
| Add a dependency | `uv add <pkg>` (dev: `uv add --dev <pkg>`) |

Never use `pip install`, and never edit `uv.lock` by hand.

Commit message template: `git config commit.template .gitmessage`. Issue/commit/PR rules:
[conventions.md](conventions.md).

## Project layout

```
src/attacksurf/   application package (src layout)
tests/            pytest suite, mirrors src/
docs/             architecture, ADRs, guides
.claude/          Claude Code settings, hooks, skills
AGENTS.md         rules for AI coding agents (CLAUDE.md imports it)
.mcp.json         MCP servers for AI agents
```

## Git hooks and CI

| When | What runs |
|---|---|
| `git commit` | trailing whitespace/EOF/line endings, YAML/TOML/JSON syntax, merge markers, large files, private keys, **gitleaks** (secrets), **ruff** check + format, **import-linter** (layer rules) |
| commit message | Conventional Commits check (`.github/scripts/check-commit-msg.sh`, same rules as PR titles) |
| `git push` | **pyright**, **pytest** (80% coverage gate) |
| CI on push to `main` / every PR | `lint` (pre-commit hooks + pyright), `test (3.12)`, `test (3.13)`, `test (3.15)` (with a Postgres service), `web-e2e` (Playwright Chromium layout + full-stack MVP E2E with Postgres), `audit` (`pip-audit` on locked dependencies), `secrets` (gitleaks over full git history), `compose` (builds the prod image, checks it runs as non-root, starts the dev stack, curls `/healthz`, runs migrations), `sandbox (runsc)` (sandbox runtime tests under gVisor), `pr-title` (also re-runs on title edits). A separate workflow, `sandbox-images.yml`, builds the sandbox images when their files change; it pushes nothing |

Remote hooks and GitHub Actions are pinned to commit SHAs; Dependabot proposes updates. ruff,
pyright and pytest versions come from `uv.lock`.

## Testing

- Coverage must stay **≥ 80%** (`--cov-fail-under=80` in `pyproject.toml`; CI enforces it).
- No live network in tests: use fixtures under `tests/fixtures/` and fake providers.
- LLM: tests use `tests.fakes.FakeLLMProvider` (queued replies, shared schema validation). A
  provider adapter's tests subclass `tests/unit/ai/contract.ProviderContract` with a harness that
  stubs its HTTP (both SDKs take `http_client=httpx2.Client(transport=
  httpx2.MockTransport(...))`; see `tests/unit/ai/providers/test_anthropic.py` and
  `tests/unit/ai/providers/test_openai_compat.py`). Tests that call a real provider are marked `llm_live`; `tests/conftest.py`
  skips them unless you run `RUN_LLM_TESTS=1 uv run pytest -m llm_live --no-cov` with
  `LLM_API_KEY` and `LLM_MODEL` in your `.env`, and always in CI. `--no-cov` because a
  handful of live tests can't meet the whole-app coverage gate, which still applies to the
  normal full suite.
- Tests must pass on any OS: read files with `encoding="utf-8"` (Windows defaults to cp1252),
  and simulate network failures instead of relying on how an OS treats a closed port.
- On Windows, use `127.0.0.1` rather than `localhost` in `TEST_DATABASE_URL`: `localhost` tries
  IPv6 first, Docker only listens on IPv4, and every connection waits for a timeout.
- `.gitattributes` makes every checkout use LF line endings, whatever `core.autocrlf` says, and
  leaves vendored files byte-for-byte as committed. A Windows checkout made before it existed
  still has CRLF files: with no uncommitted work, rewrite them once from Git Bash with
  `git ls-files -z | xargs -0 rm -f && git checkout -- .` (untracked files such as `.env` stay).
- Layout: `tests/unit/`, `tests/integration/` (DB, Celery; fixtures `db_engine`, `db_session`),
  `tests/e2e/` (against the running stack, e.g. `make test-worker`, and full-stack Chromium E2E
  `tests/e2e/test_mvp_e2e.py`). Browser tests live in `tests/e2e/web/` (hermetic layout checks
  with no DB) and `tests/e2e/test_mvp_e2e.py` (full signup → verify → scan → AI triage →
  rescan diff against Postgres, marker `web_e2e`). Run locally after
  `uv run playwright install chromium` with
  `RUN_WEB_E2E=1 TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5432/attacksurf_test uv run pytest tests/e2e -m web_e2e --no-cov`
  (CI runs the same command in the `web-e2e` job).
- Celery tasks in tests: `task.apply(kwargs=...)` runs them in-process; patch
  `workers.runtime.session_factory` to share the test's connection
  (`tests/integration/workers/test_tracked_task.py`).
- Pipeline fixtures live in `tests/scanner_fixtures.py`; eager integration tests patch the
  registry, rule catalog and gate, and use an in-memory result backend. `send_task` does not
  honor Celery eager mode: the kickoff is recorded with `FakeQueue` and applied explicitly.
- `tests/e2e/test_pipeline.py` starts a real prefork test worker against Redis/Postgres with
  an isolated broker/result key prefix. It exercises Redis chords with fake, no-network
  plugins and a failing check; production workers never load those plugins. `make test-worker`
  runs both this test and the original Compose worker ping (CI uses the same command).

## Working with AI agents

This project is built mostly by AI coding agents. The setup:

- **`AGENTS.md`**: the rulebook every agent reads (architecture rules, conventions, definition
  of done). `CLAUDE.md` imports it and adds Claude-specific notes.
- **`STATE.md`**: the current handoff: what was just done and the exact next step. Overwritten
  at the end of every task (no history). Read it first when you open the project.
- **`DESIGN.md`**: the web UI design system (tokens, components, HTMX patterns). Values are
  completed with Claude Design or a similar tool; agents follow it for all UI work.
- **Skills** (`.claude/skills/`): `implement-issue`, `add-scanner`, `db-migration`, `llm-prompt`,
  `pre-pr-check`, `create-issue`, `finish-task`.
- **Keep-in-sync rule**: after every task the agent runs `finish-task` (also `/finish-task`):
  tests, docs, `DESIGN.md`, `CHANGELOG.md`, `AGENTS.md`/`CLAUDE.md`/skills, and `STATE.md`.
- **Hooks** (`.claude/settings.json`): ruff on every edited Python file; at session start
  `uv sync` runs and `STATE.md` is loaded into context; on stop, a reminder fires if code
  changed but `STATE.md` didn't.
- **MCP servers** (`.mcp.json`):

| Server | Use | Setup |
|---|---|---|
| context7 | current library docs | optional `CONTEXT7_API_KEY` (higher rate limits) |
| brave-search | web search | requires `BRAVE_API_KEY` ([get one](https://brave.com/search/api/)) |
| playwright | browser testing of the UI | dev dependency (`uv add --dev playwright`) |

Export the keys in your shell (or in your cloud environment's secrets); never commit them.
Other agents (Codex, Cursor, ...) read `AGENTS.md` directly; configure the same MCP servers in
their own config if wanted.

### Recommended workflow

1. Open `STATE.md`: it names the next step (usually the next unblocked issue in epic #31).
2. Ask the agent: "implement #N" or "continue" (it runs the `implement-issue` skill, ending with
   `finish-task`).
3. Review the PR: check the acceptance criteria and the security checklist in `pre-pr-check`.
4. Merge, then repeat.
