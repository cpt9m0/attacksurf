# Self-Hosting Guide

Run **attacksurf** on your own Linux server or VPS with Docker Compose. Your domains, scan
findings, and LLM API keys stay on infrastructure you control.

> For `attacksurf.dev` pull-based CD and deep VPS operations runbooks, see
> [docs/deployment.md](deployment.md).

---

## 1. Prerequisites

- Linux server (1–2 vCPU, ≥ 2 GB RAM, ≥ 20 GB disk) with Docker Engine and Docker Compose v2
- A domain or subdomain for the web UI (HTTPS via Caddy or Cloudflare Tunnel)
- Optional: an Anthropic or OpenAI-compatible API key (or local Ollama / vLLM) for AI triage and
  exposure summaries, and an SMTP relay for email digest notifications

## 2. Choose Your Deployment Topology

| Option | File | TLS & Ingress | Best for |
|---|---|---|---|
| **Prebuilt GHCR images (recommended)** | `compose.prod.yaml` + `WEB_IMAGE` | Caddy + Cloudflare Tunnel (`cloudflared`) or reverse proxy | Production VPS with zero inbound ports |
| **Build from source** | `compose.prod.yaml` | Same hardened prod containers | Custom forks or pinned commits |
| **Local evaluation / dev** | `compose.yaml` | Plain HTTP on `127.0.0.1:5000` | Trying locally (`make up`) |

## 3. Configure Secrets and Environment

Clone the repository and create your environment configuration:

```bash
git clone https://github.com/cpt9m0/attacksurf.git
cd attacksurf
cp .env.example .env
```

Generate strong random keys (never reuse example values):

```bash
# Session signing key (>= 32 chars required in prod)
python3 -c 'import secrets; print("SECRET_KEY=" + secrets.token_urlsafe(48))'

# 32-byte AES-256-GCM key for org BYO LLM API keys & encrypted artifacts
python3 -c 'import base64, secrets; print("APP_ENCRYPTION_KEY=" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))'
```

Review the key settings in `.env` (or `/etc/attacksurf/attacksurf.env` for systemd/prod):

| Variable | Recommended value | Notes |
|---|---|---|
| `ENV` | `prod` | Enables `__Host-` secure cookies, HSTS, JSON logs, strict `SECRET_KEY` check |
| `SECRET_KEY` | Random ≥ 32 chars | Required when `ENV=prod` |
| `APP_ENCRYPTION_KEY` | URL-safe base64 (32 B) | Required for saving org BYO LLM keys in `/settings` and encrypted uploads |
| `ALLOW_SIGNUP` | `false` (after first user) | When `false`, **only the very first user** can register (as instance owner); others get `404` |
| `PROXY_COUNT` | `1` | Trusted proxy hops in front of Flask (`1` behind Caddy or Cloudflare Tunnel → Caddy) |
| `APP_BASE_URL` | `https://asm.example.com` | Base URL used for links in email digest notifications |
| `DNS_RESOLVERS` | `1.1.1.1,8.8.8.8` | Public recursive resolvers only (private/loopback resolvers are refused at startup) |

### Optional: AI Triage & Exposure Summaries

- **Instance-wide key:** set `LLM_PROVIDER` (`anthropic` or `openai_compat`), `LLM_MODEL`,
  `LLM_API_KEY`, and optionally `LLM_BASE_URL` + `LLM_MONTHLY_INSTANCE_TOKEN_BUDGET` (default
  `500000`).
- **Bring-Your-Own-Key (BYOK):** leave `LLM_API_KEY` empty and configure per-org keys under
  `/settings`. To allow self-hosted endpoints (e.g., Ollama/vLLM), list their exact hostnames in
  `LLM_ALLOWED_BASE_HOSTS=ollama.internal`.

### Optional: Email Digest Notifications

Set `SMTP_HOST`, `SMTP_PORT` (`587`), `SMTP_TLS` (`starttls`), `SMTP_USER`, `SMTP_PASSWORD`, and
`SMTP_FROM` to send plain-text + HTML digests when scans discover new or regressed findings.

## 4. Deploy with Prebuilt Release Images

Using the official multi-arch images (`linux/amd64`, `linux/arm64`) published to GitHub Container
Registry (`v0.1.0` tag → `:0.1.0`, without the `v` prefix):

```bash
export WEB_IMAGE=ghcr.io/cpt9m0/attacksurf:0.1.0
docker compose -f compose.prod.yaml pull web worker-passive worker-ai beat migrate
docker compose -f compose.prod.yaml build caddy
docker compose -f compose.prod.yaml run --rm migrate
docker compose -f compose.prod.yaml up -d --wait
```

On first launch, open your instance URL and visit `/signup` to create the initial owner account.
With `ALLOW_SIGNUP=false`, `/signup` closes automatically once that first user is created.

> [!NOTE]
> The production stack (`compose.prod.yaml`) runs containers read-only with `cap_drop: [ALL]`,
> isolates `postgres` and `redis` on an `internal: true` network, and exposes no direct database or
> Redis ports to the host.

## 5. Backups, Upgrades, and Hardening

- **Backups & restore drills:** see [Nightly off-box backups](deployment.md#nightly-off-box-backups-and-restore-drill)
  for `scripts/backup.sh` (custom `pg_dump` + optional `age` encryption + `rclone` off-box upload)
  and `scripts/restore.sh --verify-only`. Back up `APP_ENCRYPTION_KEY` and `SECRET_KEY` separately
  in a password manager.
- **Upgrading:** update `WEB_IMAGE` to the new release tag, pull, run `migrate`, and `up -d --wait`:
  ```bash
  export WEB_IMAGE=ghcr.io/cpt9m0/attacksurf:<new-version>
  docker compose -f compose.prod.yaml pull web worker-passive worker-ai beat migrate
  docker compose -f compose.prod.yaml run --rm migrate
  docker compose -f compose.prod.yaml up -d --wait
  ```
- **Host hardening & TLS:** review [Host hardening checklist](deployment.md#host-hardening-checklist)
  (SSH key auth, UFW firewall, `unattended-upgrades`, `fail2ban`, journald/Docker log rotation).
- **Responsible use:** review [docs/responsible-use.md](responsible-use.md) before scanning any
  targets.
