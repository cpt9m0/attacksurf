# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- WordPress exposure and passive version-matching check (`web.wordpress`,
  `scanners/web/wordpress.py`) wired into `web_active.checks`, `app.py`, `workers/app.py`, and
  `web.probe` passive `?ver=` asset extraction (`scanners/web/fingerprint.py`): gates strictly on
  WordPress detection (`#73`), matches core (`/feed/` / generator) and HTML `?ver=` plugin/theme
  versions against the local NVD store (`#74`), and checks `web.wordpress.xmlrpc_enabled`,
  `web.wordpress.user_listing` (count-only evidence), `web.wordpress.debug_log` (structural
  metadata only), and `web.exposure.directory_listing` (`/wp-content/uploads/`) under ADR 0033
  `ScopeGuard` `http_paths` enforcement (#79).
- Fixed-path exposed sensitive file, debug endpoint, API docs, admin panel, and `security.txt`
  scanner (`web.exposures`, `scanners/web/exposures.py`) wired into `web_active.checks`, `app.py`,
  and `workers/app.py`, alongside ADR 0033 `ScopeGuard` enforcement (`http_methods`, `http_paths`,
  single-shot `soft_404_probe`) and `SafeHttpClient.head`: detects `web.exposure.git_repo`,
  `env_file`, `backup_archive`, `debug_endpoint`, `api_docs`, `admin_panel`, and
  `web.security.security_txt_missing` using soft-404 calibration, per-path content validators,
  `HEAD`-only probes for archives and `/actuator/heapdump`, and key-name-only `.env` evidence
  (#78).
- HTTP security headers, cookie flags, HTTPS redirect, and CORS credential reflection checks
  (`web.headers`, `web.cors`, `scanners/web/headers.py`) wired into `web_active.checks`, `app.py`,
  and `workers/app.py`, plus `SafeHttpClient.get(..., headers=...)` forwarding through
  `ScopeGuard`: checks `hsts_missing`, `hsts_weak` (`< 180` days), `csp_missing`, `csp_unsafe`
  (`unsafe-inline` without nonce/hash or `unsafe-eval`), `clickjacking`, `nosniff_missing`,
  `web.cookies.insecure_flags`, `web.https.no_redirect`, and `web.cors.wildcard_credentials` with
  relevant-header evidence only and `Asset.details["security_headers"]` summary (#77).
- Guarded TLS certificate and protocol configuration check (`web.tls`, `scanners/web/tls.py`)
  wired into `web_active.checks`, `app.py`, and `workers/app.py`: inspects verified `https://`
  URLs over `ctx.runtime.tls`, records capped `Asset.details["tls"]`, and checks all 7 TLS rules
  (`web.tls.cert_expired`, `cert_expiring`, `hostname_mismatch`, `untrusted_chain`, `weak_key`,
  `weak_signature`, `legacy_protocol`) with parsed chain-summary evidence (#76).
- Known-vulnerable web component matcher (`web.components`, `scanners/web/components.py`),
  wired into `web_active.checks`, `VulnIntelLookup` / `DbVulnIntelLookup`, and
  `ScanContext.target_details`: maps fingerprinted URL technologies with versions to NVD CPEs,
  queries the local NVD/KEV/EPSS store, emits `web.components.known_vulnerable` findings with
  CVSS-derived severity raised on CISA KEV, `medium` confidence, capped CVE evidence, and stable
  evidence digesting across daily EPSS updates (#75).
- Passive web technology fingerprinting (`scanners/web/fingerprint.py`) over captured `web.probe`
  responses using a curated, ReDoS-audited dataset vendored from `enthec/webappanalyzer`
  (GPL-3.0; headers, Set-Cookie names only, `<meta>`, `<script src>`, HTML patterns, and
  `implies` propagation), storing `technologies: [{name, version, categories, confidence}]` on URL
  asset `details` and emitting info finding `web.disclosure.version_banner` (`domain.rules.web`)
  when `Server` or `X-Powered-By` exposes a version (#73).
- `web.probe` HTTP service discovery scanner (`scanners/web/probe.py`) and `web_active` profile
  (selectable in UI/API): probes `https://` then `http://` on active verified domains/subdomains
  and refreshes `url` assets, creates `url` assets + `serves` edges with capped `Asset.details["web"]`
  metadata and `<redacted>` `Set-Cookie` values, adds `http_ports`/`follow_redirects` grants plus
  verified-root URL ownership and out-of-scope redirect halting in `ScopeGuard`/`SafeHttpClient`,
  and adds `build_http_response_evidence` (`EvidenceKind.HTTP_RESPONSE`) (#72).
- Global vulnerability intelligence store (`vuln_cves`, `vuln_cpe_ranges`, `vuln_sync_state`,
  migration `0015`), pure CPE 2.3 and version-range matching (`domain.vulnintel`,
  `services.vulnintel.match_product`), daily `passive.vulnintel_sync` Celery Beat task fetching NVD
  CVE 2.0, CISA KEV, and FIRST EPSS over `VULNINTEL_GRANT` (optional `NVD_API_KEY`), custom headers /
  `max_body_bytes` / cross-origin secret-header stripping in `SafeHttpClient`, and NVD/KEV/EPSS
  attribution (#74).
- Guarded TLS handshake adapter (`infra/tls.py`, `ctx.runtime.tls.inspect`) with IP pinning, SNI,
  web-port allowlists (`ScannerGrant.tls`/`tls_ports`), bounded chain parsing, non-raising cert
  validation reporting, best-effort TLS 1.0/1.1 probing, and `ssl` scanner import ban (#71, ADR 0033).
- Active worker queue (`active.scan`), isolated `worker-active` service on `active-egress` in dev
  and prod Compose, `ACTIVE_SCANS_ENABLED` kill switch (default `false`), identifying
  `User-Agent` (`SCANNER_CONTACT_URL`), and Redis-backed per-`(org, host)` token-bucket rate and
  concurrency limiting in `SafeHttpClient` (#70, ADR 0033).
- [ADR 0033](docs/adr/0033-website-network-grants.md) defining network grants, guarded TLS
  handshakes, allowed HTTP methods/ports/paths, `active` queue isolation, per-target rate limits,
  identifying `User-Agent`, `ACTIVE_SCANS_ENABLED` kill switch, and hard defensive boundaries for
  website checks (#69).

## [0.1.0] - 2026-11-22

First public alpha release (MVP): AI-powered attack surface management with passive and verified-active DNS discovery/checks, finding lifecycle and rescan diffing, AI triage and exposure summaries, recurring schedules, email digests, and single-VPS Docker deployment.

### Added
- MVP acceptance, security hardening, and documentation (#30):
  - Full-stack Chromium Playwright E2E test (`tests/e2e/test_mvp_e2e.py`) exercising signup, domain intake, DNS TXT ownership verification, passive + verified-active scan, AI triage and exposure summary, false-positive suppression with required comment, and DNS mutation rescan diff against PostgreSQL.
  - Exhaustive route security test matrix (`tests/integration/web/test_route_security.py`) verifying auth, CSRF, admin role checks, cross-tenant isolation, and encrypted-key non-disclosure across every registered endpoint, plus template CSP/autoescape and `Settings`-only config AST checks (`tests/unit/web/test_security.py`) and tenant-scoped `artifacts._defer_retry`.
  - Supply-chain CVE auditing (`make audit` and CI `audit` job with `pip-audit==2.10.1`) and dependency lockfile upgrades (`dnspython`, `filelock`, `opentelemetry-api`, `virtualenv`).
  - Scale & scan-detail improvements for ~1k-subdomain scans (`tests/integration/workers/test_scale_1k.py`): batched job planning in `services.scans.dispatch_stage`, `MAX_DETAIL_JOBS = 200` job list cap with exact SQL status counts in `services.scan_views`, and `mark_completed = False` on `passive.scan`.
  - Overview & Mermaid diagrams in `README.md` and `docs/architecture.md`, cataloged scanners/rules (`docs/scanners.md`), plugin guide (`docs/writing-a-scanner.md`), `docs/self-hosting.md`, `docs/responsible-use.md`, and doc-sync verification (`tests/unit/scanners/test_docs_sync.py`).
- All-page hermetic Playwright screenshot harness (`scripts/capture_screenshots.py`, `make screenshots`, `tests/e2e/web/ui_fixtures.py`) rendering 20 canonical UI screens/states across light & dark themes at desktop (`1440×900`) and mobile (`390×844`) viewports with an HTML gallery and overflow diagnostics, plus automated WCAG 2.2 AA contrast & dark-theme parity verification (`tests/unit/web/test_design_tokens.py`) and comprehensive UI/UX improvements:
  - Upgraded `tokens.css` and `app.css` with contrast-verified light/dark surface hierarchy, semantic tinted status pills (`pill-good`, `pill-bad`, `pill-active`), interactive hover states, styled native `<progress>` and file inputs, card-aligned table margins, and `tabular-nums` metrics.
  - Consolidated `/assets` intake forms (*Add a domain*, *Upload a codebase*, *Upload a binary or mobile app*) into a compact tabbed intake card (`Alpine.data("assetIntake")`, graceful no-JS fallback) to bring the asset inventory above the fold.
  - Added primary CTA (`Add a domain`) to the Dashboard empty state, theme toggle and `shield-check` brand icon to signed-out auth pages, copy button (`Alpine.data("copyField")`) and scroll cap to Finding Detail evidence blocks, active sidebar nav highlighting on Scan Detail and Finding Detail, clickable finding links on the Asset Detail *Findings* tab, debounced live search and baseline alignment on the Findings *Asset* filter, and fixed `.card > .card-header`, `.field.field-check`, `.dns-chain`, and `.page-actions` layout issues.
- Production deployment hardening, backups, optional Sentry, and GHCR releases (#29):
  - Hardened `compose.prod.yaml` with `read_only: true`, `cap_drop: [ALL]`, PID/CPU/memory
    limits, bounded `json-file` log rotation, `internal: true` network isolation for
    `postgres`/`redis`/`caddy`/`migrate`, Redis `--maxmemory 192mb --maxmemory-policy noeviction`,
    non-root `caddy` (`uid 10001`), and Gunicorn tuning (`--timeout 120`, `--max-requests 1000`,
    `--worker-tmp-dir /dev/shm`) with `/tmp` `tmpfs` headroom (`320m`) for uploads; `scripts/deploy.sh`
    now passes `SENTRY_RELEASE` and prunes older `attacksurf-web` images while retaining the
    previous release for instant rollback.
  - Added optional, env-gated Sentry error tracking (`SENTRY_DSN`, `SENTRY_ENVIRONMENT`,
    `SENTRY_RELEASE`, `SENTRY_TRACES_SAMPLE_RATE`) via `infra.sentry` (`sentry-sdk[flask,celery]`)
    with `send_default_pii=False`, `include_local_variables=False`, and `before_send` /
    `before_breadcrumb` scrubbing reusing `infra.logging` credential/key redaction.
  - Added nightly off-box PostgreSQL backups (`scripts/backup.sh`, `deploy/backup.env.example`,
    `deploy/systemd/attacksurf-backup.{service,timer,tmpfiles.conf}`) via `rclone` with optional
    client-side `age` encryption and retention pruning, plus `scripts/restore.sh` (`--verify-only`
    throwaway-DB drill and `--live` recovery).
  - Added tag-triggered (`v*.*.*`) multi-arch (`linux/amd64`, `linux/arm64`) GHCR release workflow
    (`.github/workflows/release.yml`) and documented host hardening (SSH, UFW,
    `unattended-upgrades`, `fail2ban`), log rotation, and restore verification in `docs/deployment.md`.
- Email digest notifications (#28, ADR 0032): `passive.notify_scan` runs at the end of the
  post-scan AI phase (or its skip/failure exits) and sends each opted-in org member a plain-text
  + HTML digest (no external tracking) of new and regressed findings (`FindingObservation.regressed`,
  migration `0014_add_notifications`) meeting their severity threshold, with the AI exposure
  summary headline when available. `infra.email.SmtpEmailSender` delivers over env-configured
  SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`,
  `APP_BASE_URL`), `NotificationDelivery` prevents duplicate emails across retries, `/settings`
  adds a per-user Email notifications card (`POST /settings/notifications`), and `compose.yaml`
  adds `mailpit` for local previewing.
- Analysis worker and sandbox services in the dev stack (#84): `worker-analysis`,
  `sandbox-launcher` and `sandbox-proxy` run behind the opt-in Compose `sandbox` profile on an
  internal network, the `analysis` queue is consumed from now on (ADR 0031), and an empty
  `sandbox-images.lock` ships in the image, so no analyzer can run yet. Prod runs none of it
  until #92.
- AI exposure summary and notable assets (#26, ADR 0030): after triage finishes (or when a scan
  has nothing new to triage), `ai.summarize` makes one LLM call with the versioned prompt
  `summary/v1` using change stats, up to 25 observed findings (triaged first, no raw evidence)
  and up to 200 active assets under the scan's root inside `<scan_data>`. `validate_summary`
  maps batch-local refs (`F1`..`F25`, `A1`..`A200`) to real finding and asset UUIDs and drops
  every unknown or duplicate ref before storing `StoredSummary` on `Scan.ai_summary`
  (`0013_add_scan_ai_summary`). Flagged hosts receive the AI-owned `notable` tag on `Asset.tags`
  under that root without disturbing other tags or roots. The scan page shows a polled
  `#scan-summary` card (`ui.scan_summary`) and the dashboard shows a "Latest AI summary" card
  per active root with its top 3 risks. Summary eval cases (`risky_scan`, `clean_scan`) run
  alongside triage evals in `make eval`.
- AI triage (#25, ADR 0029): after a scan completes, `ai.triage` runs one `ai.triage_batch`
  job per asset (at most 20 findings, one LLM call each) with the versioned prompt
  `triage/v1`. Each finding gets an adjusted severity, confidence, false-positive likelihood,
  a P1 to P4 priority, rationale, exploitation notes and fix steps, stored in
  `Finding.ai_triage` and shown in an AI panel on the finding page and a polled section on the
  scan page. Scan data reaches the model only as escaped, capped JSON in `<scan_data>` with
  batch-local refs; replies are schema-validated and unknown refs dropped; judgments are cached
  by prompt version, model and everything the prompt shows about the finding (fingerprint,
  evidence digest, scanner severity and confidence, title, description); the budget is checked
  before every call; `LLM_TRIAGE_INCLUDE_INFO` opts `info` findings in. `make eval` runs the
  eval set against the LLM in `.env`.
- Recurring scans (#27): one per-root schedule (`0012_add_scan_schedules`), weekly by default
  for new domains (`SCAN_DEFAULT_FREQUENCY`), a minute beat tick that claims due rows with
  `FOR UPDATE SKIP LOCKED` and starts the read-only `dns_scheduled` profile through
  `start_scan`, and an admin-only card on the root's overview to change or turn it off.
- Findings UI (#22): a filterable, sortable findings list with bulk status actions and
  CSV/JSON export that warns when the download cap is exceeded; a detail page with
  escaped evidence (DNS records, HTTP snippets, raw JSON), remediation, references,
  timeline and an AI-triage placeholder; accept-risk /
  false-positive decisions that require a comment and are audited, plus reopen; a dashboard
  with open findings by severity, the newest findings, the asset count and each root's last
  scan; and `/api/v1/findings` list/detail/status/bulk endpoints. Status comments live in
  the audit log, so no schema change was needed; scans keep owning `fixed`/`regressed`.
- Production `worker-ai` consumes Settings connection tests from the `ai` queue, with a
  secret-aware targeted healthcheck that gates deployment (#24).
- Organization AI settings, encrypted BYO API keys, SSRF-guarded custom `base_url`s, monthly UTC token budget enforcement, and monthly AI usage breakdown on `/settings` (`0011_add_org_settings`, `SecretCipher` with `APP_ENCRYPTION_OLD_KEYS` rotation, `validate_llm_base_url`, `services.org_settings`, `services.llm_usage.get_usage_summary`, `LLM_MONTHLY_INSTANCE_TOKEN_BUDGET`, `LLM_ALLOWED_BASE_HOSTS`, #24).
- Provider factory (`ai/factory.build_provider`, #23): turns a resolved `LLMConfig` into the
  Anthropic or OpenAI-compatible adapter it names, without a network call, so AI features
  never pick an adapter themselves. Completes the LLM provider layer.
- OpenAI-compatible provider (`ai/providers/openai_compat.py`, #23): Chat Completions requests
  with `max_completion_tokens`, native `json_schema` structured output with HTTP 400 fallback to
  `json_object` and then plain text (including the schema in the system prompt), the base URL
  always passed explicitly so `OPENAI_BASE_URL` can't redirect a key, `finish_reason`
  `length`/`content_filter` and `message.refusal` failing at once with usage, unreadable 2xx
  replies treated as transient, missing usage recorded as unreported, and `CALL_DEADLINE_SECONDS`
  enforced across format fallbacks and the corrective retry. Passes the shared provider contract
  against a stubbed API, adds an opt-in `llm_live` test (`tests/e2e/test_openai_compat_live.py`),
  and adds `openai` (`>=3.41.0,<3.42`, two-week supply-chain policy) to the import-linter SDK
  contract (ADR 0019, ADR 0024).
- Scans UI: start a `dns_passive` scan from the Scans page or an active root domain's page,
  watch stage/job progress polling every 2 s, cancel a running scan, and review the new /
  fixed / regressed finding diff with new and disappeared assets when it finishes. Same over
  `/api/v1/scans`: `POST` creates from a `root_asset_id` (201, `Location`), `GET` lists and
  shows one scan with its jobs and diff. Starting and cancelling is open to every org
  member; a second concurrent scan of the same root is refused (409 with the running scan's
  id) and each org may start `SCAN_MAX_STARTS_PER_HOUR` scans per profile per hour (default
  10, 429 beyond it; the count and the insert are serialized on the org row, so concurrent
  starts for different roots cannot both slip under the quota). Cancellation is database-only
  like archiving (ADR 0021): queued work drains without writing, nothing is revoked in
  Celery (#21).
- Worker-side sandbox client: `infra.sandbox.LauncherSandboxRunner` calls `sandbox-launcher`, and
  the worker gate uses it when the new `SANDBOX_LAUNCHER_URL` setting is set (plain
  `http://host[:port]` only; unset, the workers refuse every sandbox request). The reply is
  size-capped and strictly validated, only a busy or unreachable launcher is retried, and no
  reply text reaches a log or a stored job error (ADR 0016, #84).
- `sandbox-launcher` service (`python -m attacksurf.sandbox_launcher`): `POST /runs` takes an
  analyzer name and artifact ID and runs the analyzer in one proxy-approved sandbox, killing it
  at the wall time or past 2 MiB of stdout and always removing the container. It refuses to
  start in prod unless `runsc` is a registered runtime, and exits instead of running with a
  weaker sandbox (ADR 0016, ADR 0023, #84).
- Upload a binary or mobile app: the Assets page takes an ELF, PE or Mach-O executable, an
  Android `.apk` or an iOS `.ipa` (gated by its leading bytes; a text file is refused with a
  415 before anything is stored), stores it encrypted as an artifact of a binary asset named
  `sha256:<digest of its bytes>` and queues a `binary_static` scan. The file name is kept for
  display only and shown escaped; the same bytes uploaded again reuse the asset. The scan stays
  queued until the analysis worker ships (#84). Binaries are never executed, emulated or
  decrypted. All upload routes share one allowance of 20 uploads per user per hour (#101).
- Binary format detection for the analysis sandbox: `attacksurf.sandbox_tools.detect`, a
  standard-library tool that names the format from fixed-size headers (ELF, PE, thin and
  universal Mach-O, told apart from Java class files) and from a size-capped zip central
  directory (APK, IPA; inconsistent or APK-and-IPA zips are rejected), without decompressing
  anything; exit status 3 means rejected, 4 an I/O
  failure. Not wired to a run yet; ships with a synthetic corpus in `tests/fixtures/binaries/`
  (#101).
- Upload a codebase archive: the Assets page takes a `.zip` or `.tar(.gz/.bz2/.xz)` (checked by
  its leading bytes, never opened outside the sandbox), stores it encrypted as an artifact of
  a repo asset `upload/<name>` and queues a `code` scan that records the archive's SHA-256 as
  its revision. Uploading the same name again adds a version to the same asset. The scan stays
  queued until the analysis worker ships (#84). Request bodies are now capped everywhere (2 MiB;
  `ARTIFACT_MAX_BYTES` plus framing on the upload route, 413 beyond it), uploads are rate
  limited per user, and repo values are normalized (`host/owner/name`, ADR 0017). The prod
  stack gets an `artifact-store` volume; uploads stay off there until `APP_ENCRYPTION_KEY` is
  set (#87).
- Safe archive extraction for the analysis sandbox: `attacksurf.sandbox_tools.extract`, a
  standard-library tool that analyzer images will run before their scanner. It unpacks zip and
  tar(.gz/.bz2/.xz) with its own loop, never creates links, strips setuid/setgid/sticky bits,
  skips symlinks, hard links, device nodes and FIFOs with a reason, and rejects the whole
  artifact on unsafe or duplicate paths, corrupt archives, data after a tar's end, differing zip
  headers or a cap (512 MiB total, 64 MiB per file, 100,000 entries including created
  directories, depth 32, ratio 200:1), all counted while writing; for tar the size budget also
  covers bytes the parser skips. It writes a manifest (path, size, SHA-256, skipped entries)
  and prints a bounded summary; exit status 3 means rejected, 4 an extractor failure. Not wired to a run yet; ships with a hostile archive corpus in
  `tests/fixtures/archives/` (ADR 0017, #86).
- Encrypted artifact storage for uploaded and fetched repositories and binaries: an `Artifact`
  model (migration 0010), streaming AES-256-GCM envelope encryption with a per-artifact key
  wrapped by the new `APP_ENCRYPTION_KEY`, a per-artifact size limit enforced while reading
  (`ARTIFACT_MAX_BYTES`), a per-organization quota (`ARTIFACT_ORG_QUOTA_BYTES`), plaintext
  staged only for one sandbox run, and a retention task (`passive.purge_expired_artifacts`,
  every 10 minutes) that deletes expired files and erases their keys
  (`ARTIFACT_RETENTION_HOURS`; 0 = delete once analysis completes). Storage only: no upload
  route yet. Adds the `cryptography` dependency (ADR 0028, #85).
- LLM usage tracking: an `llm_usage` row per finished LLM call, failed ones included, with the
  model, purpose, whose key paid, token counts, latency and a cost estimated from list prices
  in `ai/pricing.py`. Prompts, replies, error messages and keys are never stored. The app warns
  at startup when the instance key or model is missing, so AI being off isn't silent (#23).
- Scan diffing and the finding lifecycle: a scan marks findings it no longer sees `fixed` only
  when their own scanner completed for that asset, a previously fixed finding observed again
  becomes `regressed`, suppressed (`accepted_risk`/`false_positive`) findings reopen only on
  materially different evidence, and `Scan.stats` records new/fixed/regressed/total findings by
  severity plus new assets and disappeared subdomains for the scan-history view (ADR 0027,
  #20).
- DNS hygiene checks (`dns.dnssec`, `dns.ns`, `dns.mx`, `dns.caa`, `dns.whois`, `dns.axfr`):
  DS/DNSKEY delegation-chain checks (`dns.dnssec.not_enabled` info, `dns.dnssec.broken_chain`
  high), single-nameserver / lame-delegation / inconsistent-SOA detection (`dns.ns.*`), MX
  targets that are aliases or do not resolve (`dns.mx.*`), missing CAA (`dns.caa.missing`),
  registration expiry and a missing registrar transfer lock via RDAP (`dns.whois.*`, 24-hour
  cache), and unauthenticated zone transfers on verified roots (`dns.axfr.allowed`, high). Adds
  grant-gated authoritative DNS, RDAP and zone-transfer adapters and wires the checks into the
  `dns_passive` profile (ADR 0026, #19).
- Subdomain takeover checks (`dns.takeover`, `dns.takeover.http`): dangling CNAMEs to
  known-claimable services that no longer resolve and NS delegations to nameservers that no
  longer exist are flagged from DNS alone; on verified domains a single HTTP probe also
  flags resolving services answering with their "unclaimed instance" signature. Reports
  `dns.takeover.dangling_cname` / `dns.takeover.fingerprint_match` (high) and
  `dns.takeover.dangling_ns` (critical) against a pinned subset of the can-i-take-over-xyz
  fingerprint dataset (CC-BY-4.0); wired into the `dns_passive` profile checks (#18).
- Email security check (`dns.email`): passive evaluation of SPF, DMARC, DKIM and MTA-STS
  publication from TXT DNS records, reporting `dns.email.*` findings (missing/multiple/
  permissive SPF, >10 SPF DNS lookups, missing/monitor-only/unreported/partial DMARC,
  undiscovered DKIM selectors at low confidence, missing MTA-STS as info) with raw TXT
  records as evidence; wired into the `dns_passive` profile checks (#17).
- DNS resolution (`dns.resolve`): configurable public resolvers with async, bounded queries;
  A/AAAA/CNAME/MX/NS/TXT/CAA/SOA records stored in `Asset.details["dns"]`; IP assets with
  `resolves_to` edges and in-root `cname_to` chains; reverse DNS and optional offline ip2asn
  enrichment; non-resolving subdomains marked inactive; and the info finding
  `dns.records.private_ip_exposed` for private/special-purpose addresses. Asset detail shows the
  CNAME → IP chain and records (ADR 0025, #16).
- Sandbox launcher building blocks: env-only settings (the proxy URL is a `SecretStr`, since it
  may embed credentials), an analyzer catalog (empty until the first analyzer ships), an artifact
  resolver that refuses symlinks and anything outside the artifact root, a create-body builder
  checked against the proxy's policy, and a stdout reader that drops stderr, caps output at 2 MiB
  and rejects truncated streams (#84).
- Subdomain discovery from Certificate Transparency: `dns.discovery.ct` queries crt.sh's JSON
  endpoint with Cert Spotter as fallback, normalizes and caps names per root (1000), caches
  complete results in a namespaced Redis cache for six hours, and detects wildcard DNS zones.
  Wildcard zones are persisted as `Asset.details["wildcard"] = true` for later resolution, and
  all network access stays behind ScopeGuard (ADR 0022, #15).
- `sandbox-proxy` service: the only holder of the Docker socket, allowing six container actions
  on containers it created and refusing any create request outside the sandbox policy (#84).
- `sandbox-proxy` answers `GET /info` with the registered runtime names only, so the launcher
  can refuse to start in prod without `runsc` (ADR 0023, #84).
- CD is verified end-to-end: a merge to `main` reaches production within one timer
  interval, and the running `web` image tag matches the recorded deployed SHA (#29).
- Pull-based CD: `scripts/deploy.sh` (also `make deploy`) fetches `origin/main`, builds the
  images tagged with the short SHA, runs `migrate` before replacing `web`, smoke-tests
  `/healthz` through the ingress and rolls back to the previously deployed SHA on failure; the
  deployed SHA is recorded in `/var/lib/attacksurf/deployed-sha` (#138).
- Pull-based CD units (`deploy/systemd/`): `attacksurf-deploy.timer` runs `scripts/deploy.sh`
  every 3 minutes (±45 s jitter) as root under a `flock`, so a merge to `main` reaches
  production within one interval with no inbound port, no GitHub secret and no runner; the
  deployed SHA lands in the journal and in `/var/lib/attacksurf/deployed-sha` (#29).
- Sandbox port for scanners: `ctx.runtime.sandbox.run(analyzer, artifact_id)`, limited to the
  analyzers in a plugin's `ScannerGrant` and refused until a runner is configured (#84).
- Production stack (`compose.prod.yaml`) published through a Cloudflare Tunnel: `cloudflared`,
  Caddy, gunicorn, PostgreSQL and Redis on a private network with no inbound ports, `www`
  redirecting to the apex, and a deploy runbook in `docs/deployment.md` (ADR 0020, #132).
- Production `worker-passive` and `beat`: ownership checks, `dns_passive` scans and the
  artifact purge are consumed on attacksurf.dev instead of staying queued; both are gated by
  `up -d --wait` healthchecks and the deploy's idempotence check covers every long-running
  service (#174).

### Fixed
- Delayed AI exposure summaries retain their historical results without overwriting a newer
  scan's `notable` asset tags: publication is serialized per root, and tag updates use the
  dashboard's scan ordering (`created_at`, then `id`) (#26).
- An LLM call that hits its deadline now ends its HTTP request too, instead of leaving it
  running in an abandoned thread: a server that kept trickling bytes could hold threads and
  connections open in a Celery worker indefinitely. Both providers build their SDK client on a
  network layer (`ai/providers/deadline.py`) that caps every connect, read and write at the time
  left (#23).
- Ownership verification no longer spins forever when no worker consumes the queue: a verify
  job still queued past five minutes renders `Stalled` with a queue (not record) explanation
  and stops the 2-second poll until workers are back (#174).
- Artifact staging and deletion are serialised per artifact with a `flock`, so a purge can no
  longer mark an artifact deleted mid-staging and leave its plaintext mounted until the sweep,
  and a failed purge pushes its artifact behind the rest of the queue instead of starving it
  on every run (#85).
- Artifact deletion now fails instead of reporting success when the staged plaintext cannot be
  removed: the key is kept and the row stays live, so the purge retries it instead of leaving
  mountable plaintext for a deleted artifact (#85).
- The content area fills the main column on every viewport instead of stopping at a 72rem cap,
  so wide screens no longer leave empty space to the right of the dashboard (#149).
- Pyright and pytest pass on Windows again: pyright checks as Linux (where the app runs), and
  the sandbox proxy server tests, which need Unix sockets, skip on Windows (#84).
- The archived-roots due-verification test recorded its check at the real time instead of the
  test clock, so it passed without testing the archive filter (#14).
- Archiving a root domain now cancels its queued and running scans in the same transaction, and
  they show as `cancelled` in the scan history. Nothing under an archived root becomes active or
  produces a new finding afterwards, whatever stage the scan was in: persistence drops output for
  a cancelled scan or an archived root (ADR 0021, #116).
- The app shell fits a phone viewport: the top bar wraps and truncates the user menu (full text
  in `title`) and the mobile nav row scrolls inside itself instead of widening the page (#114).
- The `playwright` dev dependency is pinned to 1.64.1 (`>=1.64.1,<1.65`), the newest release
  that satisfies the two-week dependency-age policy, instead of the day-old 1.65.0 (#114).
- Deploying into a checkout owned by another user (the pre-CD copied tree, or a clone made by a
  person while the timer runs as root) no longer fails with git's "dubious ownership" error:
  `scripts/deploy.sh` trusts its own `APP_DIR` for its git calls (#29).
- Sandbox proxy retains ownership after rejected removals, reclaims capacity after confirmed
  automatic removal, and reserves in-flight create capacity atomically, so concurrent requests
  cannot exceed its container cap (#84, PR #135).
- Unknown Docker-create outcomes retain their reserved slot and receive a proxy-generated
  name for forced cleanup; failed cleanup (including 404 while creation may still be running)
  never frees capacity. Subsequent create requests retry reconciliation (#84, PR #135).
- Legacy Docker API prefixes below v1.30 are denied so clients cannot disable AutoRemove or
  downgrade removed-wait semantics and bypass the container cap (#84, PR #135).
- Proxy settings tests clear all application and proxy environment fields, including the
  documented dev runtime fallback, before constructing settings (#84, PR #135).
- Proxy environment settings and defaults are documented in `.env.example` (#84).
- Login and signup rate limits key on the visitor address Cloudflare forwards
  (`CF-Connecting-IP`, else the leftmost `X-Forwarded-For` entry) instead of the first proxy
  hop, so visitors behind the tunnel no longer share one budget (#132).
- LLM endpoint credentials are masked in settings and provider-config representations;
  base URLs remain `SecretStr` through config resolution (#23).
- The test suite passes on Windows checkouts: `.gitattributes` keeps LF line endings whatever
  the local `core.autocrlf` setting (vendored files are never converted, so their SHA-256
  checks hold), the vendor tests read files as UTF-8, and the connection-failure test simulates
  a refused connection instead of dialing a closed port (Windows retries it until the timeout).
- Tests: hermetic worker settings are installed before pytest collection, so collecting a
  module-level Celery task can't load `.env` into the worker config and fail the suite on
  machines whose `REDIS_URL` differs from the default (#126).
- Ownership review fixes (#14): renew proofs four hours before authorization expires, keep
  inherited subdomain cards read-only across polling, and retry zone-discovery failures
  instead of treating them as missing proof records (migration 0007; ADR 0015).
- Flaky CSRF test: corrupting a token's last base64 character can keep the signature valid
  (padding bits), so the test now changes the first one (#119).
- Run database migrations as part of dev `make up`, before starting application services,
  preventing signup from returning HTTP 500 on a fresh database.
- Document the Docker socket permission fix for Linux sessions with stale group membership,
  including safe setup steps and the security implications of Docker access.
- Auth hardening from review: atomic first-user signup, login password length bound, login
  gate before CSRF (anonymous writes get 401/redirect), logout clears the session even if the
  audit write fails, absolute session lifetime enforced server-side
- Review follow-ups on the ScopeGuard PR: the run-scoped HTTP client now enforces the grant
  policy before its first request (not only on redirects) and applies the body-size ceiling to
  the decoded body whatever limit a plugin passes; a `TARGET` HTTP grant always requires
  verified ownership; the discovered-asset cap counts against the scan root under a row lock, so
  neither overlapping scans nor checks on discovered subdomains can exceed it; and a
  `ScopePolicyError` from the gate fails only its job instead of the whole scan (ADR 0013).
- Response decoding clamps every fallback to the requested limit (a corrupt or unknown
  `Content-Encoding` no longer returns the oversized wire buffer), decodes all concatenated
  gzip members — carrying unread bytes across members instead of dropping them — and reports a
  stream that ends before its final block as truncated instead of returning partial content
  silently.

### Changed
- Scans complete before AI triage starts (#25, ADR 0029): the chain ends at `finalize`, which
  queues the `ai.triage` job, so AI failures never fail a scan. `passive.triage` stays one
  release as a no-op for chains queued before the deploy. AI jobs are left out of a scan's job
  count, and `PipelineTask`'s chord-member behavior moved to `workers.base.ChordTask`.
- The runtime image moves to Python 3.15 (`python:3.15-slim`) and CI also tests 3.15; this
  needs `pydantic` 2.14.1, whose pinned `pydantic-core` 2.50.1 ships CPython 3.15 wheels, and
  `grimp` 3.18 so `import-linter` installs on 3.15 (#154).
- The LLM contract has no `temperature` any more: Anthropic API version `2026-10-21` (sent by
  the `anthropic` 2.x SDK) rejects sampling parameters on every model, and nothing used it, so
  models run with their defaults (ADR 0024, #23).
- LLM SDK clients no longer retry (`ai/limits.MAX_RETRIES = 0`): Celery's task retry is the
  only retry layer, so errors don't multiply requests or park an `ai` worker in `Retry-After`
  sleeps (ADR 0024, #23).
- Dependencies: add the `anthropic` SDK (2.3.0, the newest release at least two weeks old;
  `jiter` and `opentelemetry-api` pinned back the same way). The scanner network-boundary test
  also bans its `httpx2`/`httpcore2` HTTP stack and the LLM SDKs (#23).
- `LLM_MODEL` no longer defaults to a Claude model in code: model names come only from config,
  and an instance without both `LLM_API_KEY` and `LLM_MODEL` has AI off (ADR 0019).
  Developers set the Meta development configuration in their own `.env` (see
  `docs/development.md`). `LLM_PROVIDER` is validated as a `ProviderKind`.
- Deleting a scan keeps its jobs (with `scan_id` NULL) instead of deleting them, so job history
  survives scan pruning and work outside a scan can be tracked.

### Added
- Anthropic provider (`ai/providers/anthropic.py`, #23): Messages API requests with native
  JSON-schema output, the system prompt split out, thinking blocks ignored, cached input
  tokens counted as input, SDK errors mapped to `LLMError`s without the response body, and the
  base URL always passed explicitly so `ANTHROPIC_BASE_URL` can't redirect a key. Replies cut
  off at the token limit, refused, or over the context window fail at once instead of paying
  for a corrective retry; an unreadable 2xx body is transient; a reply without usage is kept
  with usage marked unreported; failed calls log status, error type and request ID. A whole
  `complete()` call stops at `CALL_DEADLINE_SECONDS`, even against a server that trickles
  bytes, and the corrective retry gets only the time left. Passes the
  shared provider contract against a stubbed API, and an opt-in `llm_live` test against Meta's
  Anthropic-format endpoint (`tests/e2e/test_anthropic_live.py`). An import-linter contract keeps LLM SDK
  imports inside `ai/providers/`.
- LLM provider contract (#23, ADR 0019): `LLMProvider` protocol, result/usage types and
  `LLMError` subclasses in `domain/llm.py`; shared schema validation with one corrective retry
  (`ai/structured.py`); one HTTP-status error mapping (`ai/errors.py`); `resolve_llm_config`
  choosing the org's own key, else the capped instance key, else AI off (`ai/config.py`);
  shared SDK timeout/retry values and a total per-call deadline for adapters to enforce,
  sized to leave room under the Celery soft time limit (`ai/limits.py`); `FakeLLMProvider` and a contract test suite every provider adapter must
  pass; `llm_live` pytest marker for opt-in calls to a real provider, skipped unless
  `RUN_LLM_TESTS=1` and a key and model are set, and always in CI.
- ADR 0016: sandbox for code and binary analysis (per-job gVisor containers started by a
  credential-free launcher, no network, read-only input, resource limits) (#83).
- Ownership card on a domain's overview page (#14): shows the TXT record to publish with
  a copy button, its last check / verification / recheck times, and admin-only actions (start,
  verify now via HTMX, which queues a check without rotating the token, and rotate behind a
  confirm). The card polls itself while a check runs, so the outcome appears without a
  reload. Inventory shows a "Verified" badge on roots; `passive.verify_ownership` runs each
  check and an hourly beat entry re-queues due proofs.
- Ownership proof by DNS TXT (#14): `start_verification` issues (or rotates) a
  `_attacksurf-verify.<root>` token and queues a `passive.verify_ownership` job, an
  authoritative lookup records `verified`/`pending`/`revoked` with a day-long recheck window and
  a revoke grace, and `DbOwnershipChecker` makes ScopeGuard let active checks run only on a
  verified, unexpired root (subdomains inherit it). Roots added as subdomains are checked in
  their enclosing zone; failing nameservers are retried rather than read as a missing record.
  New `verifications` table (migrations 0005, 0006); `jobs.scan_id` is nullable so verification
  jobs no longer need a scan. See ADR 0014.
- Assets pages (#13): add a root domain from `/assets` (inline HTMX validation errors), browse
  assets with filters (type, root, tag, search, status) kept in the URL, and open an asset's
  detail page with its relations, findings and scan history tabs. Admins archive a root domain
  through a confirm dialog. New components: `confirm_dialog`, `select_field`, `relative_time`;
  `data_table` takes a call block for rich cells.
- ADR 0017: how repositories are fetched under ScopeGuard and how archives are extracted (#83).
- Root domains and asset browsing, service + JSON side (#13): `add_root_domain` validates names
  with the ScopeGuard rules (registrable or subdomain; no IPs, internal or bare-suffix names),
  `archive_root_domain` deactivates a root and everything discovered under it (admin only),
  both audited. `/api/v1/assets` lists assets (filters by type, root, tag, search, status;
  paginated; open-finding count and worst severity per asset) and serves detail with relations,
  findings and scan history.
- ADR 0018: the analysis tools, their licenses, and how their images are built and updated (#83).
- ScopeGuard and the scanner network boundary (ADR 0013): target validation against the bundled
  Public Suffix List (no internal names, single labels or IP literals), public-only resolved
  addresses (private, loopback, link-local/metadata, CGNAT, reserved, IPv6 equivalents), a frozen
  `ScannerGrant` per plugin enforced on every DNS lookup and HTTP request, an ownership check
  that keeps active checks denied until verification (#14), and a pinned HTTP client that
  applies the allowlist before the first request and at every redirect, ignores env proxies and
  caps time and body size. Scan profiles can cap discovered assets per root.
- Scanner plugin framework and scan pipeline (ADR 0011): validated `ScanOutput`, explicit
  registry/profiles, tenant-scoped start/finalize services, Celery discovery/check chords and
  continuation chain, atomic fingerprint/evidence persistence, bounded scanner budgets and
  isolated errors, and post-commit domain events. Diff/AI stages are seams for #20/#25.
  No network-enabled checks yet.
- Celery workers (ADR 0003): `passive` / `ai` queues routed by task-name prefix, `TrackedTask`
  base recording each task's lifecycle on its `Job` (attempts, retries with backoff for
  `TransientJobError`, time limits, redelivery-safe), `services.jobs.create_job` (commit, then
  enqueue), compose `worker-passive`, `worker-ai`, `beat`, and a real-worker check in CI
  (`make test-worker`)
- Scan results model (migration `0004`): `scans` and `jobs` (status, trigger, timings,
  stats), `findings` unique by `(org_id, fingerprint)` with severity, confidence, status
  lifecycle and AI triage slot, and `evidence`; stable versioned finding fingerprints and an
  in-code rule catalog (`domain.rules`)
- Asset model: `assets` (domain, subdomain, IP, URL; repo/binary reserved) with per-type value
  normalization (IDNA2008 punycode, canonical IPs, credential-free http(s) URLs with
  RFC 3986/3987 normalization) and `asset_relations` graph (migration `0003`); same-org links
  enforced by composite foreign keys; atomic upserts that update `last_seen` instead of
  duplicating; `deactivated_at` so delayed results can't reactivate an asset; user-added
  assets are roots, so deleting a parent only removes what was discovered under it
- Authentication: signup, login, logout (Flask-Login), login required everywhere by default,
  `@require_role`, CSRF on all POSTs incl. HTMX, rate-limited login/signup (Flask-Limiter),
  hardened session cookies, audit of login/logout/failed logins; settings `ALLOW_SIGNUP`,
  `SESSION_LIFETIME_HOURS`, `PROXY_COUNT`
- UI foundation: app shell (top bar, nav for Dashboard/Assets/Scans/Findings/Settings, light/dark
  theme toggle, AGPL source link), HTMX fragment rendering, Jinja component macros (button,
  severity badge, status pill, data table, pagination, empty state, flash), design tokens as CSS
  custom properties (placeholder values), vendored HTMX 2.0.11 + Alpine 3.17.4 (CSP build) with
  checksums, Lucide icons
- Security headers (strict CSP, frame/sniffing/referrer/permissions policies, HSTS in prod) and
  403/404/500 error pages (JSON under `/api/`)
- Accounts: `users`, `memberships` (roles owner/admin/member), `audit_log` tables and org
  `slug`/`plan` (migration `0002`); `register_user` service (user + personal org + owner
  membership + audit entry in one transaction); argon2id password hashing; `audit()` helper
- Database foundation: SQLAlchemy 2.0 base with constraint naming convention, UUIDv7 primary
  keys, `Timestamps` and `TenantScoped` (`org_id`) mixins, tenant-scoped query helpers,
  per-request sessions, Alembic migrations (`make migrate`, `make revision`), minimal `orgs`
  table; DB tests against PostgreSQL in CI and `make test`
- Docker: multi-stage `Dockerfile` (`dev` with hot reload, `prod` with gunicorn as non-root),
  `compose.yaml` dev stack (web, PostgreSQL, Redis, worker/beat placeholders), `Makefile`,
  CI `compose` smoke test
- Layered package layout (`web`, `services`, `domain`, `scanners`, `ai`, `infra`, `workers`) with
  import-linter contracts; app factory with `ui`, `health` (`/healthz`) and `api_v1` blueprints
- Typed settings (pydantic-settings, `.env.example`; prod requires a strong `SECRET_KEY`) and
  structured logging (structlog, incl. stdlib/library logs) with request IDs and secret redaction
- Project skeleton: Flask app factory, src layout, uv, ruff, pyright, pytest with 80% coverage gate
- Architecture docs, ADRs, security model
- AI-agent setup: AGENTS.md, CLAUDE.md, Claude Code skills, hooks, MCP servers
- Open-source community files: AGPL-3.0 license, contributing guide, code of conduct, security
  policy, issue/PR templates, funding
- `STATE.md` handoff file, `finish-task` skill + keep-in-sync rule, SessionStart/Stop hooks
- `DESIGN.md` web UI design system skeleton
- Issue/commit/PR conventions (`docs/conventions.md`), task and epic issue forms, label
  definitions, commit message template, `create-issue` skill
- Label sync workflow from `.github/labels.yml`
- Dependabot commit prefixes (`build(deps)`, `ci(deps)`); `pr-title` checks only the prefix on
  Dependabot PRs
- Git hooks via pre-commit (ruff, hygiene checks, gitleaks, Conventional Commits message check,
  pyright + pytest on push) and GitHub Actions CI (lint, tests on Python 3.12/3.13, PR-title check)
