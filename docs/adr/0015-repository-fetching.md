# 0015. Fetching repositories and handling archives under ScopeGuard

- Status: accepted
- Date: 2026-11-04

## Context
ADR 0014 gives the sandbox no network, so repository bytes must be fetched before analysis
starts. The code module needs public git URLs (#88), GitHub App repositories (#91), recent
history for secret scanning (#92) and archive uploads (#87). ADR 0013 says scanner traffic goes
through ScopeGuard and that nothing contacts an arbitrary target without ownership proof.

Three things stand in the way:
- The `git` binary does its own DNS and connects, so ScopeGuard can't pin its addresses or
  check its redirects. It also supports transports such as `ext::`, `file://` and `ssh://`.
- `SafeHttpClient` is GET-only, buffers in memory and caps bodies at 1 MiB (`MAX_BODY_BYTES`).
  Smart HTTP needs a POST and a streamed response. Raising that cap would weaken every scanner.
- Public-repo ownership is proved by a file inside the repository (#89), so the first fetch
  has to happen before proof exists.

## Decision
- **One fetch path: git smart HTTP, spoken in Python.** A dulwich `AbstractHttpGitClient`
  subclass implements `_http_request` on top of the safe client. The `git` binary is never run
  with network access. Public URLs and GitHub App repositories share this path.
- **The fetcher never parses repository content.** It handles HTTP and pkt-line framing, and
  dulwich's `pack_data` callback passes the pack on as opaque bytes. It doesn't index, unpack
  or check out anything, so hostile objects are first parsed inside the sandbox.
- **`worker-fetch` runs it:** a Celery worker on a new `fetch` queue (`fetch.repository`), with
  internet egress but no access to `sandbox-launcher`. `worker-analysis` needs no egress, and
  so no process can both reach the internet and start sandboxes. The worker holds DB/Redis
  credentials, the same exposure as `passive` workers, because it parses only framing and
  never runs a tool on the artifact.

### Network rules
- **Hosts are a fixed list in code:** `github.com` and `gitlab.com`, matched exactly, not by
  the subdomain match `hostname_allowed` uses for data services. Adding one is a reviewed code
  change, never a setting or user input. Keeping to known forges preserves ADR 0013's rule, so
  a user can't aim our traffic at any host they like. Self-hosted servers are out of scope.
- **A new gate entry point:** `ScopeGuard.check_fetch` handles `repo` assets. It isn't a scanner
  plugin, because it produces an artifact rather than `ScanOutput`. It still runs
  `check_public_hostname`, and every connection resolves through the guarded resolver and pins
  a public address. `ScopeGuard.check` keeps refusing `repo` assets, so scanners get no way in.
- **The URL is rebuilt, never passed through.** A repo asset is stored as
  `host/path` (no scheme, no credentials, no query or fragment), with path segments limited to
  a strict character set and `.`/`..` rejected. The fetcher builds only
  `https://<host>/<path>.git/info/refs?service=git-upload-pack` and
  `https://<host>/<path>.git/git-upload-pack`. Dulwich's `get_transport_and_path` is never
  called, as it would accept `ssh://`, `git://` and local paths.
- **A separate port for streaming.** `GitTransport` is handed only to the fetcher and allows
  those two requests. `ctx.runtime.http` stays GET-only with its 1 MiB cap.
- **No redirects:** any 3xx fails the fetch. A moved repository needs its URL updated, and an
  auth header can't follow a redirect anywhere.
- **Smart protocol only.** The transport fails on any `Content-Type` other than the expected
  `application/x-git-upload-pack-*`. Otherwise dulwich falls back to dumb HTTP, which fetches
  and parses objects inside the fetcher, breaking the rule above.
- **Identity encoding only.** The transport sends `Accept-Encoding: identity` and fails on any
  `Content-Encoding`, so nothing is decompressed in this process.
- **No URL-borne secrets.** GitHub App tokens (#91) go in an `Authorization` header set by the
  transport, for `github.com` only. They never appear in URLs, logs, `Job.error` or the sandbox.

### What is fetched
- The ref must appear in the server's advertisement, and it is matched by exact name. Only the
  advertised commit SHA is requested, and that SHA is recorded on the scan (#88).
- History is shallow: `REPO_HISTORY_DEPTH` commits, default 50, with a validated upper bound.
- Submodules aren't followed and LFS objects aren't downloaded: gitlinks and pointer files stay
  plain entries. No hooks or repository config can arrive, since neither is sent over the
  protocol, and the repository the sandbox builds uses a config we write.

| Limit | Default | On breach |
|---|---|---|
| Response body, whole fetch (`ARTIFACT_MAX_BYTES`, #85) | 256 MiB | fail, delete partial data |
| Ref advertisement, held in memory | 8 MiB | fail |
| Total fetch time (`REPO_FETCH_TIMEOUT`) | 180 s, below the 300 s task limit | fail, delete partial data |
| Stall between reads | 30 s | fail, delete partial data |

The bytes stream through artifact storage (#85), so only a complete fetch is recorded as an
`Artifact`. Scanners never see a truncated pack.

### Ownership before analysis
The fetch itself is allowed without proof because it only talks to an allowlisted forge. Proof
gates what happens next (#89): until it passes, the artifact goes only to a fixed verification
step in the sandbox, which reads `.attacksurf-verify`. If it fails, the artifact is deleted and
scan jobs are `skipped`. The worker compares the token, not the sandbox. A repository exploit
could fake that output, but planting the exploit already takes write access to the repository.

### Archives
- **Archives enter by upload only (#87).** There's no "fetch this archive URL" feature and no
  forge tarball path, so nothing else reaches the network.
- **Extraction happens inside the analyzer's sandbox (#86), never on the host.** It writes to
  `/scratch` before the tool starts, so ADR 0014's proxy policy (one read-only bind) doesn't
  change. The same rules apply when the fetched repository's tree is written out.
- **The extractor is its own loop over entries,** not `tar`, `unzip` or `extractall`, and it
  never creates links. Extraction filters have had bypasses, and this leaves no link to resolve.

| Entry or condition | Result |
|---|---|
| Symlink, hard link, device node, FIFO | skipped, with the reason in the manifest |
| Setuid, setgid or sticky bits | stripped; files are written `0600`, directories `0700` |
| Absolute path, `..`, NUL or invalid name, duplicate path | whole artifact rejected |
| Corrupt or truncated archive, differing zip local and central headers | whole artifact rejected |
| Nested archive | kept as a file, never unpacked recursively |
| Any cap exceeded, counted while writing, never from declared headers | whole artifact rejected |

Caps: 512 MiB total, 64 MiB per file, 100,000 files, path depth 32, and a compression ratio of
200:1 across the archive. The total stays well below the 1 GiB scratch because `tmpfs` pages
also count against the sandbox's 1 GiB memory limit.

A partial tree would read as "no findings", so caps fail the job rather than truncate it. Skips
are different: they're reported with the results, so a user can see what wasn't analysed.

### Rejected
- **Running `git clone` with restrictive flags:** flags narrow the protocols and hooks, but git
  still connects by itself, so pinning and redirect checks don't apply.
- **Forge tarballs:** they carry no history (#92), work per forge, and honor `export-ignore`, so
  a repository could hide files from analysis.
- **A per-job fetch container:** `sandbox-proxy` would have to allow networked containers, which
  removes its `--network=none` check. A credential-less fetch service was also rejected: it adds
  key and token hand-offs (#85, #91) and protects little in a process that parses no artifact
  content.
- **Fetching in `worker-analysis`:** the process that can start sandboxes would gain egress.

## Consequences
- Compose gains `worker-fetch`, and the `fetch` queue joins the known task prefixes. The new
  settings go in `.env.example`.
- New dependency for #88: `dulwich` (Apache-2.0 OR GPL-2.0-or-later, AGPL-compatible). Its
  `urllib3` dependency is installed but unused here, and nothing outside the transport may
  import it for fetching. Scanner modules stay under the raw-network import test.
- The transport overrides a dulwich extension hook, so upgrades must pass the recorded smart-HTTP
  fixtures (#88), which include a dumb-fallback refusal and a redirect refusal.
- A fetched repository needs a step that builds it from the pack inside the sandbox and turns
  it into the same tree layout as an archive. It must not use `git archive` with the
  repository's own attributes, for the same `export-ignore` reason.
- #85 encrypts artifacts at rest while ADR 0014 mounts a plain read-only directory. #84 and #85
  must decrypt for a run only, under the artifact root, and remove the plaintext afterwards.
- Known gaps, shown in the results: history beyond the depth, submodule contents, LFS objects
  and skipped links aren't analysed. Other forges and self-hosted servers need a new decision.
- Forge rate limits and large repositories can fail fetches. These are ordinary job failures;
  transient network errors raise `TransientJobError` (ADR 0010).
