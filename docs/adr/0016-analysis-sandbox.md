# 0016. Sandbox for code and binary analysis

- Status: accepted
- Date: 2026-11-04

## Context
The code and binary modules (#67) will analyse artifacts an attacker can craft: repositories,
archives, ELF/PE/Mach-O files, APKs. The tools that read them (git, archive readers, LIEF,
androguard, SAST and dependency scanners) parse hostile formats, and parser bugs have led to
code execution before. Analysis can also be steered into exhausting CPU, memory, disk or
processes. ADR 0013's boundary is an import check for *trusted* plugin code running in-process,
not a sandbox. A malicious artifact must not reach the DB, Redis, the network or the host.

## Decision
- **Never execute the artifact.** Analysis is static only: no builds, installs, package
  scripts, `setup.py` or test runs. Tools run in modes that don't resolve or fetch anything.
- **Four roles, and none of them holds both parsing and privilege:**
  - `worker-analysis` (Celery, `analysis` queue): holds DB/Redis credentials, tracks the `Job`,
    and persists results. It never opens artifact bytes. It asks the launcher for a run
    identified by artifact ID and analyzer name, never by paths, images, args or mounts.
  - `sandbox-launcher`: a small internal service with no DB/Redis credentials and no broker
    access. It maps the analyzer name to an image digest from a fixed allowlist, resolves the
    artifact ID to its directory under the artifact root itself, applies the fixed flags
    below, and returns exit status plus capped stdout. It never holds the Docker socket.
  - `sandbox-proxy`: the **only** component that mounts the Docker socket, reachable only by
    the launcher on an internal network. It allows container create, start, wait, attach
    (stdout), kill and remove, and nothing else (no exec, images, volumes, networks, or other
    containers). It also validates every create request against the sandbox policy: image
    digest on the allowlist, `runsc` runtime (or the dev fallback), the flags and limits
    below, a single read-only bind under the artifact root, and no other mount except the
    OSV data volume for the osv-scanner image (tool-image follow-up, PR #130). A compromised launcher can
    therefore only start more sandboxes. Off-the-shelf proxies filter by API section only and
    can't check create bodies, so this is a small purpose-built service.
  - **Sandbox**: one fresh gVisor (`runsc`) container per job, started with `--rm` and never
    reused. Its environment contains only the image's own variables: no credentials, no
    Docker socket, no broker URL.
- **I/O contract:** the artifact is mounted read-only at `/input`; the root filesystem is
  read-only; `/scratch` is a size-capped `tmpfs` (`noexec,nosuid,nodev`) and the only writable
  path; the container runs with `--network=none` (loopback only). The osv-scanner analyzer
  alone also gets the OSV data volume read-only at `/data/osv`. The tool writes one JSON
  document to stdout. The launcher stops reading past the ADR 0011 output cap (2 MiB) and
  kills the run, so oversized output fails the job. stderr is drained and discarded because it
  can echo secrets the tool found; only exit status and byte counts are logged. The worker
  validates stdout as `ScanOutput` (ADR 0011 caps, including 64 KiB per evidence object) and
  treats it as untrusted downstream (templates, prompts).
- **Privileges:** fixed non-root UID, `--cap-drop=ALL`, `--security-opt no-new-privileges`,
  no devices, never `--privileged`, no host namespaces.
- **Limits:** every run gets them. Defaults are settings with validated upper bounds, tuned
  later:

  | Resource | Default | Enforced by |
  |---|---|---|
  | CPU | 1 core | `--cpus` |
  | Memory | 1 GiB, no swap | `--memory` = `--memory-swap` |
  | Processes | 256 | `--pids-limit` |
  | Wall time | 600 s | launcher kills and removes the container |
  | Scratch disk | 1 GiB | `tmpfs` size; `fsize` ulimit |
  | Open files | 1024 | `nofile` ulimit |

  Worker concurrency bounds how many sandboxes run at once, so the host keeps headroom for the
  web app and other workers. Unlike scanner thread timeouts (`security.md`), a timeout here
  really kills the work.
- **Dev/CI without `runsc`:** the launcher may use `runc` with the same flags only when
  `ENV != prod` and the runtime setting says so explicitly. In prod it refuses to start unless
  `runsc` is a registered Docker runtime. The runtime used is logged for each run. Unit tests
  replace the launcher with a fake (no Docker). A separate CI job installs `runsc` and runs a
  harmless fixture image to check the flags, limits and the no-network guarantee.
- **Out of scope here:** fetching artifacts over the network
  ([PR #129](https://github.com/cpt9m0/attacksurf/pull/129)) and the tool images and their
  licenses ([PR #130](https://github.com/cpt9m0/attacksurf/pull/130)).

### Rejected
- **Running the tools inside the Celery worker**, even under gVisor: a parser exploit would
  sit next to DB and Redis credentials.
- **Workers starting containers themselves:** the Docker socket is root on the host, and
  combining it with DB credentials and output parsing widens the blast radius of any worker
  bug.
- **Launcher holding the socket directly:** its own code would be the only check, so one
  launcher bug would mean control of the host.

## Consequences
- Compose gains `worker-analysis`, `sandbox-launcher` and `sandbox-proxy`. The VPS needs
  `runsc` registered in Docker's `daemon.json`. New settings for runtime, limits and artifact
  root go in `.env.example`.
- The `analysis` queue stays reserved until the worker, launcher, proxy and at least one
  analyzer exist.
- Each job pays container start-up and gVisor syscall overhead; that's acceptable for
  background analysis.
- `sandbox-proxy` is now the root-equivalent component. It must stay small, have its policy
  checks unit-tested (rejecting privileged, extra binds, the OSV volume on any other image,
  host namespaces, unknown images), and deny by default. Rootless Docker is a possible later
  hardening on top.
- Residual risk: a gVisor escape combined with a tool exploit. Fresh containers, no network
  and no secrets keep what such an escape could reach small.
