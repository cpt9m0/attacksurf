# 0034. Keep `/tmp` read-only in the analysis sandbox

- Status: accepted; amends the mounts in [0016](0016-analysis-sandbox.md)
- Date: 2026-11-26

## Context
ADR 0016 makes `/scratch` (a size-capped `tmpfs`, `noexec,nosuid,nodev`) the sandbox's only
writable path, with a read-only root. The create body said nothing about `/tmp`, on the
assumption that the read-only root covered it.

gVisor does not work that way. `runsc` (`runsc/boot/vfs.go`, `mountTmp`) mounts its own `tmpfs`
at `/tmp` when the image's `/tmp` is empty or missing and nothing is explicitly mounted there. It
does this whether or not the root is read-only, and its only option is `mode=01777`: writable,
with exec allowed. A tool taken over by a hostile artifact could write a program there and run it,
which `/scratch` is set up to prevent. The files would stay inside the sandbox and vanish with it.

This was found by reading gVisor's source (its main branch); it has not been reproduced with a
running `runsc`.

## Decision
- Every sandbox mounts a `tmpfs` at `/tmp` with exactly `ro,noexec,nosuid,nodev,size=4096`. An
  explicit mount stops `runsc` from adding its own; under `runc` the mount is read-only too.
- `sandbox-proxy` enforces it. A create request must have exactly two `tmpfs` mounts: `/scratch`
  (rules unchanged) and `/tmp` with that exact string. A missing, writable or reworded `/tmp`
  entry is refused, so a compromised launcher cannot reopen it.
- The launcher and the proxy each hold a copy of the string, since the launcher never imports the
  proxy; a test keeps them equal.

We rejected putting a file in each image's `/tmp`, which would also stop `runsc`'s mount: every
future analyzer image would have to remember it, and nothing at the gate could check it.

## Consequences
- Analyzers use `/scratch` for temporary files. Real analyzer images set `TMPDIR=/scratch`. A
  tool with `/tmp` hard-coded fails with a read-only error until it is configured otherwise; the
  fix is to configure the tool, not to reopen `/tmp`.
- The launcher and the proxy must be upgraded together: each refuses the other's old shape.
- This lock covers `/tmp` only. Docker also sets up kernel mounts under `/dev` (`/dev/shm` among
  them), which may be writable. The runtime tests must list every writable directory and check
  that none allows exec.
- That `runsc` honours the read-only mount is to be proven by the CI job that runs the sandbox
  under `runsc`.
