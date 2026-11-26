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
- This lock covers `/tmp` only, so `/scratch` is not literally the only writable path. The
  runtime tests (`tests/integration/sandbox/`) search the whole filesystem from inside the
  sandbox. Under `runc`, two kernel mounts that Docker adds are also writable, `/dev/shm` and
  `/dev/mqueue`; neither allows exec. The tests fail on any other writable directory, or on one
  that runs files.

## Results under `runsc`
CI's `sandbox (runsc)` job passed on 2026-11-26 at commit `8c408e4`
([run](https://github.com/cpt9m0/attacksurf/actions/runs/45776869301)): `runsc`
`release-20261109.0` on an `ubuntu-26.04` runner, with the `runc` fallback off. 14 tests passed.
The one skipped there, that a prod launcher refuses to start without `runsc`, passed in its own
step before `runsc` was installed.

- **`runsc` honours the read-only `/tmp`.** The probe searched the filesystem, apart from `/proc`
  and `/sys`, without being cut short. No directory outside `/scratch`, `/dev/shm` and
  `/dev/mqueue` accepted a file, so `/tmp` did not, and no writable directory ran one. The
  fixture image's `/tmp` is empty (checked on a local build), one of the cases where `runsc`
  would add its own mount.
- `/scratch` was writable and did not allow exec. The test accepts `/dev/shm` and `/dev/mqueue`
  but doesn't require them, and the log doesn't show which of them `runsc` made writable.
- Still not reproduced: that `runsc` adds a writable `/tmp` when the explicit mount is missing.
  No test removes the mount, since the proxy refuses that request.
