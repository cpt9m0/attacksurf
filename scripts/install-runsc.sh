#!/usr/bin/env bash
# Install the pinned gVisor release (runsc) and register it with Docker, for the CI job that runs
# the sandbox under it (ADR 0016, 0018). It installs system binaries as root and restarts Docker,
# so it is meant for a throwaway CI runner, not a machine with containers you care about.
#
# To upgrade: pick a release at least two weeks old, set both constants and the publish date (the
# SHA-512 is in gvisor.tar.zstd.sha512 beside the tarball), and send the change through review.
#
# Usage: scripts/install-runsc.sh    (x86_64 Linux with Docker and sudo)
set -euo pipefail

# Tag release-20261109.0, published 2026-11-11.
GVISOR_RELEASE=20261109
GVISOR_SHA512=0a0041fd862f4ea3042a9db8d41c742f48a01f909699adc2a0256e46d85e53f97b82b9fd154b3dce636f62b8d557677639f91c77d13f3f875ff9fa535275393c
TARBALL=gvisor.tar.zstd
URL=https://storage.googleapis.com/gvisor/releases/release/$GVISOR_RELEASE/x86_64/$TARBALL
INSTALL_DIR=/usr/local/bin

die() {
  printf 'install-runsc: %s\n' "$*" >&2
  exit 1
}

arch=$(uname -m)
[ "$arch" = x86_64 ] || die "only x86_64 is pinned (this machine is $arch)"
for tool in curl sha512sum tar zstd sudo docker systemctl; do
  command -v "$tool" >/dev/null || die "missing tool: $tool"
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl --fail --silent --show-error --location --retry 3 --proto '=https' --tlsv1.2 \
  --output "$work/$TARBALL" "$URL"

# Checked against the pinned value, not a downloaded .sha512 file: whoever could replace the
# tarball could replace that too. Nothing is unpacked or installed before this passes.
printf '%s  %s\n' "$GVISOR_SHA512" "$work/$TARBALL" | sha512sum --check --strict --status ||
  die "checksum mismatch for $TARBALL: nothing was installed"

mkdir "$work/release"
tar --zstd --extract --file "$work/$TARBALL" --directory "$work/release"
# runsc looks for its sidecar binaries in gvisor-bin/ next to itself.
sudo install -m 0755 "$work/release/runsc" "$work/release/containerd-shim-runsc-v1" "$INSTALL_DIR/"
sudo cp -R "$work/release/gvisor-bin" "$INSTALL_DIR/"

version=$("$INSTALL_DIR/runsc" --version)
[[ $version == *"release-$GVISOR_RELEASE.0"* ]] || die "unexpected runsc version: $version"

# By default `runsc install` downloads any missing sidecar, outside the pinned checksum.
sudo "$INSTALL_DIR/runsc" install --download-sidecars=NEVER --require-sidecars=ALWAYS
sudo systemctl restart docker

runtimes=$(docker info --format '{{json .Runtimes}}')
[[ $runtimes == *'"runsc":'* ]] || die "Docker does not list the runsc runtime"
printf 'install-runsc: runsc release-%s.0 is registered with Docker\n' "$GVISOR_RELEASE"
