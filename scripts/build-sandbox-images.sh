#!/usr/bin/env bash
# Build the sandbox analyzer images locally or in CI (ADR 0016, 0018).
#
# Every directory under sandbox/images/ holding a Dockerfile is one image. Each is built with plain
# `docker build` and tagged attacksurf-sandbox-<name>:ci. The tag is only a handle: the sandbox
# proxy accepts the bare image ID, so nothing is pushed and no registry is needed.
#
# Usage: scripts/build-sandbox-images.sh [name ...]    (no names: build every image)
#
# Output: one "<name> <image id>" line per image on stdout; Docker's build output goes to stderr.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

IMAGES_DIR=sandbox/images
TAG_PREFIX=attacksurf-sandbox-

die() {
  printf 'build-sandbox-images: %s\n' "$*" >&2
  exit 1
}

available=()
for dockerfile in "$IMAGES_DIR"/*/Dockerfile; do
  [ -f "$dockerfile" ] || continue
  dir=${dockerfile%/Dockerfile}
  available+=("${dir##*/}")
done
[ "${#available[@]}" -gt 0 ] || die "no images under $IMAGES_DIR"

if [ "$#" -gt 0 ]; then
  names=("$@")
else
  names=("${available[@]}")
fi

# Check every name before building anything, so a typo fails fast and builds nothing.
for name in "${names[@]}"; do
  found=
  for candidate in "${available[@]}"; do
    [ "$candidate" = "$name" ] && found=1
  done
  [ -n "$found" ] || die "unknown image: $name (available: ${available[*]})"
done

for name in "${names[@]}"; do
  tag=$TAG_PREFIX$name:ci
  docker build --tag "$tag" "$IMAGES_DIR/$name" >&2
  image_id=$(docker image inspect --format '{{.Id}}' "$tag")
  # A different shape (say a tag or a name) would be refused later by the proxy policy.
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "unexpected image ID for $name"
  printf '%s %s\n' "$name" "$image_id"
done
