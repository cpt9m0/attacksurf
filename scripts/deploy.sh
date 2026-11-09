#!/usr/bin/env bash
# Deploy attacksurf to production from a fetched, clean checkout.
#
# This is the single entry point for pull-based CD: `attacksurf-deploy.timer` runs
# `attacksurf-deploy.service`, which runs this script as root, and humans run
# `sudo make deploy`. Mutually exclusive runs are guaranteed by the systemd unit's flock;
# do not add a second lock here (a nested flock on the same file would deadlock).
#
# Sequence:
#   1. bootstrap/refresh a git checkout in APP_DIR (/opt/attacksurf is a copied tree, not a
#      clone, so the first run turns it into a real checkout in place and keeps ignored files
#      such as deploy/attacksurf.env)
#   2. refuse to deploy from a dirty tree, from a commit that is not on origin/main, or from a
#      checkout that is stale relative to both origin/main and what production runs
#   3. checkout the target commit and build its images tagged with the short SHA
#   4. run the one-off `migrate` service, which uses the new code, before `web` is replaced
#   5. replace `web` (and only `web`: no `down`, no `-v`, so postgres/redis keep running with
#      their pgdata volume intact)
#   6. smoke-test /healthz through the ingress; on failure roll back to the previously
#      deployed SHA (rebuild + up -d --wait) and exit non-zero
#   7. record the deployed SHA in /var/lib/attacksurf/deployed-sha and log it to stdout/journal
#
# Usage: sudo scripts/deploy.sh [SHA]        (default: origin/main)
#
# Environment overrides (all optional):
#   APP_DIR        checkout to deploy from            /opt/attacksurf
#   REPO_URL       upstream repository                https://github.com/cpt9m0/attacksurf.git
#   BRANCH         branch that may be deployed        main
#   COMPOSE_FILE   production compose file            compose.prod.yaml
#   STATE_DIR      deployed-SHA bookkeeping           /var/lib/attacksurf
#   HEALTH_ATTEMPTS / HEALTH_DELAY   smoke-test retries and pause in seconds (15 / 2)
set -eEuo pipefail

APP_DIR=${APP_DIR:-/opt/attacksurf}
REPO_URL=${REPO_URL:-https://github.com/cpt9m0/attacksurf.git}
BRANCH=${BRANCH:-main}
COMPOSE_FILE=${COMPOSE_FILE:-compose.prod.yaml}
STATE_DIR=${STATE_DIR:-/var/lib/attacksurf}
DEPLOYED_SHA_FILE=$STATE_DIR/deployed-sha
HEALTH_ATTEMPTS=${HEALTH_ATTEMPTS:-15}
HEALTH_DELAY=${HEALTH_DELAY:-2}

# Long-running services. `migrate` is deliberately absent: it is a one-off that runs before
# `web` is replaced, and `up -d` must never start it as a background service.
SERVICES=(web caddy cloudflared postgres redis)

case "$COMPOSE_FILE" in
  /*) COMPOSE_PATH=$COMPOSE_FILE ;;
  *) COMPOSE_PATH=$APP_DIR/$COMPOSE_FILE ;;
esac

log() { printf '[deploy] %s\n' "$*"; }
die() {
  printf '[deploy] ERROR: %s\n' "$*" >&2
  exit 1
}

git_() { git -C "$APP_DIR" "$@"; }
compose() { docker compose --project-directory "$APP_DIR" -f "$COMPOSE_PATH" "$@"; }

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^set -euo/d'
}

# --- preconditions -----------------------------------------------------------

require_root() {
  [ "$(id -u)" -eq 0 ] || die "must run as root (sudo make deploy): it reads /etc/attacksurf and drives docker"
}

require_docker() {
  command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
  docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not available"
}

# --- repository state --------------------------------------------------------

# /opt/attacksurf is a copied tree without .git, so a deploy has to create the checkout
# itself. `git init` + fetch + `checkout -f` converges the tree in place: tracked files that
# drifted are overwritten, ignored files (deploy/attacksurf.env) and untracked files are left
# alone. Nothing is ever cleaned, so a local file can never be deleted by a deploy.
prepare_repo() {
  if [ ! -d "$APP_DIR/.git" ]; then
    log "no git checkout in $APP_DIR; initializing one (first run)"
    mkdir -p "$APP_DIR"
    git init --quiet "$APP_DIR"
  fi

  local url
  if url=$(git_ remote get-url origin 2>/dev/null); then
    [ "$url" = "$REPO_URL" ] || { log "origin was $url; switching to $REPO_URL"; git_ remote set-url origin "$REPO_URL"; }
  else
    git_ remote add origin "$REPO_URL"
  fi

  log "fetching origin/$BRANCH"
  git_ fetch --quiet --prune origin "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH"
}

# Resolve the commit to deploy and refuse anything that is not merged into the deploy branch.
resolve_target() {
  local requested=${1:-} target
  if [ -n "$requested" ]; then
    target=$(git_ rev-parse --verify --quiet "$requested^{commit}") ||
      die "cannot resolve '$requested' to a commit in $APP_DIR"
  else
    target=$(git_ rev-parse --verify "refs/remotes/origin/$BRANCH^{commit}")
  fi
  git_ merge-base --is-ancestor "$target" "origin/$BRANCH" ||
    die "commit $target is not on origin/$BRANCH; only merged commits can be deployed"
  printf '%s' "$target"
}

# A deploy never discards work: a dirty tracked tree, local commits, or a checkout that is
# stale relative to what production runs are all refused. HEAD being behind origin/main is the
# *normal* state between two timer runs (the deploy itself moves it forward), so that alone is
# not an error. It is one when the checkout is strictly older than the deployed commit — the
# case where someone left the tree on an old commit — or when nothing is deployed yet and the
# checkout is not the tip.
check_checkout() {
  local head_sha=$1 main_sha=$2 deployed=$3
  [ -n "$head_sha" ] || return 0

  if [ -n "$(git_ status --porcelain --untracked-files=no)" ]; then
    git_ status --short --untracked-files=no >&2
    die "working tree in $APP_DIR is dirty; commit, stash or discard the changes first"
  fi

  git_ merge-base --is-ancestor "$head_sha" "$main_sha" ||
    die "HEAD ($head_sha) has commits that are not on origin/$BRANCH; refusing to discard them"

  [ "$head_sha" = "$main_sha" ] && return 0
  [ "$head_sha" = "$deployed" ] && return 0

  if [ -z "$deployed" ]; then
    die "HEAD ($head_sha) is behind origin/$BRANCH ($main_sha) and no deploy is recorded; refusing to deploy from a stale checkout"
  fi
  if git_ merge-base --is-ancestor "$head_sha" "$deployed"; then
    die "HEAD ($head_sha) is older than the deployed commit ($deployed); refusing to deploy from a stale checkout"
  fi
  # Newer than what prod runs but not the tip: an interrupted earlier deploy. The checkout
  # below fixes it, so this is not a reason to refuse.
  log "note: HEAD ($head_sha) is not the tip; moving to $main_sha"
}

# --- deployment steps --------------------------------------------------------

smoke() {
  local attempt
  for ((attempt = 1; attempt <= HEALTH_ATTEMPTS; attempt++)); do
    # Through Caddy, not loopback: this also proves the ingress can still reach the new web.
    if compose exec -T caddy wget -q -T 5 -O /dev/null "http://web:5000/healthz" 2>/dev/null; then
      log "smoke test passed (/healthz via caddy, attempt $attempt)"
      return 0
    fi
    sleep "$HEALTH_DELAY"
  done
  log "smoke test FAILED: /healthz was not reachable through caddy after $HEALTH_ATTEMPTS attempts"
  return 1
}

# Restore the previous version: rebuild the recorded SHA and put it back. Without a recorded
# SHA (the first CD deploy) fall back to the image the running container used, so the very
# first deploy is not a one-way door. Migrations are not reversed: schema changes are
# forward-only, and the previous code is expected to run against a migrated database.
rollback() {
  local reason=$1 prev_sha=$2 prev_image=$3 prev_short

  log "ROLLBACK: $reason"

  if [ -n "$prev_sha" ]; then
    prev_short=$(git_ rev-parse --short=12 "$prev_sha") || {
      log "CRITICAL: cannot resolve previous SHA $prev_sha; manual intervention required"
      return 1
    }
    log "rebuilding $prev_sha ($prev_short)"
    git_ checkout --quiet --force --detach "$prev_sha" || {
      log "CRITICAL: cannot check out $prev_sha; manual intervention required"
      return 1
    }
    export WEB_IMAGE="attacksurf-web:$prev_short"
    compose build web || {
      log "CRITICAL: rebuild of $prev_sha failed; manual intervention required"
      return 1
    }
  elif [ -n "$prev_image" ] && docker image inspect "$prev_image" >/dev/null 2>&1; then
    log "no previous SHA recorded; restoring the pre-deploy image $prev_image"
    export WEB_IMAGE="$prev_image"
  else
    log "CRITICAL: no rollback target (no recorded SHA, no pre-deploy image); prod may be broken"
    return 1
  fi

  if ! compose up -d --wait "${SERVICES[@]}"; then
    log "CRITICAL: rollback to $WEB_IMAGE did not come up; manual intervention required"
    return 1
  fi

  if smoke; then
    log "rollback complete: $WEB_IMAGE is live again"
    return 0
  fi

  log "CRITICAL: rollback target $WEB_IMAGE also fails /healthz; manual intervention required"
  return 1
}

write_deployed_sha() {
  install -d -m 0755 "$STATE_DIR"
  printf '%s\n' "$1" >"$DEPLOYED_SHA_FILE.tmp"
  chmod 0644 "$DEPLOYED_SHA_FILE.tmp"
  mv -f "$DEPLOYED_SHA_FILE.tmp" "$DEPLOYED_SHA_FILE"
}

# --- main --------------------------------------------------------------------

main() {
  case "${1:-}" in
    -h | --help)
      usage
      exit 0
      ;;
  esac
  [ $# -le 1 ] || die "usage: deploy.sh [SHA]"

  require_root
  require_docker

  prepare_repo

  local main_sha target target_short deployed prev_sha prev_image web_container web_image="" web_running=""
  main_sha=$(git_ rev-parse --verify "refs/remotes/origin/$BRANCH^{commit}")
  target=$(resolve_target "${1:-}")
  target_short=$(git_ rev-parse --short=12 "$target")
  export WEB_IMAGE="attacksurf-web:$target_short"

  deployed=$(cat "$DEPLOYED_SHA_FILE" 2>/dev/null || true)
  web_container=$(compose ps -q web 2>/dev/null | head -n1 || true)
  if [ -n "$web_container" ]; then
    prev_image=$(docker inspect --format '{{.Config.Image}}' "$web_container" 2>/dev/null || true)
    web_image=$prev_image
    web_running=$(docker inspect --format '{{.State.Running}}' "$web_container" 2>/dev/null || true)
  fi
  prev_sha=$deployed

  check_checkout "$(git_ rev-parse --verify HEAD 2>/dev/null || true)" "$main_sha" "$deployed"

  # Idempotent: the target is what prod already runs, so there is nothing to build or replace.
  if [ "$target" = "$deployed" ] && [ "$web_image" = "$WEB_IMAGE" ] && [ "$web_running" = true ]; then
    log "already deployed: $target ($WEB_IMAGE) is live; nothing to do"
    exit 0
  fi

  log "deploying $target ($target_short), previously ${prev_sha:-none}"

  git_ checkout --quiet --force --detach "$target"
  [ "$(git_ rev-parse HEAD)" = "$target" ] || die "checkout did not land on $target"

  local untracked
  untracked=$(git_ ls-files --others --exclude-standard | tr '\n' ' ')
  [ -z "$untracked" ] || log "note: untracked files left in place: $untracked"

  [ -e "$APP_DIR/deploy/attacksurf.env" ] ||
    die "$APP_DIR/deploy/attacksurf.env is missing; it must be a symlink into /etc/attacksurf"
  compose config --quiet || die "$COMPOSE_PATH is not a valid compose file"

  log "building $WEB_IMAGE"
  compose build web
  # The Caddyfile is baked into its image, so a deploy that changes it has to rebuild Caddy.
  # Docker's cache makes this a no-op when nothing changed, and Compose then leaves the
  # running caddy container alone.
  compose build caddy

  # Migrate first, with the new code, while the old web is still serving. A failure here has
  # not touched web at all, so the previous version simply keeps running.
  log "running migrations (one-off migrate service)"
  if ! compose run --rm -T migrate; then
    log "ERROR: migration failed; web was not replaced, ${deployed:-the previous version} is still live"
    # Leave the checkout on what prod runs, so the next attempt starts from a known state.
    if [ -n "$prev_sha" ]; then
      git_ checkout --quiet --force --detach "$prev_sha" || log "WARNING: could not restore $prev_sha in $APP_DIR"
    fi
    exit 1
  fi

  log "replacing web"
  if ! compose up -d --wait "${SERVICES[@]}"; then
    rollback "compose up -d --wait failed" "$prev_sha" "$prev_image" || true
    exit 1
  fi

  if ! smoke; then
    rollback "post-deploy smoke test failed" "$prev_sha" "$prev_image" || true
    exit 1
  fi

  write_deployed_sha "$target"
  log "deployed $target ($WEB_IMAGE) — recorded in $DEPLOYED_SHA_FILE"
}

# Unexpected failures (set -e) would otherwise leave only the failing command's own message in
# the journal; this names the line so the systemd log is actionable.
trap 'log "ERROR: deploy failed at line $LINENO"' ERR

main "$@"
