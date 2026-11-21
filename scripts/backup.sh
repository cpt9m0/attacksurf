#!/usr/bin/env bash
# Nightly off-box PostgreSQL backup to S3-compatible object storage via rclone (issue #29).
#
# Sequence:
#   1. validate root execution, required tools, and strict 0600 permissions on BACKUP_ENV_FILE
#   2. stream `pg_dump --format=custom` from the running postgres container into a private temp dir
#   3. verify the dump archive structure with `pg_restore --list` inside the postgres container
#   4. optionally encrypt with `age -r "$BACKUP_AGE_RECIPIENT"` (dropping plaintext immediately)
#   5. write a SHA-256 sidecar and upload both files with `rclone copyto`
#   6. prune remote backups older than BACKUP_RETENTION_DAYS only after the upload succeeds
#
# Usage: sudo scripts/backup.sh
#
# Optional environment overrides:
#   APP_DIR         checkout root                         /opt/attacksurf
#   COMPOSE_FILE    production compose file               compose.prod.yaml
#   BACKUP_ENV_FILE root-only env file with rclone creds  /etc/attacksurf/backup.env
set -eEuo pipefail

APP_DIR=${APP_DIR:-/opt/attacksurf}
COMPOSE_FILE=${COMPOSE_FILE:-compose.prod.yaml}
BACKUP_ENV_FILE=${BACKUP_ENV_FILE:-/etc/attacksurf/backup.env}

case "$COMPOSE_FILE" in
  /*) COMPOSE_PATH=$COMPOSE_FILE ;;
  *) COMPOSE_PATH=$APP_DIR/$COMPOSE_FILE ;;
esac

log() { printf '[backup] %s\n' "$*"; }
die() {
  printf '[backup] ERROR: %s\n' "$*" >&2
  exit 1
}

compose() { docker compose --project-directory "$APP_DIR" -f "$COMPOSE_PATH" "$@"; }

WORK_DIR=""
cleanup() {
  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT
trap 'log "ERROR: backup failed at line $LINENO"' ERR

require_private_env_file() {
  [ -f "$BACKUP_ENV_FILE" ] || die "$BACKUP_ENV_FILE not found; copy deploy/backup.env.example and chmod 600"
  local perm
  perm=$(stat -c '%a' "$BACKUP_ENV_FILE" 2>/dev/null || stat -f '%Lp' "$BACKUP_ENV_FILE")
  case "$perm" in
    400 | 600) ;;
    *) die "$BACKUP_ENV_FILE must have mode 0600 or 0400 (got $perm)" ;;
  esac
}

main() {
  [ $# -eq 0 ] || die "usage: backup.sh"
  [ "$(id -u)" -eq 0 ] || die "must run as root (reads $BACKUP_ENV_FILE and drives docker)"
  command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
  docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not available"
  command -v rclone >/dev/null 2>&1 || die "rclone not found in PATH"
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found in PATH"

  require_private_env_file

  set -a
  # shellcheck source=/dev/null
  . "$BACKUP_ENV_FILE"
  set +a

  local remote_path=${BACKUP_REMOTE_PATH:-}
  local retention_days=${BACKUP_RETENTION_DAYS:-30}
  local age_recipient=${BACKUP_AGE_RECIPIENT:-}

  [ -n "$remote_path" ] || die "BACKUP_REMOTE_PATH must be set in $BACKUP_ENV_FILE"
  [[ "$retention_days" =~ ^[1-9][0-9]*$ ]] || die "BACKUP_RETENTION_DAYS must be a positive integer"

  if [ -n "$age_recipient" ]; then
    command -v age >/dev/null 2>&1 || die "age not found in PATH (required by BACKUP_AGE_RECIPIENT)"
  fi

  local started_at timestamp raw_dump final_name final_dump remote_base size_bytes elapsed
  started_at=$(date +%s)
  timestamp=$(date -u +%Y%m%dT%H%M%SZ)

  WORK_DIR=$(mktemp -d)
  chmod 700 "$WORK_DIR"

  raw_dump="$WORK_DIR/attacksurf-$timestamp.dump"
  log "dumping postgres database"
  compose exec -T postgres pg_dump -U attacksurf -d attacksurf \
    --format=custom --no-owner --no-acl >"$raw_dump"

  [ -s "$raw_dump" ] || die "pg_dump produced an empty file"

  log "verifying dump table of contents"
  compose exec -T postgres pg_restore --list <"$raw_dump" >/dev/null

  if [ -n "$age_recipient" ]; then
    final_name="attacksurf-$timestamp.dump.age"
    final_dump="$WORK_DIR/$final_name"
    log "encrypting dump with age"
    age -r "$age_recipient" -o "$final_dump" "$raw_dump"
    rm -f "$raw_dump"
  else
    final_name="attacksurf-$timestamp.dump"
    final_dump="$raw_dump"
  fi

  (cd "$WORK_DIR" && sha256sum "$final_name" >"$final_name.sha256")
  size_bytes=$(wc -c <"$final_dump" | tr -d '[:space:]')

  remote_base=${remote_path%/}
  log "uploading $final_name ($size_bytes bytes) to $remote_base"
  rclone copyto "$final_dump" "$remote_base/$final_name"
  rclone copyto "$final_dump.sha256" "$remote_base/$final_name.sha256"

  log "pruning remote backups older than ${retention_days}d"
  rclone delete --min-age "${retention_days}d" "$remote_base"

  elapsed=$(($(date +%s) - started_at))
  log "backup complete: $remote_base/$final_name ($size_bytes bytes, ${elapsed}s)"
}

main "$@"
