#!/usr/bin/env bash
# Restore or non-destructively verify an off-box PostgreSQL backup (issue #29).
#
# Modes:
#   --verify-only <backup>   Restore into a temporary database `attacksurf_restore_verify`,
#                            check schema/table row counts, and drop the temporary DB.
#   --live <backup> --i-understand-this-replaces-prod
#                            Preserve the deployed WEB_IMAGE, stop app/workers, take a safety
#                            dump, restore into a clean staging DB, swap it into `attacksurf`,
#                            run migrations, restart services, and check /healthz.
#
# <backup> may be a local file path or a filename/object under BACKUP_REMOTE_PATH.
# Encrypted `.age` backups require BACKUP_AGE_IDENTITY=/path/to/age.key (or in backup.env).
set -eEuo pipefail

APP_DIR=${APP_DIR:-/opt/attacksurf}
COMPOSE_FILE=${COMPOSE_FILE:-compose.prod.yaml}
BACKUP_ENV_FILE=${BACKUP_ENV_FILE:-/etc/attacksurf/backup.env}
VERIFY_DB=${VERIFY_DB:-attacksurf_restore_verify}
STAGE_DB=${STAGE_DB:-attacksurf_restore_stage}
STATE_DIR=${STATE_DIR:-/var/lib/attacksurf}
DEPLOY_LOCK_FILE=${DEPLOY_LOCK_FILE:-/var/lock/attacksurf-deploy.lock}

case "$COMPOSE_FILE" in
  /*) COMPOSE_PATH=$COMPOSE_FILE ;;
  *) COMPOSE_PATH=$APP_DIR/$COMPOSE_FILE ;;
esac

log() { printf '[restore] %s\n' "$*"; }
die() {
  printf '[restore] ERROR: %s\n' "$*" >&2
  exit 1
}

compose() { docker compose --project-directory "$APP_DIR" -f "$COMPOSE_PATH" "$@"; }

WORK_DIR=""
PREPARED_DUMP=""
VERIFY_DB_CREATED=0
STAGE_DB_CREATED=0
cleanup() {
  if [ "$VERIFY_DB_CREATED" -eq 1 ]; then
    compose exec -T postgres psql -U attacksurf -d postgres -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS \"$VERIFY_DB\";" >/dev/null 2>&1 || true
  fi
  if [ "$STAGE_DB_CREATED" -eq 1 ]; then
    compose exec -T postgres psql -U attacksurf -d postgres -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS \"$STAGE_DB\";" >/dev/null 2>&1 || true
  fi
  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT
trap 'log "ERROR: restore failed at line $LINENO"' ERR

usage() {
  cat <<'EOF'
Usage:
  sudo scripts/restore.sh --verify-only <local-path-or-remote-filename>
  sudo scripts/restore.sh --live <local-path-or-remote-filename> --i-understand-this-replaces-prod
EOF
}

load_backup_env_if_present() {
  if [ -f "$BACKUP_ENV_FILE" ]; then
    local perm
    perm=$(stat -c '%a' "$BACKUP_ENV_FILE" 2>/dev/null || stat -f '%Lp' "$BACKUP_ENV_FILE")
    case "$perm" in
      400 | 600) ;;
      *) die "$BACKUP_ENV_FILE must have mode 0600 or 0400 (got $perm)" ;;
    esac
    set -a
    # shellcheck source=/dev/null
    . "$BACKUP_ENV_FILE"
    set +a
  fi
}

fetch_and_prepare_dump() {
  local ref=$1
  local target_name local_file checksum_file plain_dump

  if [ -f "$ref" ]; then
    target_name=$(basename "$ref")
    local_file="$WORK_DIR/$target_name"
    cp "$ref" "$local_file"
    if [ -f "$ref.sha256" ]; then
      cp "$ref.sha256" "$local_file.sha256"
    fi
  else
    command -v rclone >/dev/null 2>&1 || die "rclone not found in PATH"
    local remote_base=${BACKUP_REMOTE_PATH:-}
    [ -n "$remote_base" ] || die "BACKUP_REMOTE_PATH must be set in $BACKUP_ENV_FILE to fetch remote backups"
    remote_base=${remote_base%/}
    target_name=$(basename "$ref")
    local_file="$WORK_DIR/$target_name"
    log "downloading $remote_base/$target_name"
    rclone copyto "$remote_base/$target_name" "$local_file"
    rclone copyto "$remote_base/$target_name.sha256" "$local_file.sha256" >/dev/null 2>&1 || true
  fi

  [ -s "$local_file" ] || die "backup file $target_name is empty"

  checksum_file="$local_file.sha256"
  if [ -f "$checksum_file" ]; then
    command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found in PATH"
    log "verifying sha256 checksum"
    (cd "$WORK_DIR" && sha256sum -c "$target_name.sha256")
  else
    log "note: no .sha256 sidecar found; continuing with pg_restore validation"
  fi

  if [[ "$target_name" == *.age ]]; then
    command -v age >/dev/null 2>&1 || die "age not found in PATH (required for .age backups)"
    local identity=${BACKUP_AGE_IDENTITY:-}
    [ -n "$identity" ] && [ -f "$identity" ] ||
      die "BACKUP_AGE_IDENTITY must point to the age identity file to decrypt $target_name"
    plain_dump="$WORK_DIR/${target_name%.age}"
    log "decrypting $target_name"
    age -d -i "$identity" -o "$plain_dump" "$local_file"
  else
    plain_dump="$local_file"
  fi

  compose exec -T postgres pg_restore --list <"$plain_dump" >/dev/null
  PREPARED_DUMP="$plain_dump"
}

check_restored_db() {
  local db_name=$1
  log "checking alembic_version and core table counts in $db_name"
  compose exec -T postgres psql -U attacksurf -d "$db_name" -v ON_ERROR_STOP=1 -At -c "
    SELECT 'alembic_version=' || COALESCE((SELECT version_num FROM alembic_version LIMIT 1), 'missing');
    SELECT 'orgs=' || count(*) FROM orgs;
    SELECT 'users=' || count(*) FROM users;
    SELECT 'assets=' || count(*) FROM assets;
    SELECT 'scans=' || count(*) FROM scans;
    SELECT 'findings=' || count(*) FROM findings;
  "
}

verify_restore() {
  local plain_dump=$1
  [[ "$VERIFY_DB" =~ ^[A-Za-z0-9_]+$ ]] || die "invalid VERIFY_DB name: $VERIFY_DB"

  log "creating throwaway database $VERIFY_DB"
  compose exec -T postgres psql -U attacksurf -d postgres -v ON_ERROR_STOP=1 \
    -c "DROP DATABASE IF EXISTS \"$VERIFY_DB\";" >/dev/null
  compose exec -T postgres psql -U attacksurf -d postgres -v ON_ERROR_STOP=1 \
    -c "CREATE DATABASE \"$VERIFY_DB\" OWNER attacksurf;" >/dev/null
  VERIFY_DB_CREATED=1

  log "restoring backup into $VERIFY_DB"
  compose exec -T postgres pg_restore -U attacksurf -d "$VERIFY_DB" \
    --no-owner --no-acl --exit-on-error <"$plain_dump"

  check_restored_db "$VERIFY_DB"
  log "restore verification passed ($VERIFY_DB will be dropped on exit)"
}

resolve_live_web_image() {
  local deployed_sha short_sha web_container live_image
  deployed_sha=$(cat "$STATE_DIR/deployed-sha" 2>/dev/null || true)
  if [ -z "${SENTRY_RELEASE:-}" ] && [ -n "$deployed_sha" ]; then
    export SENTRY_RELEASE
    SENTRY_RELEASE=$(printf '%s' "$deployed_sha" | cut -c1-12)
  fi
  if [ -n "${WEB_IMAGE:-}" ]; then
    return 0
  fi
  web_container=$(compose ps -q web 2>/dev/null | head -n1 || true)
  if [ -n "$web_container" ]; then
    live_image=$(docker inspect --format '{{.Config.Image}}' "$web_container" 2>/dev/null || true)
    if [ -n "$live_image" ]; then
      export WEB_IMAGE="$live_image"
      return 0
    fi
  fi
  if [ -n "$deployed_sha" ]; then
    short_sha=$(printf '%s' "$deployed_sha" | cut -c1-12)
    export WEB_IMAGE="attacksurf-web:$short_sha"
  fi
}

acquire_deploy_lock() {
  command -v flock >/dev/null 2>&1 || die "flock not found in PATH"
  mkdir -p "$(dirname "$DEPLOY_LOCK_FILE")"
  log "acquiring deploy lock $DEPLOY_LOCK_FILE"
  exec 9>"$DEPLOY_LOCK_FILE"
  flock --timeout 300 9 ||
    die "could not acquire deploy lock $DEPLOY_LOCK_FILE (a deploy may be running)"
}

reconcile_restored_db() {
  local db_name=$1
  log "cancelling unfinished scans and jobs from backup snapshot in $db_name"
  compose exec -T postgres psql -U attacksurf -d "$db_name" -v ON_ERROR_STOP=1 -c "
    UPDATE scans
       SET status = 'cancelled',
           started_at = COALESCE(started_at, clock_timestamp()),
           finished_at = GREATEST(COALESCE(started_at, clock_timestamp()), clock_timestamp()),
           updated_at = clock_timestamp()
     WHERE status IN ('queued', 'running');
    UPDATE jobs
       SET status = 'cancelled',
           error = 'Cancelled by database restore.',
           finished_at = GREATEST(COALESCE(started_at, clock_timestamp()), clock_timestamp()),
           updated_at = clock_timestamp()
     WHERE status IN ('queued', 'running');
  " >/dev/null
}

live_restore() {
  local plain_dump=$1
  local safety_dump="$STATE_DIR/pre-restore-$(date -u +%Y%m%dT%H%M%SZ).dump"

  [[ "$STAGE_DB" =~ ^[A-Za-z0-9_]+$ ]] || die "invalid STAGE_DB name: $STAGE_DB"

  acquire_deploy_lock
  resolve_live_web_image
  log "preserving image ${WEB_IMAGE:-attacksurf:prod} across recovery"

  log "stopping application services before live restore"
  compose stop web worker-passive worker-active worker-ai beat

  install -d -m 0700 "$STATE_DIR"
  log "taking pre-restore safety dump at $safety_dump"
  compose exec -T postgres pg_dump -U attacksurf -d attacksurf \
    --format=custom --no-owner --no-acl >"$safety_dump"
  chmod 0600 "$safety_dump"

  log "restoring backup into clean staging database $STAGE_DB"
  compose exec -T postgres psql -U attacksurf -d postgres -v ON_ERROR_STOP=1 \
    -c "DROP DATABASE IF EXISTS \"$STAGE_DB\";" >/dev/null
  compose exec -T postgres psql -U attacksurf -d postgres -v ON_ERROR_STOP=1 \
    -c "CREATE DATABASE \"$STAGE_DB\" OWNER attacksurf;" >/dev/null
  STAGE_DB_CREATED=1

  compose exec -T postgres pg_restore -U attacksurf -d "$STAGE_DB" \
    --no-owner --no-acl --exit-on-error <"$plain_dump"
  check_restored_db "$STAGE_DB"

  log "swapping staged database $STAGE_DB into attacksurf"
  compose exec -T postgres psql -U attacksurf -d postgres -v ON_ERROR_STOP=1 \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'attacksurf' AND pid <> pg_backend_pid();" >/dev/null
  compose exec -T postgres psql -U attacksurf -d postgres -v ON_ERROR_STOP=1 \
    -c "DROP DATABASE IF EXISTS attacksurf;" >/dev/null
  compose exec -T postgres psql -U attacksurf -d postgres -v ON_ERROR_STOP=1 \
    -c "ALTER DATABASE \"$STAGE_DB\" RENAME TO attacksurf;" >/dev/null
  STAGE_DB_CREATED=0

  log "running forward migrations on restored database"
  compose run --rm -T migrate
  reconcile_restored_db attacksurf

  log "restarting application services"
  compose up -d --wait --wait-timeout 300 --no-build \
    web worker-passive worker-active worker-ai beat caddy cloudflared
  compose exec -T caddy wget -q -T 5 -O /dev/null "http://web:5000/healthz"
  log "live restore complete; safety dump kept at $safety_dump"
}

main() {
  local mode="" ref="" confirmed=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --verify-only)
        mode="verify"
        shift
        [ $# -ge 1 ] || die "--verify-only requires a backup path or remote filename"
        ref=$1
        ;;
      --live)
        mode="live"
        shift
        [ $# -ge 1 ] || die "--live requires a backup path or remote filename"
        ref=$1
        ;;
      --i-understand-this-replaces-prod)
        confirmed=1
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
    shift
  done

  [ -n "$mode" ] && [ -n "$ref" ] || {
    usage >&2
    exit 1
  }
  if [ "$mode" = "live" ] && [ "$confirmed" -ne 1 ]; then
    die "--live requires --i-understand-this-replaces-prod"
  fi

  [ "$(id -u)" -eq 0 ] || die "must run as root (reads $BACKUP_ENV_FILE and drives docker)"
  command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
  docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not available"

  load_backup_env_if_present

  WORK_DIR=$(mktemp -d)
  chmod 700 "$WORK_DIR"

  fetch_and_prepare_dump "$ref"

  if [ "$mode" = "verify" ]; then
    verify_restore "$PREPARED_DUMP"
  else
    live_restore "$PREPARED_DUMP"
  fi
}

main "$@"
