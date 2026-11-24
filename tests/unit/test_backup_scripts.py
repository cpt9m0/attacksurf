"""Syntax and stubbed-CLI behavior tests for production deploy/backup/restore scripts."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash") or "/bin/bash"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _install_stub_bin(
    tmp_path: Path,
    *,
    with_age: bool = True,
    with_rclone: bool = True,
) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log_file = tmp_path / "calls.log"
    remote_dir = tmp_path / "remote"
    remote_dir.mkdir()

    # Stub `id` so root-only checks run cleanly inside unprivileged unit tests.
    _write_executable(bin_dir / "id", "#!/bin/sh\necho 0\n")

    # Stub `docker` handling `compose version`, `compose exec ... pg_dump`, `pg_restore`, `psql`,
    # `compose stop`, `compose up`.
    _write_executable(
        bin_dir / "docker",
        f"""#!/usr/bin/env bash
set -euo pipefail
echo "docker $*" >> {str(log_file)!r}
if [ "${{1:-}}" = "compose" ] && [ "${{2:-}}" = "version" ]; then
  echo "Docker Compose version v5.1.1"
  exit 0
fi
if [ "${{1:-}}" = "inspect" ]; then
  echo "attacksurf-web:deadbeef1234"
  exit 0
fi
prev=""
for arg in "$@"; do
  if [ "$prev" = "-q" ] && [ "$arg" = "web" ]; then
    echo "web-cid-1"
    exit 0
  fi
  if [ "$prev" = "-d" ]; then
    case "$*" in
      *orgs*)
        printf 'alembic_version=0014\\norgs=1\\nusers=2\\n'
        printf 'assets=5\\nscans=3\\nfindings=4\\n'
        exit 0
        ;;
    esac
  fi
  prev=$arg
done
for arg in "$@"; do
  case "$arg" in
    pg_dump)
      printf 'PGDMP-FAKE-CUSTOM-DUMP\\n'
      exit 0
      ;;
    pg_restore)
      cat >/dev/null
      exit 0
      ;;
  esac
done
exit 0
""",
    )

    if with_rclone:
        _write_executable(
            bin_dir / "rclone",
            f"""#!/usr/bin/env bash
set -euo pipefail
echo "rclone $*" >> {str(log_file)!r}
remote_root={str(remote_dir)!r}
case "${{1:-}}" in
  copyto)
    src=$2
    dst=$3
    if [[ "$src" == backup:* ]]; then
      rel=${{src#backup:}}
      mkdir -p "$(dirname "$dst")"
      cp "$remote_root/$rel" "$dst"
    elif [[ "$dst" == backup:* ]]; then
      rel=${{dst#backup:}}
      mkdir -p "$(dirname "$remote_root/$rel")"
      cp "$src" "$remote_root/$rel"
    fi
    ;;
  delete)
    ;;
esac
""",
        )

    if with_age:
        _write_executable(
            bin_dir / "age",
            f"""#!/usr/bin/env bash
set -euo pipefail
echo "age $*" >> {str(log_file)!r}
mode="enc"
out=""
src=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d) mode="dec" ;;
    -r|-i) shift ;;
    -o) shift; out=$1 ;;
    *) src=$1 ;;
  esac
  shift
done
if [ "$mode" = "enc" ]; then
  {{ printf 'AGE-ENC\\n'; cat "$src"; }} >"$out"
else
  tail -n +2 "$src" >"$out"
fi
""",
        )

    return bin_dir, log_file


def test_production_shell_scripts_pass_bash_syntax_check() -> None:
    for script in ("scripts/deploy.sh", "scripts/backup.sh", "scripts/restore.sh"):
        result = subprocess.run(  # noqa: S603 (fixed local scripts)
            [BASH, "-n", str(ROOT / script)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"{script}: {result.stderr}"


def test_backup_refuses_insecure_env_file_permissions(tmp_path: Path) -> None:
    bin_dir, _ = _install_stub_bin(tmp_path)
    env_file = tmp_path / "backup.env"
    env_file.write_text("BACKUP_REMOTE_PATH=backup:bucket/pg\n", encoding="utf-8")
    env_file.chmod(0o644)

    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "APP_DIR": str(ROOT),
        "BACKUP_ENV_FILE": str(env_file),
    }
    result = subprocess.run(  # noqa: S603
        [str(ROOT / "scripts/backup.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "mode 0600 or 0400" in result.stderr


def test_backup_uploads_encrypted_dump_and_prunes_after_upload(tmp_path: Path) -> None:
    bin_dir, log_file = _install_stub_bin(tmp_path)
    env_file = tmp_path / "backup.env"
    env_file.write_text(
        "BACKUP_REMOTE_PATH=backup:bucket/pg\n"
        "BACKUP_RETENTION_DAYS=14\n"
        "BACKUP_AGE_RECIPIENT=age1testrecipientkey\n",
        encoding="utf-8",
    )
    env_file.chmod(stat.S_IRUSR | stat.S_IWUSR)

    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "APP_DIR": str(ROOT),
        "BACKUP_ENV_FILE": str(env_file),
    }
    result = subprocess.run(  # noqa: S603
        [str(ROOT / "scripts/backup.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    remote_files = sorted(p.name for p in (tmp_path / "remote/bucket/pg").iterdir())
    assert len(remote_files) == 2
    assert remote_files[0].endswith(".dump.age")
    assert remote_files[1].endswith(".dump.age.sha256")
    calls = log_file.read_text(encoding="utf-8").splitlines()
    copy_idx = next(i for i, line in enumerate(calls) if line.startswith("rclone copyto"))
    prune_idx = next(i for i, line in enumerate(calls) if line.startswith("rclone delete"))
    assert prune_idx > copy_idx
    assert "--min-age 14d" in calls[prune_idx]


def test_restore_verify_only_downloads_verifies_decrypts_and_drops_temp_db(
    tmp_path: Path,
) -> None:
    bin_dir, log_file = _install_stub_bin(tmp_path)
    env_file = tmp_path / "backup.env"
    identity_file = tmp_path / "age.key"
    identity_file.write_text("AGE-SECRET-KEY-1TEST", encoding="utf-8")
    identity_file.chmod(0o600)
    env_file.write_text(
        "BACKUP_REMOTE_PATH=backup:bucket/pg\n"
        "BACKUP_AGE_RECIPIENT=age1testrecipientkey\n"
        f"BACKUP_AGE_IDENTITY={identity_file}\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)

    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "APP_DIR": str(ROOT),
        "BACKUP_ENV_FILE": str(env_file),
    }
    backup_res = subprocess.run(  # noqa: S603
        [str(ROOT / "scripts/backup.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "backup complete" in backup_res.stdout
    dump_name = next(
        p.name for p in (tmp_path / "remote/bucket/pg").iterdir() if p.name.endswith(".dump.age")
    )

    log_file.unlink()
    restore_res = subprocess.run(  # noqa: S603
        [str(ROOT / "scripts/restore.sh"), "--verify-only", dump_name],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert restore_res.returncode == 0, restore_res.stderr
    assert "alembic_version=0014" in restore_res.stdout
    assert "orgs=1" in restore_res.stdout
    calls = log_file.read_text(encoding="utf-8")
    assert "CREATE DATABASE" in calls
    assert "DROP DATABASE IF EXISTS" in calls


def test_restore_live_preserves_image_stages_clean_db_and_migrates(tmp_path: Path) -> None:
    bin_dir, log_file = _install_stub_bin(tmp_path)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "deployed-sha").write_text("deadbeef1234567890\n", encoding="utf-8")
    dump_file = tmp_path / "backup.dump"
    dump_file.write_bytes(b"PGDMP-FAKE-CUSTOM-DUMP\n")

    # Record WEB_IMAGE seen by compose invocations in the stubbed docker wrapper.
    docker_stub = bin_dir / "docker"
    docker_stub.write_text(
        docker_stub.read_text(encoding="utf-8").replace(
            'echo "docker $*"',
            'echo "WEB_IMAGE=${WEB_IMAGE:-unset} docker $*"',
        ),
        encoding="utf-8",
    )

    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "APP_DIR": str(ROOT),
        "BACKUP_ENV_FILE": str(tmp_path / "nonexistent.env"),
        "STATE_DIR": str(state_dir),
        "DEPLOY_LOCK_FILE": str(tmp_path / "deploy.lock"),
    }
    res = subprocess.run(  # noqa: S603
        [
            str(ROOT / "scripts/restore.sh"),
            "--live",
            str(dump_file),
            "--i-understand-this-replaces-prod",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert res.returncode == 0, res.stderr
    assert (tmp_path / "deploy.lock").is_file()
    calls = log_file.read_text(encoding="utf-8")
    assert 'CREATE DATABASE "attacksurf_restore_stage"' in calls
    assert "pg_restore -U attacksurf -d attacksurf_restore_stage --no-owner" in calls
    assert "--clean" not in calls
    assert 'ALTER DATABASE "attacksurf_restore_stage" RENAME TO attacksurf' in calls
    assert "UPDATE scans" in calls
    assert "Cancelled by database restore." in calls
    assert "WEB_IMAGE=attacksurf-web:deadbeef1234 docker compose" in calls
    stop_line = next(
        line for line in calls.splitlines() if " compose " in line and " stop " in line
    )
    migrate_line = next(line for line in calls.splitlines() if "run --rm -T migrate" in line)
    reconcile_line = next(
        line for line in calls.splitlines() if "Cancelled by database restore." in line
    )
    up_line = next(
        line for line in calls.splitlines() if "up -d --wait --wait-timeout 300 --no-build" in line
    )
    assert "worker-active" in stop_line
    assert "worker-active" in up_line
    assert (
        calls.index(stop_line)
        < calls.index(migrate_line)
        < calls.index(reconcile_line)
        < calls.index(up_line)
    )
    assert migrate_line.startswith("WEB_IMAGE=attacksurf-web:deadbeef1234 ")
    assert up_line.startswith("WEB_IMAGE=attacksurf-web:deadbeef1234 ")


def test_restore_live_requires_explicit_confirmation_flag(tmp_path: Path) -> None:
    bin_dir, _ = _install_stub_bin(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "APP_DIR": str(ROOT),
    }

    result = subprocess.run(  # noqa: S603
        [str(ROOT / "scripts/restore.sh"), "--live", "some-backup.dump"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "--i-understand-this-replaces-prod" in result.stderr
