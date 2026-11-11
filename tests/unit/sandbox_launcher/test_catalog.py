"""The analyzer catalog: fixed commands and limits, joined to image digests from the lock."""

import json
from pathlib import Path

import pytest

from attacksurf.sandbox_launcher import catalog
from attacksurf.sandbox_launcher.catalog import (
    CATALOG,
    AnalyzerSpec,
    SandboxLimits,
    load_catalog,
)
from attacksurf.sandbox_proxy import policy

DIGEST = "ghcr.io/acme/echo@sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
SPEC = AnalyzerSpec(name="echo", command=("/analyze", "/input"))
CEILINGS = {
    "nano_cpus": policy.MAX_NANO_CPUS,
    "memory_bytes": policy.MAX_MEMORY_BYTES,
    "pids": policy.MAX_PIDS,
    "scratch_bytes": policy.MAX_SCRATCH_BYTES,
    "open_files": policy.MAX_OPEN_FILES,
    "file_bytes": policy.MAX_FILE_BYTES,
}
BAD_LOCKS = [
    "not json",
    "[]",
    '"text"',
    json.dumps({"echo": 5}),
    json.dumps({"echo": "ghcr.io/acme/echo:latest"}),
    json.dumps({"echo": "sha256:" + "a" * 63}),
    json.dumps({"echo": "sha256:" + "A" * 64}),
]
GOOD_LOCKS = [
    "{}",
    json.dumps({"echo": DIGEST}),
    json.dumps({"echo": DIGEST, "other": OTHER_DIGEST}),
]


def write_lock(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "sandbox-images.lock"
    path.write_text(content)
    return path


def test_catalog_starts_empty() -> None:
    assert CATALOG == ()


def test_load_catalog_with_no_specs_returns_nothing(tmp_path: Path) -> None:
    assert load_catalog(write_lock(tmp_path, json.dumps({"echo": DIGEST}))) == {}


def test_load_catalog_joins_a_spec_to_its_lock_digest(tmp_path: Path) -> None:
    lock = write_lock(tmp_path, json.dumps({"echo": DIGEST}))

    analyzers = load_catalog(lock, (SPEC,))

    assert analyzers["echo"].spec == SPEC
    assert analyzers["echo"].image == DIGEST


def test_load_catalog_leaves_out_a_spec_missing_from_the_lock(tmp_path: Path) -> None:
    lock = write_lock(tmp_path, json.dumps({"other": OTHER_DIGEST}))

    assert load_catalog(lock, (SPEC,)) == {}


def test_load_catalog_ignores_a_lock_entry_without_a_spec(tmp_path: Path) -> None:
    lock = write_lock(tmp_path, json.dumps({"echo": DIGEST, "other": OTHER_DIGEST}))

    assert set(load_catalog(lock, (SPEC,))) == {"echo"}


def test_load_catalog_rejects_duplicate_spec_names(tmp_path: Path) -> None:
    lock = write_lock(tmp_path, json.dumps({"echo": DIGEST}))

    with pytest.raises(ValueError, match="duplicate"):
        load_catalog(lock, (SPEC, SPEC))


@pytest.mark.parametrize("content", BAD_LOCKS)
def test_load_catalog_rejects_a_malformed_lock_without_echoing_it(
    tmp_path: Path, content: str
) -> None:
    with pytest.raises(ValueError, match=r"^invalid images lock$"):
        load_catalog(write_lock(tmp_path, content), (SPEC,))


def test_load_catalog_lets_a_missing_lock_file_fail_startup(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_catalog(tmp_path / "missing.lock", (SPEC,))


@pytest.mark.parametrize("content", BAD_LOCKS)
def test_load_catalog_and_proxy_reject_the_same_locks(tmp_path: Path, content: str) -> None:
    lock = write_lock(tmp_path, content)

    with pytest.raises(ValueError, match="invalid images lock"):
        policy.load_images(lock)
    with pytest.raises(ValueError, match="invalid images lock"):
        load_catalog(lock, (SPEC,))


@pytest.mark.parametrize("content", GOOD_LOCKS)
def test_load_catalog_and_proxy_accept_the_same_locks(tmp_path: Path, content: str) -> None:
    lock = write_lock(tmp_path, content)

    digests, _ = policy.load_images(lock)
    assert digests == frozenset(json.loads(content).values())
    load_catalog(lock, (SPEC,))


def test_default_limits_match_the_adr_table() -> None:
    limits = SandboxLimits()

    assert limits.nano_cpus == 1_000_000_000
    assert limits.memory_bytes == 1024**3
    assert limits.pids == 256
    assert limits.scratch_bytes == 1024**3
    assert limits.open_files == 1024
    assert limits.file_bytes == 1024**3


def test_launcher_ceilings_match_the_proxy_ceilings() -> None:
    for field, ceiling in CEILINGS.items():
        assert catalog.LIMIT_CEILINGS[field] == ceiling
    assert set(catalog.LIMIT_CEILINGS) == set(CEILINGS)


@pytest.mark.parametrize("field", CEILINGS)
def test_limits_accept_exactly_the_ceiling(field: str) -> None:
    assert getattr(SandboxLimits(**{field: CEILINGS[field]}), field) == CEILINGS[field]


@pytest.mark.parametrize("field", CEILINGS)
@pytest.mark.parametrize("delta", ["zero", "negative", "bool", "above", "float"])
def test_limits_reject_invalid_values(field: str, delta: str) -> None:
    value = {
        "zero": 0,
        "negative": -1,
        "bool": True,
        "above": CEILINGS[field] + 1,
        "float": 1.5,
    }[delta]

    with pytest.raises(ValueError, match=field):
        SandboxLimits(**{field: value})


@pytest.mark.parametrize("name", ["Echo", "1echo", "../x", "", "a" * 64, "ec ho", "echo_x"])
def test_spec_rejects_a_bad_name(name: str) -> None:
    with pytest.raises(ValueError, match="name"):
        AnalyzerSpec(name=name, command=("/analyze",))


@pytest.mark.parametrize("command", [(), ("",), ("/analyze", "")])
def test_spec_rejects_an_empty_command(command: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="command"):
        AnalyzerSpec(name="echo", command=command)


def test_spec_rejects_non_string_command_items() -> None:
    with pytest.raises(ValueError, match="command"):
        AnalyzerSpec(name="echo", command=("/analyze", 3))  # type: ignore[arg-type]
