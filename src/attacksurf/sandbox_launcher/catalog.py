"""The fixed menu of analyzers (ADR 0016, 0018): what each one runs, its limits and its image.

The caller names an analyzer and nothing else. The command and limits are code, reviewed with the
analyzer; the image digest comes from `sandbox-images.lock`, built in CI. An analyzer needs both
to be runnable, so one missing from the lock, or from the code, is simply unavailable.

The launcher never imports `sandbox_proxy`, so the lock format and hard ceilings are copied from
`sandbox_proxy/policy.py`; unit tests keep the copies in step.
"""

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from pathlib import Path

ANALYZER_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")

_DIGEST = re.compile(r"([^@\s:]+(:\d+)?(/[^@\s:]+)*@)?sha256:[0-9a-f]{64}")

# The proxy's hard ceilings: a create body above any of them is refused there.
LIMIT_CEILINGS = {
    "nano_cpus": 4_000_000_000,
    "memory_bytes": 8 * 1024**3,
    "pids": 1024,
    "scratch_bytes": 8 * 1024**3,
    "open_files": 4096,
    "file_bytes": 8 * 1024**3,
}


@dataclass(frozen=True)
class SandboxLimits:
    """Per-run resource limits; defaults are the ADR 0016 table."""

    nano_cpus: int = 1_000_000_000
    memory_bytes: int = 1024**3
    pids: int = 256
    scratch_bytes: int = 1024**3
    open_files: int = 1024
    file_bytes: int = 1024**3

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            valid = (
                isinstance(value, int)
                and not isinstance(value, bool)
                and 0 < value <= LIMIT_CEILINGS[field.name]
            )
            if not valid:
                raise ValueError(f"{field.name} is out of bounds")


@dataclass(frozen=True)
class AnalyzerSpec:
    """One analyzer's fixed command (the sandbox `Cmd`) and limits."""

    name: str
    command: tuple[str, ...]
    limits: SandboxLimits = SandboxLimits()

    def __post_init__(self) -> None:
        if not ANALYZER_NAME.fullmatch(self.name):
            raise ValueError("analyzer name is not allowed")
        command = self.command
        if not command or not all(isinstance(item, str) and item for item in command):
            raise ValueError("analyzer command must be a non-empty list of non-empty strings")


@dataclass(frozen=True)
class Analyzer:
    """A runnable analyzer: its spec plus the image digest reference from the lock."""

    spec: AnalyzerSpec
    image: str


# Empty until an analyzer ships; the fixture analyzer arrives with the real-runtime CI job.
CATALOG: tuple[AnalyzerSpec, ...] = ()


def load_catalog(
    lock_path: Path, specs: Sequence[AnalyzerSpec] = CATALOG
) -> Mapping[str, Analyzer]:
    """Runnable analyzers: those with both a spec and a lock entry. Everything else is dropped.

    Raises `ValueError` for a malformed lock (never echoing it) or duplicate spec names.
    """
    by_name = {spec.name: spec for spec in specs}
    if len(by_name) != len(specs):
        raise ValueError("duplicate analyzer names in the catalog")
    digests = _read_lock(lock_path)
    return {
        name: Analyzer(spec, digests[name]) for name, spec in by_name.items() if name in digests
    }


def _read_lock(lock_path: Path) -> dict[str, str]:
    try:
        entries = json.loads(lock_path.read_text())
    except ValueError:
        raise ValueError("invalid images lock") from None
    if not isinstance(entries, dict):
        raise ValueError("invalid images lock")
    for digest in entries.values():
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ValueError("invalid images lock")
    return entries
