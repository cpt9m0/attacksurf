"""The sandbox port: how scanners ask for an analyzer run on an untrusted artifact (ADR 0016).

The caller names an allowlisted analyzer and an artifact, and nothing else. Images, arguments,
mounts and limits are fixed on the launcher's side, so a compromised caller can't choose them.
"""

from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from attacksurf.domain.jobs import JobError


class SandboxError(JobError):
    """A run could not be started or completed. Never carries tool output or artifact paths."""


@dataclass(frozen=True)
class SandboxResult:
    """What came back from one run. `stdout` is untrusted and hidden from logs and reprs."""

    exit_code: int | None  # None when the run was killed before exiting
    stdout: bytes = field(repr=False)
    timed_out: bool = False
    output_exceeded: bool = False


class SandboxRunner(Protocol):
    def run(self, analyzer: str, artifact_id: UUID) -> SandboxResult:
        """Run `analyzer` on the artifact in a fresh sandbox. Raises `SandboxError` on failure."""
        ...


class UnconfiguredSandboxRunner:
    """Processes with no launcher wired: fail closed rather than run anything."""

    def run(self, analyzer: str, artifact_id: UUID) -> SandboxResult:
        raise SandboxError("Sandboxed analysis is not configured.")
