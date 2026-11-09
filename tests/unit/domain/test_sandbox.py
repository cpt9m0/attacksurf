"""The sandbox port: a safe result shape, a fail-closed default, and validated grants."""

from uuid import uuid4

import pytest

from attacksurf.domain.jobs import JobError
from attacksurf.domain.net import ScannerRuntime
from attacksurf.domain.sandbox import SandboxError, SandboxResult, UnconfiguredSandboxRunner
from attacksurf.domain.scanners import ScannerGrant
from tests.scanner_fixtures import StubDns, StubHttp


def test_sandbox_result_repr_never_contains_tool_output() -> None:
    result = SandboxResult(exit_code=0, stdout=b'{"secret": "AKIA-evidence"}')

    assert "AKIA-evidence" not in repr(result)


def test_sandbox_result_defaults_to_a_run_that_stayed_within_limits() -> None:
    result = SandboxResult(exit_code=0, stdout=b"{}")

    assert result.timed_out is False
    assert result.output_exceeded is False


def test_unconfigured_runner_refuses_every_run() -> None:
    with pytest.raises(SandboxError, match="not configured"):
        UnconfiguredSandboxRunner().run("gitleaks.tree", uuid4())


def test_sandbox_error_is_a_user_safe_job_error() -> None:
    assert issubclass(SandboxError, JobError)


def test_scanner_runtime_without_a_sandbox_fails_closed() -> None:
    runtime = ScannerRuntime(StubDns(), StubHttp())

    with pytest.raises(SandboxError):
        runtime.sandbox.run("gitleaks.tree", uuid4())


def test_scanner_grant_allows_no_analyzers_by_default() -> None:
    assert ScannerGrant().sandbox_analyzers == frozenset()


@pytest.mark.parametrize("name", ["gitleaks", "gitleaks.tree", "osv-scanner", "lief_elf"])
def test_scanner_grant_accepts_analyzer_names(name: str) -> None:
    assert ScannerGrant(sandbox_analyzers=frozenset({name})).sandbox_analyzers == {name}


@pytest.mark.parametrize(
    "name",
    ["", "Gitleaks", "../gitleaks", "ghcr.io/x/y@sha256:abc", "tool --flag", ".hidden", "a" * 65],
)
def test_scanner_grant_rejects_anything_but_a_plain_analyzer_name(name: str) -> None:
    with pytest.raises(ValueError, match="analyzer"):
        ScannerGrant(sandbox_analyzers=frozenset({name}))
