"""The CI workflows (#84): pinned actions, a read-only image build, and a sandbox job that can't
pass without gVisor."""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
RUNTIME_TESTS = ROOT / "tests" / "integration" / "sandbox" / "test_runtime.py"
PINNED_ACTION = re.compile(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}")
USES_LINE = re.compile(r"^\s*(?:- )?uses:[ \t]*(\S+)(.*)$", re.MULTILINE)
VERSION_COMMENT = re.compile(r"\s+# v\d+(\.\d+)*")
REFUSAL_TEST = "test_launcher_refuses_to_start_in_prod_without_runsc"
IMAGE_PATHS = [
    "sandbox/images/**",
    "scripts/build-sandbox-images.sh",
    ".github/workflows/sandbox-images.yml",
]
# In the order the sandbox job must run them.
SANDBOX_STEPS = (
    "scripts/build-sandbox-images.sh",
    REFUSAL_TEST,
    "scripts/install-runsc.sh",
    "--runtime=runsc",
    "make sandbox-test",
)

pytestmark = pytest.mark.skipif(
    not WORKFLOWS.is_dir(), reason="needs the checkout's .github/workflows"
)


def load(name: str) -> dict[Any, Any]:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    # YAML 1.1, which PyYAML follows, reads the bare key `on` as the boolean True.
    return workflow[True]


def uses_values(workflow: dict[Any, Any]) -> list[str]:
    jobs = workflow["jobs"].values()
    from_jobs = [job["uses"] for job in jobs if "uses" in job]
    return from_jobs + [
        step["uses"] for job in jobs for step in job.get("steps", []) if "uses" in step
    ]


def sandbox_job() -> dict[str, Any]:
    return load("ci.yml")["jobs"]["sandbox"]


def step_index(marker: str) -> int:
    steps = sandbox_job()["steps"]
    found = [index for index, step in enumerate(steps) if marker in step.get("run", "")]
    assert len(found) == 1, f"expected one step running {marker!r}, found {len(found)}"
    return found[0]


def step(marker: str) -> dict[str, Any]:
    return sandbox_job()["steps"][step_index(marker)]


@pytest.mark.parametrize("path", sorted(WORKFLOWS.glob("*.yml")), ids=lambda path: path.name)
def test_every_action_is_pinned_to_a_commit_sha(path: Path) -> None:
    lines = USES_LINE.findall(path.read_text())

    # The same references both ways, so the line check can't miss one written another way.
    assert sorted(value for value, _ in lines) == sorted(uses_values(load(path.name)))
    for value, rest in lines:
        assert PINNED_ACTION.fullmatch(value), value
        assert VERSION_COMMENT.fullmatch(rest), f"{value} needs a `# vX.Y.Z` comment"


def test_sandbox_images_workflow_can_only_read() -> None:
    workflow = load("sandbox-images.yml")

    assert workflow["permissions"] == {"contents": "read"}
    for job in workflow["jobs"].values():
        assert "permissions" not in job
        for each in job["steps"]:
            assert "login" not in each.get("uses", "")
            assert "push" not in each.get("run", "")
            assert not each.get("with", {}).get("push")


def test_sandbox_images_workflow_runs_when_images_change() -> None:
    on = triggers(load("sandbox-images.yml"))

    assert set(on) == {"pull_request", "push", "workflow_dispatch"}
    assert on["pull_request"] == {"paths": IMAGE_PATHS}
    assert on["push"] == {"branches": ["main"], "paths": IMAGE_PATHS}


def test_sandbox_images_workflow_uses_the_shared_build_script() -> None:
    (job,) = load("sandbox-images.yml")["jobs"].values()

    runs = [each["run"] for each in job["steps"] if "run" in each]

    assert runs == ["scripts/build-sandbox-images.sh"]


def test_sandbox_job_runs_on_every_pull_request() -> None:
    assert "pull_request" in triggers(load("ci.yml"))
    assert triggers(load("ci.yml"))["pull_request"] is None  # no path or branch filter


def test_sandbox_job_never_falls_back_to_runc() -> None:
    job = sandbox_job()

    assert job["env"] == {"RUN_SANDBOX_TESTS": "1", "SANDBOX_ALLOW_RUNC": "false"}
    assert step("make sandbox-test")["env"] == {"SANDBOX_EXPECT_RUNTIME": "runsc"}
    for each in job["steps"]:
        assert not {"RUN_SANDBOX_TESTS", "SANDBOX_ALLOW_RUNC"} & set(each.get("env", {}))
        # A later line in a step could re-set them for the steps after it.
        assert "SANDBOX_ALLOW_RUNC" not in each.get("run", "")


def test_sandbox_job_cannot_pass_by_skipping_a_step() -> None:
    job = sandbox_job()

    assert not {"if", "continue-on-error"} & set(job)
    assert job["timeout-minutes"] <= 15
    for each in job["steps"]:
        assert "continue-on-error" not in each
        assert each.get("if") in (None, "failure()")


def test_prod_refusal_runs_before_runsc_is_installed() -> None:
    order = [step_index(marker) for marker in SANDBOX_STEPS]

    assert order == sorted(order)
    assert step(REFUSAL_TEST)["env"] == {"SANDBOX_EXPECT_RUNTIME": "runc"}
    assert f"def {REFUSAL_TEST}(" in RUNTIME_TESTS.read_text()
