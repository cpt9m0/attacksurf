"""The create body: exactly what the proxy's `validate_create` accepts, built from fixed inputs."""

import json
from dataclasses import fields, replace
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

import pytest

from attacksurf.sandbox_launcher import container
from attacksurf.sandbox_launcher.artifacts import resolve_artifact
from attacksurf.sandbox_launcher.catalog import (
    CATALOG,
    LIMIT_CEILINGS,
    Analyzer,
    AnalyzerSpec,
    SandboxLimits,
)
from attacksurf.sandbox_launcher.container import build_create_body
from attacksurf.sandbox_proxy import policy
from attacksurf.sandbox_proxy.policy import PolicyViolation, SandboxPolicy, validate_create

IMAGE = "ghcr.io/acme/echo@sha256:" + "a" * 64
OSV_IMAGE = "ghcr.io/acme/osv@sha256:" + "b" * 64
ROOT = Path("/srv/artifacts")
ARTIFACT_DIR = ROOT / "11111111-1111-4111-8111-111111111111"
COMMAND = ("/analyze", "/input")
LIMIT_NAMES = [field.name for field in fields(SandboxLimits)]


def analyzer(
    name: str = "echo", image: str = IMAGE, limits: SandboxLimits | None = None
) -> Analyzer:
    spec = AnalyzerSpec(name=name, command=COMMAND, limits=limits or SandboxLimits())
    return Analyzer(spec, image)


def proxy_policy(
    image: str = IMAGE,
    runtime: str = "runsc",
    root: Path = ROOT,
    osv_image: str | None = None,
) -> SandboxPolicy:
    return SandboxPolicy(
        images=frozenset({image}),
        runtimes=frozenset({runtime}),
        artifact_root=PurePosixPath(root),
        osv_image=osv_image,
    )


def host_of(body: dict[str, Any]) -> dict[str, Any]:
    return body["HostConfig"]


# --- A. Happy path ------------------------------------------------------------------------------


def test_default_analyzer_builds_the_exact_adr_body() -> None:
    body = build_create_body(analyzer(), ARTIFACT_DIR, "runsc")

    assert body == {
        "Image": IMAGE,
        "User": "65532:65532",
        "Cmd": ["/analyze", "/input"],
        "AttachStdout": True,
        "HostConfig": {
            "Runtime": "runsc",
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "AutoRemove": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "Binds": [f"{ARTIFACT_DIR}:/input:ro"],
            "Tmpfs": {"/scratch": "rw,noexec,nosuid,nodev,size=1073741824"},
            "NanoCpus": 1_000_000_000,
            "Memory": 1024**3,
            "MemorySwap": 1024**3,
            "PidsLimit": 256,
            "Ulimits": [
                {"Name": "nofile", "Soft": 1024, "Hard": 1024},
                {"Name": "fsize", "Soft": 1024**3, "Hard": 1024**3},
            ],
            "LogConfig": {"Type": "none"},
        },
    }


@pytest.mark.parametrize("runtime", ["runsc", "runc"])
def test_body_is_accepted_by_the_proxy_policy(runtime: str) -> None:
    body = build_create_body(analyzer(), ARTIFACT_DIR, runtime)

    validate_create(body, proxy_policy(runtime=runtime))


@pytest.mark.parametrize(
    ("name", "value", "check"),
    [
        ("nano_cpus", 2_000_000_000, lambda h: h["NanoCpus"] == 2_000_000_000),
        (
            "memory_bytes",
            2 * 1024**3,
            lambda h: h["Memory"] == h["MemorySwap"] == 2 * 1024**3,
        ),
        ("pids", 64, lambda h: h["PidsLimit"] == 64),
        (
            "scratch_bytes",
            2048,
            lambda h: h["Tmpfs"] == {"/scratch": "rw,noexec,nosuid,nodev,size=2048"},
        ),
        (
            "open_files",
            512,
            lambda h: {"Name": "nofile", "Soft": 512, "Hard": 512} in h["Ulimits"],
        ),
        (
            "file_bytes",
            4096,
            lambda h: {"Name": "fsize", "Soft": 4096, "Hard": 4096} in h["Ulimits"],
        ),
    ],
)
def test_each_limit_lands_in_its_own_field(name: str, value: int, check: Any) -> None:
    limits = replace(SandboxLimits(), **{name: value})

    body = build_create_body(analyzer(limits=limits), ARTIFACT_DIR, "runsc")

    assert check(host_of(body))
    validate_create(body, proxy_policy())


def test_cmd_and_image_come_from_the_analyzer() -> None:
    body = build_create_body(analyzer(), ARTIFACT_DIR, "runsc")

    assert body["Cmd"] == ["/analyze", "/input"]
    assert isinstance(body["Cmd"], list)
    assert body["Image"] == IMAGE
    assert "Entrypoint" not in body


def test_osv_scanner_gets_the_osv_bind() -> None:
    body = build_create_body(analyzer("osv-scanner", OSV_IMAGE), ARTIFACT_DIR, "runsc")

    assert host_of(body)["Binds"] == [f"{ARTIFACT_DIR}:/input:ro", "attacksurf_osv:/data/osv:ro"]
    validate_create(body, proxy_policy(image=OSV_IMAGE, osv_image=OSV_IMAGE))


def test_other_analyzers_never_get_the_osv_bind() -> None:
    body = build_create_body(analyzer(), ARTIFACT_DIR, "runsc")

    assert host_of(body)["Binds"] == [f"{ARTIFACT_DIR}:/input:ro"]


def test_body_is_json_serializable() -> None:
    body = build_create_body(analyzer(), ARTIFACT_DIR, "runsc")

    assert json.loads(json.dumps(body)) == body


def test_each_call_returns_fresh_objects() -> None:
    subject = analyzer()
    first = build_create_body(subject, ARTIFACT_DIR, "runsc")
    second = build_create_body(subject, ARTIFACT_DIR, "runsc")

    first["Cmd"].append("--evil")
    host_of(first)["CapDrop"].append("NET_ADMIN")
    host_of(first)["Binds"].append("/:/host")
    host_of(first)["Ulimits"].clear()

    assert second == build_create_body(subject, ARTIFACT_DIR, "runsc")
    assert subject.spec.command == COMMAND


def test_resolved_artifact_path_feeds_the_builder(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    artifact_id = uuid4()
    (root / str(artifact_id)).mkdir(parents=True)

    body = build_create_body(analyzer(), resolve_artifact(root, artifact_id), "runsc")

    validate_create(body, proxy_policy(root=root))


@pytest.mark.parametrize("spec", CATALOG, ids=lambda spec: spec.name)
def test_every_catalog_spec_builds_an_accepted_body(spec: AnalyzerSpec) -> None:
    image = OSV_IMAGE if spec.name == policy.OSV_ANALYZER else IMAGE
    osv_image = OSV_IMAGE if spec.name == policy.OSV_ANALYZER else None

    body = build_create_body(Analyzer(spec, image), ARTIFACT_DIR, "runsc")

    validate_create(body, proxy_policy(image=image, osv_image=osv_image))


# --- B. Boundary cases --------------------------------------------------------------------------


def test_limits_at_every_proxy_ceiling_are_accepted() -> None:
    limits = SandboxLimits(**LIMIT_CEILINGS)

    validate_create(
        build_create_body(analyzer(limits=limits), ARTIFACT_DIR, "runsc"), proxy_policy()
    )


@pytest.mark.parametrize("name", LIMIT_NAMES)
def test_each_limit_at_its_proxy_ceiling_is_accepted(name: str) -> None:
    limits = replace(SandboxLimits(), **{name: LIMIT_CEILINGS[name]})

    validate_create(
        build_create_body(analyzer(limits=limits), ARTIFACT_DIR, "runsc"), proxy_policy()
    )


@pytest.mark.parametrize("name", LIMIT_NAMES)
def test_each_limit_at_the_minimum_of_one_is_accepted(name: str) -> None:
    limits = replace(SandboxLimits(), **{name: 1})

    validate_create(
        build_create_body(analyzer(limits=limits), ARTIFACT_DIR, "runsc"), proxy_policy()
    )


def test_single_item_command_is_kept() -> None:
    spec = AnalyzerSpec(name="echo", command=("/run",))

    body = build_create_body(Analyzer(spec, IMAGE), ARTIFACT_DIR, "runsc")

    assert body["Cmd"] == ["/run"]


@pytest.mark.parametrize("name", ["osv", "osv-scanner2", "my-osv-scanner", "osv-scanner-x"])
def test_osv_bind_matches_the_analyzer_name_exactly(name: str) -> None:
    body = build_create_body(analyzer(name), ARTIFACT_DIR, "runsc")

    assert host_of(body)["Binds"] == [f"{ARTIFACT_DIR}:/input:ro"]


def test_artifact_dir_with_dots_hyphens_and_underscores_is_accepted() -> None:
    root = Path("/srv/art.if_acts-1")
    artifact_dir = root / "11111111-1111-4111-8111-111111111111"

    body = build_create_body(analyzer(), artifact_dir, "runsc")

    assert host_of(body)["Binds"] == [f"{artifact_dir}:/input:ro"]
    validate_create(body, proxy_policy(root=root))


def test_deep_artifact_root_is_accepted() -> None:
    root = Path("/var/lib/attacksurf/data/artifacts")

    body = build_create_body(analyzer(), root / "abc", "runsc")

    validate_create(body, proxy_policy(root=root))


# --- C. Invalid inputs --------------------------------------------------------------------------


@pytest.mark.parametrize("path", [Path("a/b"), Path("./x"), Path("secret-relative-dir")])
def test_relative_artifact_dir_is_rejected(path: Path) -> None:
    with pytest.raises(ValueError, match="absolute") as caught:
        build_create_body(analyzer(), path, "runsc")

    assert str(path) not in str(caught.value)


@pytest.mark.parametrize("path", ["/srv/a:rw", "/srv/a:/etc:rw", "/srv/a:", "/srv:x/a"])
def test_artifact_dir_with_a_colon_is_rejected(path: str) -> None:
    with pytest.raises(ValueError, match="colon") as caught:
        build_create_body(analyzer(), Path(path), "runsc")

    assert path not in str(caught.value)


@pytest.mark.parametrize("runtime", ["", "kata", "RUNSC", "runsc ", "runsc,runc"])
def test_unknown_runtime_is_rejected(runtime: str) -> None:
    with pytest.raises(ValueError, match="runtime") as caught:
        build_create_body(analyzer(), ARTIFACT_DIR, runtime)

    assert runtime.strip() == "" or runtime not in str(caught.value)


# --- D. Proxy rejection and drift guards --------------------------------------------------------


@pytest.mark.parametrize("osv_image", [None, IMAGE])
def test_osv_body_is_refused_when_the_policy_has_no_matching_osv_image(
    osv_image: str | None,
) -> None:
    body = build_create_body(analyzer("osv-scanner", OSV_IMAGE), ARTIFACT_DIR, "runsc")

    with pytest.raises(PolicyViolation):
        validate_create(body, proxy_policy(image=OSV_IMAGE, osv_image=osv_image))


def test_body_is_refused_for_an_image_not_on_the_allowlist() -> None:
    body = build_create_body(analyzer(), ARTIFACT_DIR, "runsc")

    with pytest.raises(PolicyViolation):
        validate_create(body, proxy_policy(image=OSV_IMAGE))


def test_body_is_refused_when_the_runtime_is_not_allowed() -> None:
    body = build_create_body(analyzer(), ARTIFACT_DIR, "runc")

    with pytest.raises(PolicyViolation):
        validate_create(body, proxy_policy(runtime="runsc"))


def test_body_is_refused_outside_the_artifact_root() -> None:
    body = build_create_body(analyzer(), ARTIFACT_DIR, "runsc")

    with pytest.raises(PolicyViolation):
        validate_create(body, proxy_policy(root=Path("/srv/other")))


def test_copied_constants_match_the_proxy() -> None:
    assert container.SANDBOX_USER == policy.SANDBOX_USER
    assert container.OSV_ANALYZER == policy.OSV_ANALYZER
    assert container.OSV_BIND == policy.OSV_BIND
