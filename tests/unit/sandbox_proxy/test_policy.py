"""The create-request policy: only the exact ADR 0016 sandbox shape may reach Docker."""

import copy
import json
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from attacksurf.sandbox_proxy.policy import (
    MAX_MEMORY_BYTES,
    OSV_BIND,
    SANDBOX_USER,
    PolicyViolation,
    SandboxPolicy,
    classify_request,
    load_images,
    validate_create,
)

IMAGE = "ghcr.io/acme/echo@sha256:" + "a" * 64
OSV_IMAGE = "ghcr.io/acme/osv@sha256:" + "b" * 64
OTHER_IMAGE = "ghcr.io/acme/evil@sha256:" + "c" * 64
CONTAINER = "d" * 64
POLICY = SandboxPolicy(
    images=frozenset({IMAGE, OSV_IMAGE}),
    runtimes=frozenset({"runsc"}),
    artifact_root=PurePosixPath("/srv/artifacts"),
    osv_image=OSV_IMAGE,
)
Body = dict[str, Any]


def create_body() -> Body:
    return {
        "Image": IMAGE,
        "User": SANDBOX_USER,
        "Cmd": ["/analyze", "/input"],
        "AttachStdout": True,
        "HostConfig": {
            "Runtime": "runsc",
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "AutoRemove": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "Binds": ["/srv/artifacts/org/artifact:/input:ro"],
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


def host(**changes: Any) -> Callable[[Body], None]:
    def mutate(body: Body) -> None:
        body["HostConfig"].update(changes)

    return mutate


def top(**changes: Any) -> Callable[[Body], None]:
    return lambda body: body.update(changes)


def drop(field: str) -> Callable[[Body], None]:
    return lambda body: body["HostConfig"].pop(field)


def test_valid_sandbox_request_passes() -> None:
    validate_create(create_body(), POLICY)


def test_osv_image_may_mount_the_osv_volume_read_only() -> None:
    body = create_body()
    body["Image"] = OSV_IMAGE
    body["HostConfig"]["Binds"].append(OSV_BIND)

    validate_create(body, POLICY)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(top(Image=OTHER_IMAGE), id="unknown-image"),
        pytest.param(top(Image="ghcr.io/acme/echo:latest"), id="tag-instead-of-digest"),
        pytest.param(top(User="0:0"), id="root-user"),
        pytest.param(top(Env=["TOKEN=x"]), id="injected-environment"),
        pytest.param(top(Tty=True), id="tty"),
        pytest.param(top(OpenStdin=True), id="stdin"),
        pytest.param(top(Volumes={"/x": {}}), id="declared-volume"),
        pytest.param(top(Labels={"a": "b"}), id="unknown-top-level-field"),
        pytest.param(top(Cmd="sh -c evil"), id="cmd-not-a-list"),
        pytest.param(host(Privileged=True), id="privileged"),
        pytest.param(host(privileged=True), id="case-variant-of-a-field"),
        pytest.param(host(PidMode="host"), id="host-pid-namespace"),
        pytest.param(host(IpcMode="host"), id="host-ipc-namespace"),
        pytest.param(host(UTSMode="host"), id="host-uts-namespace"),
        pytest.param(host(UsernsMode="host"), id="host-user-namespace"),
        pytest.param(host(Devices=[{"PathOnHost": "/dev/sda"}]), id="devices"),
        pytest.param(host(CapAdd=["SYS_ADMIN"]), id="added-capability"),
        pytest.param(host(VolumesFrom=["other"]), id="volumes-from"),
        pytest.param(host(Mounts=[{"Type": "bind"}]), id="mounts-field"),
        pytest.param(host(Runtime="runc"), id="runtime-not-allowed"),
        pytest.param(host(NetworkMode="bridge"), id="network"),
        pytest.param(host(ReadonlyRootfs=False), id="writable-root"),
        pytest.param(host(AutoRemove=False), id="not-removed"),
        pytest.param(host(CapDrop=["NET_RAW"]), id="capabilities-kept"),
        pytest.param(host(SecurityOpt=[]), id="new-privileges-allowed"),
        pytest.param(host(SecurityOpt=["seccomp=unconfined"]), id="seccomp-off"),
        pytest.param(host(LogConfig={"Type": "json-file"}), id="output-logged-to-host"),
        pytest.param(host(Memory=MAX_MEMORY_BYTES + 1), id="memory-over-ceiling"),
        pytest.param(host(Memory=0), id="memory-unlimited"),
        pytest.param(host(Memory=True), id="memory-boolean"),
        pytest.param(host(MemorySwap=2 * 1024**3), id="swap-allowed"),
        pytest.param(host(NanoCpus=0), id="cpu-unlimited"),
        pytest.param(host(PidsLimit=-1), id="pids-unlimited"),
        pytest.param(host(Ulimits=[]), id="ulimits-missing"),
        pytest.param(
            host(
                Ulimits=[
                    {"Name": "nofile", "Soft": 1024, "Hard": 1024},
                    {"Name": "fsize", "Soft": 10, "Hard": 10},
                    {"Name": "core", "Soft": 1, "Hard": 1},
                ]
            ),
            id="extra-ulimit",
        ),
        pytest.param(
            host(
                Ulimits=[
                    {"Name": "nofile", "Soft": 2048, "Hard": 1024},
                    {"Name": "fsize", "Soft": 10, "Hard": 10},
                ]
            ),
            id="soft-limit-above-hard",
        ),
        pytest.param(host(Tmpfs={}), id="no-scratch"),
        pytest.param(host(Tmpfs={"/etc": "rw,noexec,nosuid,nodev,size=1"}), id="tmpfs-elsewhere"),
        pytest.param(host(Tmpfs={"/scratch": "rw,nosuid,nodev,size=1"}), id="scratch-exec"),
        pytest.param(host(Tmpfs={"/scratch": "rw,noexec,nosuid,nodev"}), id="scratch-no-size"),
        pytest.param(
            host(Tmpfs={"/scratch": "rw,noexec,nosuid,nodev,size=1g"}), id="scratch-size-units"
        ),
        pytest.param(host(Binds=[]), id="no-input"),
        pytest.param(host(Binds="/srv/artifacts/a:/input:ro"), id="binds-not-a-list"),
        pytest.param(host(Binds=["/etc:/input:ro"]), id="bind-outside-artifact-root"),
        pytest.param(host(Binds=["/srv/artifacts:/input:ro"]), id="bind-whole-artifact-root"),
        pytest.param(host(Binds=["/srv/artifacts/../etc:/input:ro"]), id="bind-traversal"),
        pytest.param(host(Binds=["/srv/artifacts-evil/a:/input:ro"]), id="bind-sibling-prefix"),
        pytest.param(host(Binds=["/srv/artifacts/a:/input:rw"]), id="bind-writable"),
        pytest.param(host(Binds=["/srv/artifacts/a:/input"]), id="bind-mode-missing"),
        pytest.param(host(Binds=["/srv/artifacts/a:/other:ro"]), id="bind-wrong-destination"),
        pytest.param(
            host(Binds=["/srv/artifacts/a:/input:ro", "/srv/artifacts/b:/input2:ro"]),
            id="extra-bind",
        ),
        pytest.param(
            host(Binds=["/srv/artifacts/a:/input:ro", OSV_BIND]), id="osv-volume-on-other-image"
        ),
        pytest.param(host(Binds=["/var/run/docker.sock:/input:ro"]), id="docker-socket-as-input"),
        *[
            pytest.param(drop(field), id=f"missing-{field}")
            for field in (
                "Runtime",
                "NetworkMode",
                "ReadonlyRootfs",
                "AutoRemove",
                "CapDrop",
                "SecurityOpt",
                "NanoCpus",
                "Memory",
                "MemorySwap",
                "PidsLimit",
                "LogConfig",
            )
        ],
    ],
)
def test_unsafe_create_request_is_rejected(mutate: Callable[[Body], None]) -> None:
    body = copy.deepcopy(create_body())
    mutate(body)

    with pytest.raises(PolicyViolation):
        validate_create(body, POLICY)


@pytest.mark.parametrize("body", [None, [], "x", {"HostConfig": []}, {"Image": IMAGE}])
def test_malformed_create_body_is_rejected(body: object) -> None:
    with pytest.raises(PolicyViolation):
        validate_create(body, POLICY)


@pytest.mark.parametrize(
    ("method", "target", "action"),
    [
        ("POST", "/containers/create", "create"),
        ("POST", "/v1.47/containers/create", "create"),
        ("POST", "/v1.30/containers/create", "create"),
        ("POST", f"/v1.30/containers/{CONTAINER}/wait?condition=removed", "wait"),
        ("POST", f"/containers/{CONTAINER}/start", "start"),
        ("POST", f"/containers/{CONTAINER}/wait?condition=removed", "wait"),
        ("POST", f"/containers/{CONTAINER}/attach?stream=1&stdout=1", "attach"),
        ("POST", f"/containers/{CONTAINER}/kill?signal=SIGKILL", "kill"),
        ("DELETE", f"/containers/{CONTAINER}?force=1", "remove"),
    ],
)
def test_allowed_docker_calls_are_recognized(method: str, target: str, action: str) -> None:
    assert classify_request(method, target).action == action


@pytest.mark.parametrize(
    ("method", "target"),
    [
        ("GET", "/containers/json"),
        ("GET", "/_ping"),
        ("GET", f"/containers/{CONTAINER}/json"),
        ("GET", f"/containers/{CONTAINER}/logs?stdout=1"),
        ("POST", f"/containers/{CONTAINER}/exec"),
        ("POST", "/exec/abc/start"),
        ("POST", "/images/create?fromImage=evil"),
        ("POST", "/volumes/create"),
        ("POST", "/networks/create"),
        ("POST", "/build"),
        ("POST", f"/containers/{CONTAINER}/restart"),
        ("POST", f"/containers/{CONTAINER}/update"),
        ("POST", "/containers/create?name=x"),
        ("POST", "/containers/not-a-hex-id/start"),
        ("POST", f"/containers/{CONTAINER}/attach?stream=1&stdout=1&stdin=1"),
        ("POST", f"/containers/{CONTAINER}/attach?stream=1&stdout=1&stderr=1"),
        ("POST", f"/containers/{CONTAINER}/attach?stream=1&stdout=1&logs=1"),
        ("POST", f"/containers/{CONTAINER}/attach?stream=1&stream=0&stdout=1"),
        ("POST", f"/containers/{CONTAINER}/kill?signal=SIGHUP"),
        ("DELETE", f"/containers/{CONTAINER}?v=1"),
        ("POST", f"/containers/%2e%2e/{CONTAINER}/start"),
        ("POST", f"/v1.47/../containers/{CONTAINER}/start"),
    ],
)
def test_other_docker_calls_are_denied(method: str, target: str) -> None:
    with pytest.raises(PolicyViolation):
        classify_request(method, target)


@pytest.mark.parametrize("version", ["0.99", "1.0", "1.24", "1.25", "1.29", "01.029"])
@pytest.mark.parametrize("action", ["create", "wait"])
def test_legacy_api_versions_cannot_weaken_container_lifecycle(version: str, action: str) -> None:
    suffix = "create" if action == "create" else f"{CONTAINER}/wait?condition=removed"
    with pytest.raises(PolicyViolation):
        classify_request("POST", f"/v{version}/containers/{suffix}")


def test_load_images_reads_digests_and_finds_the_osv_image(tmp_path: Path) -> None:
    lock = tmp_path / "sandbox-images.lock"
    lock.write_text(json.dumps({"fixture.echo": IMAGE, "osv-scanner": OSV_IMAGE}))

    assert load_images(lock) == (frozenset({IMAGE, OSV_IMAGE}), OSV_IMAGE)


@pytest.mark.parametrize(
    "content",
    ['{"a": "ghcr.io/acme/echo:latest"}', '["sha256:abc"]', '{"a": 1}', "not json"],
)
def test_load_images_refuses_anything_but_digests(tmp_path: Path, content: str) -> None:
    lock = tmp_path / "sandbox-images.lock"
    lock.write_text(content)

    with pytest.raises(ValueError, match="lock"):
        load_images(lock)
