"""Artifact IDs resolve only to real directories directly inside the artifact root."""

from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

import pytest

from attacksurf.sandbox_launcher.artifacts import ArtifactNotFound, resolve_artifact
from attacksurf.sandbox_proxy.policy import (
    OSV_BIND,
    SANDBOX_USER,
    SandboxPolicy,
    validate_create,
)

ARTIFACT_ID = UUID("0b6f3c52-7e1d-4a58-9d0f-2c1e8a4b7f90")


def test_resolve_artifact_returns_the_unresolved_directory(tmp_path: Path) -> None:
    (tmp_path / str(ARTIFACT_ID)).mkdir()

    assert resolve_artifact(tmp_path, ARTIFACT_ID) == tmp_path / str(ARTIFACT_ID)


def test_resolve_artifact_rejects_a_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(ArtifactNotFound):
        resolve_artifact(tmp_path, ARTIFACT_ID)


def test_resolve_artifact_rejects_a_regular_file(tmp_path: Path) -> None:
    (tmp_path / str(ARTIFACT_ID)).write_text("not a directory")

    with pytest.raises(ArtifactNotFound):
        resolve_artifact(tmp_path, ARTIFACT_ID)


def test_resolve_artifact_rejects_a_symlink_inside_the_root(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / str(ARTIFACT_ID)).symlink_to(tmp_path / "real", target_is_directory=True)

    with pytest.raises(ArtifactNotFound):
        resolve_artifact(tmp_path, ARTIFACT_ID)


def test_resolve_artifact_rejects_a_symlink_escaping_the_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / str(ARTIFACT_ID)).symlink_to(outside, target_is_directory=True)

    with pytest.raises(ArtifactNotFound):
        resolve_artifact(root, ARTIFACT_ID)


def test_resolve_artifact_accepts_a_root_that_is_itself_a_symlink(tmp_path: Path) -> None:
    real_root = tmp_path / "real-root"
    (real_root / str(ARTIFACT_ID)).mkdir(parents=True)
    link_root = tmp_path / "link-root"
    link_root.symlink_to(real_root, target_is_directory=True)

    assert resolve_artifact(link_root, ARTIFACT_ID) == link_root / str(ARTIFACT_ID)


def test_resolve_artifact_rejects_a_relative_root() -> None:
    with pytest.raises(ValueError, match="absolute"):
        resolve_artifact(Path("artifacts"), ARTIFACT_ID)


def test_resolve_artifact_error_never_names_the_path_or_id(tmp_path: Path) -> None:
    with pytest.raises(ArtifactNotFound) as raised:
        resolve_artifact(tmp_path, ARTIFACT_ID)

    assert str(tmp_path) not in str(raised.value)
    assert str(ARTIFACT_ID) not in str(raised.value)


def test_resolve_artifact_path_satisfies_the_proxy_bind_rule(tmp_path: Path) -> None:
    artifact_id = uuid4()
    (tmp_path / str(artifact_id)).mkdir()
    image = "ghcr.io/acme/echo@sha256:" + "a" * 64
    policy = SandboxPolicy(
        images=frozenset({image}),
        runtimes=frozenset({"runsc"}),
        artifact_root=PurePosixPath(tmp_path),
        osv_image=None,
    )
    source = resolve_artifact(tmp_path, artifact_id)

    validate_create(
        {
            "Image": image,
            "User": SANDBOX_USER,
            "HostConfig": {
                "Runtime": "runsc",
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "AutoRemove": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Binds": [f"{source}:/input:ro"],
                "Tmpfs": {"/scratch": "rw,noexec,nosuid,nodev,size=1024"},
                "NanoCpus": 1_000_000_000,
                "Memory": 1024**3,
                "MemorySwap": 1024**3,
                "PidsLimit": 256,
                "Ulimits": [
                    {"Name": "nofile", "Soft": 1024, "Hard": 1024},
                    {"Name": "fsize", "Soft": 1024, "Hard": 1024},
                ],
                "LogConfig": {"Type": "none"},
            },
        },
        policy,
    )
    assert OSV_BIND not in str(source)
