"""The one place the ADR 0016 sandbox is spelled out as a Docker create body.

The proxy accepts only this exact shape (`sandbox_proxy/policy.py: validate_create`), so the
builder takes no free-form options: the image, command and limits come from the catalog, the
mount from the resolved artifact directory, and everything else is fixed. The launcher never
imports `sandbox_proxy`, so the constants below are copies; unit tests keep them in step and
run every body through the real policy.
"""

from pathlib import Path
from typing import Any

from attacksurf.sandbox_launcher.catalog import Analyzer, SandboxLimits

SANDBOX_USER = "65532:65532"
OSV_ANALYZER = "osv-scanner"
OSV_BIND = "attacksurf_osv:/data/osv:ro"

_RUNTIMES = frozenset({"runsc", "runc"})


def build_create_body(analyzer: Analyzer, artifact_dir: Path, runtime: str) -> dict[str, Any]:
    """Docker `POST /containers/create` body for one run of `analyzer` on `artifact_dir`.

    `artifact_dir` is `resolve_artifact`'s result. Raises `ValueError` for a relative path, a
    path with a colon (it could add bind options such as `:rw`), or an unknown runtime;
    messages never echo the value.
    """
    if not artifact_dir.is_absolute():
        raise ValueError("the artifact directory must be an absolute path")
    if ":" in str(artifact_dir):
        raise ValueError("the artifact directory must not contain a colon")
    if runtime not in _RUNTIMES:
        raise ValueError("the runtime is not supported")
    limits = analyzer.spec.limits
    return {
        "Image": analyzer.image,
        "User": SANDBOX_USER,
        "Cmd": list(analyzer.spec.command),
        "AttachStdout": True,
        "HostConfig": {
            "Runtime": runtime,
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "AutoRemove": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "Binds": _binds(analyzer, artifact_dir),
            "Tmpfs": {"/scratch": f"rw,noexec,nosuid,nodev,size={limits.scratch_bytes}"},
            "NanoCpus": limits.nano_cpus,
            "Memory": limits.memory_bytes,
            "MemorySwap": limits.memory_bytes,  # equal to Memory: no swap
            "PidsLimit": limits.pids,
            "Ulimits": _ulimits(limits),
            "LogConfig": {"Type": "none"},  # a log driver would copy tool output to the host
        },
    }


def _binds(analyzer: Analyzer, artifact_dir: Path) -> list[str]:
    binds = [f"{artifact_dir}:/input:ro"]
    if analyzer.spec.name == OSV_ANALYZER:
        binds.append(OSV_BIND)
    return binds


def _ulimits(limits: SandboxLimits) -> list[dict[str, Any]]:
    return [
        {"Name": "nofile", "Soft": limits.open_files, "Hard": limits.open_files},
        {"Name": "fsize", "Soft": limits.file_bytes, "Hard": limits.file_bytes},
    ]
