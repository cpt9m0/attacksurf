"""Map an artifact ID to its directory under the artifact root, or refuse.

The caller only ever supplies an ID; the path is built here. Docker follows symlinks on the host
when it binds a directory, so anything that isn't a real directory directly inside the root is
refused. The check and the bind are separate steps, which is only safe while nothing but the
artifact fetcher can write under the (read-only for the launcher) root.
"""

from pathlib import Path
from uuid import UUID


class ArtifactNotFound(Exception):
    """The artifact isn't there or isn't usable. Never names the path or the ID."""


def resolve_artifact(root: Path, artifact_id: UUID) -> Path:
    """Return `{root}/{artifact_id}`, unresolved, if it is a real directory inside `root`.

    The proxy matches the bind source by string prefix of the artifact root, so the result keeps
    that form instead of the resolved path.
    """
    if not root.is_absolute():
        raise ValueError("the artifact root must be an absolute path")
    candidate = root / str(artifact_id)  # canonical lowercase hyphenated form
    try:
        if candidate.is_symlink() or not candidate.is_dir():
            raise ArtifactNotFound("Artifact not found.")
        if candidate.resolve(strict=True).parent != root.resolve(strict=True):
            raise ArtifactNotFound("Artifact not found.")
    except OSError:
        raise ArtifactNotFound("Artifact not found.") from None
    return candidate
