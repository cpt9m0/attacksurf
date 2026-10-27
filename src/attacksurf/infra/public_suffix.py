"""Public Suffix List classification for scan targets (no network access)."""

from functools import lru_cache
from typing import Any

import tldextract

from attacksurf.domain.scope import PublicSuffix


@lru_cache(maxsize=1)
def _extract() -> Any:
    # Bundled PSL snapshot only: no runtime fetch and no user cache directory, so the list
    # can't change under us mid-scan or phone home from a worker.
    return tldextract.TLDExtract(  # pyright: ignore[reportUnknownMemberType]
        suffix_list_urls=(), cache_dir=None, fallback_to_snapshot=True
    )


def classify(hostname: str) -> PublicSuffix:
    """Where `hostname` sits relative to the PSL. Callers pass normalized (A-label) names."""
    result = _extract()(hostname)
    if not result.suffix:
        return PublicSuffix.NONE
    if not result.domain:
        return PublicSuffix.SUFFIX_ONLY
    return PublicSuffix.ROOT if not result.subdomain else PublicSuffix.SUBDOMAIN
