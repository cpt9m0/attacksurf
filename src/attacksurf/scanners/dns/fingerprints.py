"""Pinned subdomain-takeover fingerprint dataset (#18).

Vendored from EdOverflow/can-i-take-over-xyz at a pinned commit, transformed to the subset a
scanner can act on mechanically (CC-BY-4.0; see `fingerprints-NOTICE.md` beside this module):
only services the upstream dataset marks vulnerable, each with at least one CNAME pattern and
either an NXDOMAIN signal or an HTTP body/status signature.

Matching is literal substring matching, never regex: the upstream strings are untrusted data,
some contain regex-style artifacts that therefore stay inert, and a signature only counts when
the CNAME already attributes the name to that service.
"""

import json
from dataclasses import dataclass
from functools import cache
from importlib.resources import files


@dataclass(frozen=True)
class Fingerprint:
    """One claimable service: CNAME suffixes plus how a deprovisioned instance shows itself."""

    service: str
    cname: tuple[str, ...]
    fingerprint: str | None = None  # HTTP body signature, when the service resolves
    nxdomain: bool = False  # a deprovisioned target stops resolving at all
    http_status: int | None = None  # signature is the response status, not the body

    def matches(self, hostname: str) -> bool:
        """True when `hostname` is one of this service's CNAME hosts or a name under one."""
        name = hostname.lower().removesuffix(".")
        return any(name == pattern or name.endswith(f".{pattern}") for pattern in self.cname)


class FingerprintError(ValueError):
    """The pinned dataset is corrupt; the scanner fails safely instead of guessing."""


@cache
def load_fingerprints() -> tuple[Fingerprint, ...]:
    """Load and validate the pinned dataset once per process."""
    try:
        raw = (files(__package__) / "fingerprints.json").read_text(encoding="utf-8")
        entries = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FingerprintError("takeover fingerprint dataset is unreadable") from exc
    if not isinstance(entries, list) or not entries:
        raise FingerprintError("takeover fingerprint dataset is empty")
    return tuple(_entry(entry) for entry in entries)


def match_service(fingerprints: tuple[Fingerprint, ...], hostname: str) -> Fingerprint | None:
    """The claimable service `hostname` points at, or None. First dataset match wins."""
    for fingerprint in fingerprints:
        if fingerprint.matches(hostname):
            return fingerprint
    return None


def _entry(entry: object) -> Fingerprint:
    if not isinstance(entry, dict):
        raise FingerprintError("takeover fingerprint entry is not an object")
    service = entry.get("service")
    cname = entry.get("cname")
    fingerprint = entry.get("fingerprint")
    nxdomain = entry.get("nxdomain")
    http_status = entry.get("http_status")
    if not isinstance(service, str) or not service:
        raise FingerprintError("takeover fingerprint entry has no service")
    if (
        not isinstance(cname, list)
        or not cname
        or not all(isinstance(pattern, str) and pattern for pattern in cname)
    ):
        raise FingerprintError("takeover fingerprint entry has no CNAME pattern")
    if fingerprint is not None and not isinstance(fingerprint, str):
        raise FingerprintError("takeover fingerprint entry has a bad fingerprint")
    if not isinstance(nxdomain, bool):
        raise FingerprintError("takeover fingerprint entry has a bad nxdomain flag")
    if http_status is not None and not isinstance(http_status, int):
        raise FingerprintError("takeover fingerprint entry has a bad http status")
    if not nxdomain and not fingerprint and http_status is None:
        raise FingerprintError("takeover fingerprint entry has no detection signal")
    if nxdomain and fingerprint:
        raise FingerprintError("takeover fingerprint entry mixes NXDOMAIN and body signals")
    return Fingerprint(
        service=service,
        cname=tuple(pattern.lower().removesuffix(".") for pattern in cname),
        fingerprint=fingerprint or None,
        nxdomain=nxdomain,
        http_status=http_status,
    )
