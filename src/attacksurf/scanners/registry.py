"""Explicit plugin registration. Import plugin modules at worker startup, never crawl packages."""

import math
import re

from attacksurf.domain.scanners import Scanner, ScanProfile
from attacksurf.domain.scope import HttpPermission

MAX_TIMEOUT_SECONDS = 240


class ScannerRegistry:
    def __init__(self) -> None:
        self._scanners: dict[str, type[Scanner]] = {}

    def register[T: Scanner](self, scanner: type[T]) -> type[T]:
        if scanner.name in self._scanners:
            raise ValueError(f"duplicate scanner {scanner.name!r}")
        if not re.fullmatch(r"[a-z][a-z0-9_.]{0,99}", scanner.name):
            raise ValueError("invalid scanner name")
        if scanner.queue not in {"passive", "active", "analysis"}:
            raise ValueError("invalid scanner queue")
        if not scanner.asset_types:
            raise ValueError("scanner needs asset types")
        if (
            not math.isfinite(scanner.timeout_seconds)
            or not 0 < scanner.timeout_seconds <= MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("scanner timeout must be between 0 and 240 seconds")
        # Target HTTP is an active check, so it always needs ownership proof. Reject the
        # inconsistent metadata at registration: the gate would refuse every run anyway.
        if scanner.grant.http is HttpPermission.TARGET and not scanner.requires_verification:
            raise ValueError("a target HTTP grant requires requires_verification")
        self._scanners[scanner.name] = scanner
        return scanner

    def get(self, name: str) -> Scanner:
        try:
            return self._scanners[name]()
        except KeyError:
            raise ValueError(f"unknown scanner {name!r}") from None

    def validate(self, profile: ScanProfile) -> None:
        for names in (profile.discover, profile.checks):
            if len(names) != len(set(names)):
                raise ValueError("duplicate scanner in profile stage")
            for name in names:
                # `get` also enforces the full plugin contract (grant, asset types, timeout).
                if self.get(name).queue != "passive":
                    raise ValueError("only passive scanner workers are available")
        if profile.max_discovered_assets is not None and profile.max_discovered_assets < 1:
            raise ValueError("max_discovered_assets must be positive")


registry = ScannerRegistry()
register_scanner = registry.register
