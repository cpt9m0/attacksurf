"""Profiles list registered scanner names; DNS plugins populate dns_passive in #15-#19."""

from attacksurf.domain.scanners import ScanProfile

PROFILES = {"dns_passive": ScanProfile(name="dns_passive")}
