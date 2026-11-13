"""Offline IP enrichment from an ip2asn-style TSV (no network, no paid API).

The file is public data (`start end asn country org` per line, e.g. iptoasn.com). It is loaded
lazily and cached for the process; a missing or unreadable file disables enrichment instead of
failing scans. Addresses are looked up by binary search over sorted, non-overlapping ranges.
"""

import ipaddress
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

import structlog

from attacksurf.domain.net import IpInfo

MAX_ORG_LENGTH = 200
MIN_FIELDS = 4
ORG_FIELD = 4
log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class _Range:
    start: int
    end: int
    info: IpInfo


class Ip2AsnLookup:
    def __init__(self, path: str | None) -> None:
        self._path = path
        self._lock = Lock()
        self._loaded = False
        self._v4: tuple[_Range, ...] = ()
        self._v6: tuple[_Range, ...] = ()
        self._starts4: tuple[int, ...] = ()
        self._starts6: tuple[int, ...] = ()

    def lookup(self, address: str) -> IpInfo | None:
        self._load()
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return None
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            parsed = parsed.ipv4_mapped
        ranges, starts = (
            (self._v4, self._starts4)
            if isinstance(parsed, ipaddress.IPv4Address)
            else (self._v6, self._starts6)
        )
        if not ranges:
            return None
        value = int(parsed)
        index = bisect_right(starts, value) - 1
        if index < 0:
            return None
        found = ranges[index]
        return found.info if value <= found.end else None

    def _load(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            self._loaded = True
            if not self._path:
                return
            try:
                lines = Path(self._path).read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError):
                log.warning("ip2asn database unavailable; IP enrichment is disabled")
                return
            v4: list[_Range] = []
            v6: list[_Range] = []
            for line in lines:
                record = _parse_line(line)
                if record is None:
                    continue
                (v4 if record[0] else v6).append(record[1])
            self._v4 = tuple(sorted(v4, key=lambda item: item.start))
            self._v6 = tuple(sorted(v6, key=lambda item: item.start))
            self._starts4 = tuple(item.start for item in self._v4)
            self._starts6 = tuple(item.start for item in self._v6)


def _parse_line(line: str) -> tuple[bool, _Range] | None:
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    fields = text.split(maxsplit=ORG_FIELD)
    if len(fields) < MIN_FIELDS:
        return None
    try:
        start = ipaddress.ip_address(fields[0])
        end = ipaddress.ip_address(fields[1])
        asn = int(fields[2])
    except ValueError:
        return None
    if start.version != end.version or int(start) > int(end):
        return None
    country = fields[3].strip()[:8]
    country = None if country in {"", "-"} else country
    org = fields[ORG_FIELD].strip()[:MAX_ORG_LENGTH] if len(fields) > ORG_FIELD else None
    org = None if org in {None, "", "-"} else org
    info = IpInfo(asn=asn, org=org, country=country)
    return isinstance(start, ipaddress.IPv4Address), _Range(int(start), int(end), info)
