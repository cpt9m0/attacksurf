"""Offline ip2asn parsing: ranges, IPv6, malformed lines and a missing database."""

from pathlib import Path

from attacksurf.domain.net import IpInfo
from attacksurf.infra.ip_intel import Ip2AsnLookup

SAMPLE = """\
# start end asn country org
1.0.0.0 1.0.0.255 13335 US CLOUDFLARENET
1.0.1.0 1.0.1.255 64512 US EXAMPLE ORG WITH SPACES
2001:db8:: 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff 64496 NL EXAMPLE-V6
bad line
1.0.2.0 1.0.2.255 nope US BROKEN
1.0.3.0 1.0.2.255 64513 US REVERSED
"""


def _lookup(tmp_path: Path) -> Ip2AsnLookup:
    path = tmp_path / "ip2asn.tsv"
    path.write_text(SAMPLE)
    return Ip2AsnLookup(str(path))


def test_lookup_returns_the_matching_range(tmp_path: Path) -> None:
    lookup = _lookup(tmp_path)

    assert lookup.lookup("1.0.0.42") == IpInfo(asn=13335, org="CLOUDFLARENET", country="US")


def test_lookup_keeps_spaces_in_the_organisation(tmp_path: Path) -> None:
    assert _lookup(tmp_path).lookup("1.0.1.1") == IpInfo(
        asn=64512, org="EXAMPLE ORG WITH SPACES", country="US"
    )


def test_lookup_handles_ipv6_ranges(tmp_path: Path) -> None:
    assert _lookup(tmp_path).lookup("2001:db8::1") == IpInfo(
        asn=64496, org="EXAMPLE-V6", country="NL"
    )


def test_lookup_returns_none_outside_every_range(tmp_path: Path) -> None:
    assert _lookup(tmp_path).lookup("192.0.2.1") is None


def test_lookup_accepts_an_ipv4_mapped_address(tmp_path: Path) -> None:
    assert _lookup(tmp_path).lookup("::ffff:1.0.0.1") == IpInfo(
        asn=13335, org="CLOUDFLARENET", country="US"
    )


def test_lookup_ignores_malformed_lines(tmp_path: Path) -> None:
    lookup = _lookup(tmp_path)

    assert lookup.lookup("1.0.2.1") is None
    assert lookup.lookup("1.0.3.1") is None


def test_missing_or_unset_database_disables_enrichment(tmp_path: Path) -> None:
    assert Ip2AsnLookup(None).lookup("1.0.0.1") is None
    assert Ip2AsnLookup(str(tmp_path / "missing.tsv")).lookup("1.0.0.1") is None


def test_invalid_address_is_not_an_error(tmp_path: Path) -> None:
    assert _lookup(tmp_path).lookup("not-an-address") is None
