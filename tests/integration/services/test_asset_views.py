"""Asset list and detail queries."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetNotFound, AssetSource, AssetType, RelationKind
from attacksurf.domain.findings import (
    Confidence,
    FindingStatus,
    Severity,
    finding_fingerprint,
)
from attacksurf.domain.ids import uuid7
from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Finding, Org, Scan
from attacksurf.services import asset_views
from attacksurf.services.asset_views import AssetFilter, AssetStatus
from attacksurf.services.assets import archive_root_domain, record_asset, record_relation

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


@dataclass
class Tree:
    org: Org
    root: Asset
    www: Asset
    ip: Asset


def _org(session: Session, slug: str) -> Org:
    org = Org(name=slug, slug=slug)
    session.add(org)
    session.flush()
    return org


def _discovered(session: Session, org: Org, root: Asset, kind: AssetType, value: str) -> Asset:
    return record_asset(
        session, org.id, kind, value, source=AssetSource.DISCOVERED, parent_id=root.id, seen_at=T0
    )


def _tree(session: Session, slug: str = "acme", domain: str = "example.com") -> Tree:
    org = _org(session, slug)
    root = record_asset(session, org.id, AssetType.DOMAIN, domain, source=AssetSource.USER)
    www = _discovered(session, org, root, AssetType.SUBDOMAIN, f"www.{domain}")
    ip = _discovered(session, org, root, AssetType.IP, "192.0.2.10")
    return Tree(org, root, www, ip)


def _finding(
    session: Session,
    asset: Asset,
    severity: Severity,
    status: FindingStatus = FindingStatus.OPEN,
    rule_id: str = "dns.email.dmarc_missing",
) -> Finding:
    finding = Finding(
        org_id=asset.org_id,
        asset_id=asset.id,
        rule_id=rule_id,
        fingerprint=finding_fingerprint(asset.org_id, asset.id, rule_id),
        title="No DMARC record",
        description="The domain publishes no DMARC policy.",
        severity=severity,
        confidence=Confidence.HIGH,
        status=status,
        fixed_at=T0 if status is FindingStatus.FIXED else None,
        first_seen=T0,
        last_seen=T0,
    )
    session.add(finding)
    session.flush()
    return finding


def _values(page: asset_views.AssetPage) -> list[str]:
    return [row.value for row in page.items]


@pytest.fixture
def acme(db_session: Session) -> Tree:
    return _tree(db_session)


def test_list_groups_each_root_with_its_discovered_assets(db_session: Session, acme: Tree) -> None:
    other = record_asset(
        db_session, acme.org.id, AssetType.DOMAIN, "aaa.example", source=AssetSource.USER
    )

    page = asset_views.list_assets(db_session, acme.org.id, AssetFilter())

    assert _values(page) == [
        "aaa.example",
        "example.com",
        "192.0.2.10",
        "www.example.com",
    ]
    assert page.items[0].id == other.id
    assert (page.page, page.pages, page.total) == (1, 1, 4)
    www = page.items[3]
    assert (www.root_id, www.root_value, www.source) == (acme.root.id, "example.com", "discovered")


def test_list_never_includes_another_orgs_assets(db_session: Session, acme: Tree) -> None:
    globex = _tree(db_session, "globex", "globex.com")

    page = asset_views.list_assets(db_session, acme.org.id, AssetFilter())

    assert "globex.com" not in _values(page)
    assert all(row.id not in {globex.root.id, globex.www.id} for row in page.items)


@pytest.mark.parametrize(
    ("flt", "expected"),
    [
        (AssetFilter(type=AssetType.IP), ["192.0.2.10"]),
        (AssetFilter(q="WWW"), ["www.example.com"]),
        (AssetFilter(q="example"), ["example.com", "www.example.com"]),
    ],
)
def test_list_filters_by_type_and_search(
    db_session: Session, acme: Tree, flt: AssetFilter, expected: list[str]
) -> None:
    assert _values(asset_views.list_assets(db_session, acme.org.id, flt)) == expected


def test_search_treats_like_wildcards_literally(db_session: Session, acme: Tree) -> None:
    _discovered(db_session, acme.org, acme.root, AssetType.URL, "https://example.com/a_b%25c")

    def search(q: str) -> list[str]:
        return _values(asset_views.list_assets(db_session, acme.org.id, AssetFilter(q=q)))

    assert search("%") == ["https://example.com/a_b%25c"]
    assert search("_b%") == ["https://example.com/a_b%25c"]
    assert search("w_w") == []
    assert search("\\") == []


def test_list_filters_by_root(db_session: Session, acme: Tree) -> None:
    other = record_asset(
        db_session, acme.org.id, AssetType.DOMAIN, "example.org", source=AssetSource.USER
    )
    _discovered(db_session, acme.org, other, AssetType.SUBDOMAIN, "www.example.org")

    page = asset_views.list_assets(db_session, acme.org.id, AssetFilter(root_id=other.id))

    assert _values(page) == ["example.org", "www.example.org"]


def test_list_filters_by_tag(db_session: Session, acme: Tree) -> None:
    acme.www.tags = ["prod", "web"]
    db_session.flush()

    page = asset_views.list_assets(db_session, acme.org.id, AssetFilter(tag="prod"))

    assert _values(page) == ["www.example.com"]
    assert page.items[0].tags == ("prod", "web")


def test_list_shows_active_assets_unless_asked_for_archived(
    db_session: Session, acme: Tree
) -> None:
    other = record_asset(
        db_session, acme.org.id, AssetType.DOMAIN, "example.org", source=AssetSource.USER
    )
    archive_root_domain(db_session, acme.org.id, acme.root.id, actor_id=None)

    def listed(status: AssetStatus) -> list[str]:
        flt = AssetFilter(status=status)
        return _values(asset_views.list_assets(db_session, acme.org.id, flt))

    assert listed(AssetStatus.ACTIVE) == [other.value]
    assert listed(AssetStatus.ARCHIVED) == ["example.com", "192.0.2.10", "www.example.com"]
    assert len(listed(AssetStatus.ALL)) == 4


def test_list_paginates_and_clamps_the_page(
    db_session: Session, acme: Tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(asset_views, "PAGE_SIZE", 2)

    first = asset_views.list_assets(db_session, acme.org.id, AssetFilter(), page=1)
    last = asset_views.list_assets(db_session, acme.org.id, AssetFilter(), page=99)
    low = asset_views.list_assets(db_session, acme.org.id, AssetFilter(), page=0)

    assert (_values(first), first.pages, first.total) == (["example.com", "192.0.2.10"], 2, 3)
    assert (_values(last), last.page) == (["www.example.com"], 2)
    assert low.page == 1


def test_empty_list_has_one_page(db_session: Session) -> None:
    org = _org(db_session, "empty")

    page = asset_views.list_assets(db_session, org.id, AssetFilter())

    assert (page.items, page.page, page.pages, page.total) == ((), 1, 1, 0)


def test_open_finding_stats_ignore_closed_findings(db_session: Session, acme: Tree) -> None:
    _finding(db_session, acme.root, Severity.MEDIUM)
    _finding(db_session, acme.root, Severity.LOW, rule_id="dns.caa.missing")
    _finding(db_session, acme.root, Severity.CRITICAL, FindingStatus.FIXED, "dns.spf.missing")
    _finding(db_session, acme.www, Severity.HIGH, FindingStatus.ACCEPTED_RISK)

    rows = {
        r.value: r for r in asset_views.list_assets(db_session, acme.org.id, AssetFilter()).items
    }

    assert (rows["example.com"].open_findings, rows["example.com"].max_severity) == (2, "medium")
    assert (rows["www.example.com"].open_findings, rows["www.example.com"].max_severity) == (
        0,
        None,
    )


def test_detail_has_relations_in_both_directions(db_session: Session, acme: Tree) -> None:
    cdn = _discovered(db_session, acme.org, acme.root, AssetType.SUBDOMAIN, "cdn.example.com")
    record_relation(db_session, acme.org.id, acme.www.id, cdn.id, RelationKind.CNAME_TO, seen_at=T0)
    record_relation(db_session, acme.org.id, cdn.id, acme.ip.id, RelationKind.RESOLVES_TO)

    detail = asset_views.get_asset_detail(db_session, acme.org.id, cdn.id)

    assert detail.asset.value == "cdn.example.com"
    assert [(r.kind, r.peer_value, r.peer_type) for r in detail.outgoing] == [
        ("resolves_to", "192.0.2.10", "ip")
    ]
    assert [(r.kind, r.peer_id, r.first_seen) for r in detail.incoming] == [
        ("cname_to", acme.www.id, T0)
    ]
    assert detail.discovered == 0


def test_root_detail_counts_discovered_assets(db_session: Session, acme: Tree) -> None:
    detail = asset_views.get_asset_detail(db_session, acme.org.id, acme.root.id)

    assert (detail.asset.root_id, detail.discovered) == (None, 2)


def test_detail_of_another_orgs_asset_is_not_found(db_session: Session, acme: Tree) -> None:
    globex = _tree(db_session, "globex", "globex.com")

    for lookup in (
        asset_views.get_asset_detail,
        asset_views.list_asset_findings,
        asset_views.list_asset_scans,
    ):
        with pytest.raises(AssetNotFound):
            lookup(db_session, acme.org.id, globex.root.id)
    with pytest.raises(AssetNotFound):
        asset_views.get_asset(db_session, acme.org.id, uuid7())


def test_asset_findings_list_open_worst_first(db_session: Session, acme: Tree) -> None:
    _finding(db_session, acme.root, Severity.CRITICAL, FindingStatus.FIXED, "dns.spf.missing")
    _finding(db_session, acme.root, Severity.LOW, rule_id="dns.caa.missing")
    _finding(db_session, acme.root, Severity.HIGH)
    _finding(db_session, acme.www, Severity.MEDIUM)

    findings = asset_views.list_asset_findings(db_session, acme.org.id, acme.root.id)

    assert [(f.rule_id, f.status) for f in findings] == [
        ("dns.email.dmarc_missing", "open"),
        ("dns.caa.missing", "open"),
        ("dns.spf.missing", "fixed"),
    ]


def test_asset_scans_come_from_its_root_newest_first(db_session: Session, acme: Tree) -> None:
    def scan(created: datetime) -> Scan:
        row = Scan(
            org_id=acme.org.id,
            root_asset_id=acme.root.id,
            profile="dns_passive",
            status=ScanStatus.COMPLETED,
            triggered_by=ScanTrigger.USER,
            created_at=created,
        )
        db_session.add(row)
        db_session.flush()
        return row

    old, new = scan(T0), scan(T0 + timedelta(days=1))

    from_child = asset_views.list_asset_scans(db_session, acme.org.id, acme.www.id)
    from_root = asset_views.list_asset_scans(db_session, acme.org.id, acme.root.id)

    assert [s.id for s in from_child] == [new.id, old.id]
    assert from_root == from_child
    assert from_root[0].profile == "dns_passive"


def test_root_options_list_root_domains_only(db_session: Session, acme: Tree) -> None:
    archive_root_domain(db_session, acme.org.id, acme.root.id, actor_id=None)
    other = record_asset(
        db_session, acme.org.id, AssetType.DOMAIN, "example.org", source=AssetSource.USER
    )

    options = asset_views.list_root_domains(db_session, acme.org.id)

    assert [(o.id, o.value, o.is_active) for o in options] == [
        (acme.root.id, "example.com", False),
        (other.id, "example.org", True),
    ]
