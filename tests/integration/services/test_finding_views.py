"""Finding list, detail, dashboard and export queries against real Postgres."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.findings import (
    EvidenceKind,
    FindingNotFound,
    FindingStatus,
    Severity,
)
from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Org, Scan
from attacksurf.services import finding_views
from attacksurf.services.assets import record_asset
from attacksurf.services.finding_views import FindingFilter, FindingSort, FindingStatusFilter
from tests.integration.factories import T0, make_finding, make_org


@dataclass
class Case:
    org: Org
    root: Asset
    www: Asset
    other: Asset


@pytest.fixture
def acme(db_session: Session) -> Case:
    org = make_org(db_session)
    root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )
    www = record_asset(
        db_session,
        org.id,
        AssetType.SUBDOMAIN,
        "www.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
        seen_at=T0,
    )
    other = record_asset(
        db_session, org.id, AssetType.DOMAIN, "other.example", source=AssetSource.USER
    )
    return Case(org, root, www, other)


def _scan(
    session: Session,
    org_id: UUID,
    root_id: UUID,
    *,
    status: ScanStatus = ScanStatus.COMPLETED,
    created_at: datetime = T0,
    finished_at: datetime | None = T0,
) -> Scan:
    scan = Scan(
        org_id=org_id,
        root_asset_id=root_id,
        profile="dns_passive",
        status=status,
        triggered_by=ScanTrigger.USER,
        created_at=created_at,
        finished_at=finished_at,
    )
    session.add(scan)
    session.flush()
    return scan


def _titles(page: finding_views.FindingPage) -> list[str]:
    return [row.title for row in page.items]


def test_list_findings_defaults_to_active_and_worst_first(db_session: Session, acme: Case) -> None:
    make_finding(
        db_session, acme.org.id, acme.root.id, title="critical", severity=Severity.CRITICAL
    )
    make_finding(
        db_session, acme.org.id, acme.www.id, title="low", severity=Severity.LOW, location="www"
    )
    make_finding(
        db_session,
        acme.org.id,
        acme.www.id,
        title="fixed",
        status=FindingStatus.FIXED,
        location="fixed",
    )

    page = finding_views.list_findings(db_session, acme.org.id, FindingFilter())

    assert _titles(page) == ["critical", "low"]
    assert page.total == 2


def test_list_findings_filters_combine(db_session: Session, acme: Case) -> None:
    make_finding(
        db_session,
        acme.org.id,
        acme.www.id,
        title="dmarc",
        rule_id="dns.email.dmarc_missing",
        severity=Severity.HIGH,
    )
    make_finding(
        db_session,
        acme.org.id,
        acme.root.id,
        title="spf",
        rule_id="dns.email.spf_missing",
        severity=Severity.MEDIUM,
    )

    severity = finding_views.list_findings(
        db_session, acme.org.id, FindingFilter(severity=Severity.MEDIUM)
    )
    rule = finding_views.list_findings(
        db_session, acme.org.id, FindingFilter(rule_id="dns.email.spf_missing")
    )
    asset = finding_views.list_findings(db_session, acme.org.id, FindingFilter(asset="www."))
    root = finding_views.list_findings(db_session, acme.org.id, FindingFilter(root_id=acme.www.id))

    assert _titles(severity) == ["spf"]
    assert _titles(rule) == ["spf"]
    assert _titles(asset) == ["dmarc"]
    assert _titles(root) == ["dmarc"]  # the asset itself, and anything discovered under it


def test_list_findings_root_filter_includes_discovered_assets(
    db_session: Session, acme: Case
) -> None:
    make_finding(db_session, acme.org.id, acme.root.id, title="on root", location="a")
    make_finding(db_session, acme.org.id, acme.www.id, title="on www", location="b")
    make_finding(db_session, acme.org.id, acme.other.id, title="on other", location="c")

    page = finding_views.list_findings(db_session, acme.org.id, FindingFilter(root_id=acme.root.id))

    # Same severity and last_seen, so only the UUIDv7 ids order these two, and ids made in the
    # same millisecond sort randomly: this test is about which findings match, not their order.
    assert sorted(_titles(page)) == ["on root", "on www"]


def test_list_findings_status_filter(db_session: Session, acme: Case) -> None:
    make_finding(db_session, acme.org.id, acme.root.id, title="open", location="a")
    make_finding(
        db_session,
        acme.org.id,
        acme.root.id,
        title="fixed",
        status=FindingStatus.FIXED,
        location="b",
    )
    make_finding(
        db_session,
        acme.org.id,
        acme.root.id,
        title="accepted",
        status=FindingStatus.ACCEPTED_RISK,
        location="c",
    )

    fixed = finding_views.list_findings(
        db_session, acme.org.id, FindingFilter(status=FindingStatusFilter.FIXED)
    )
    every = finding_views.list_findings(
        db_session, acme.org.id, FindingFilter(status=FindingStatusFilter.ALL)
    )

    assert _titles(fixed) == ["fixed"]
    assert len(every.items) == 3


def test_list_findings_new_since_last_scan_uses_the_scan_that_first_saw_it(
    db_session: Session, acme: Case
) -> None:
    older = _scan(
        db_session,
        acme.org.id,
        acme.root.id,
        created_at=T0,
        finished_at=T0 + timedelta(minutes=5),
    )
    newer = _scan(
        db_session,
        acme.org.id,
        acme.root.id,
        created_at=T0 + timedelta(hours=1),
        finished_at=T0 + timedelta(hours=1, minutes=5),
    )
    fresh = make_finding(db_session, acme.org.id, acme.root.id, title="fresh", location="a")
    fresh.first_seen_scan_id = newer.id
    stale = make_finding(db_session, acme.org.id, acme.root.id, title="stale", location="b")
    stale.first_seen_scan_id = older.id
    # The mutable pointer moved on; the filter must not be fooled by it.
    stale.last_seen_scan_id = newer.id
    db_session.flush()

    page = finding_views.list_findings(
        db_session, acme.org.id, FindingFilter(new_since_last_scan=True)
    )

    assert _titles(page) == ["fresh"]
    assert page.latest_scan_id == newer.id


def test_list_findings_new_since_last_scan_scopes_to_the_root(
    db_session: Session, acme: Case
) -> None:
    _scan(
        db_session,
        acme.org.id,
        acme.root.id,
        created_at=T0,
        finished_at=T0 + timedelta(minutes=5),
    )
    other_scan = _scan(
        db_session,
        acme.org.id,
        acme.other.id,
        created_at=T0 + timedelta(hours=2),
        finished_at=T0 + timedelta(hours=2, minutes=5),
    )
    make_finding(db_session, acme.org.id, acme.root.id, title="root finding", location="a")

    page = finding_views.list_findings(
        db_session,
        acme.org.id,
        FindingFilter(root_id=acme.root.id, new_since_last_scan=True),
    )

    assert page.items == ()
    assert page.latest_scan_id != other_scan.id


def test_list_findings_without_a_completed_scan_is_empty(db_session: Session, acme: Case) -> None:
    make_finding(db_session, acme.org.id, acme.root.id, title="open")

    page = finding_views.list_findings(
        db_session, acme.org.id, FindingFilter(new_since_last_scan=True)
    )

    assert page.items == ()
    assert page.total == 0


def test_list_findings_sorts_by_last_seen(db_session: Session, acme: Case) -> None:
    make_finding(
        db_session,
        acme.org.id,
        acme.root.id,
        title="old",
        location="a",
        first_seen=T0 - timedelta(days=3),
        last_seen=T0 - timedelta(days=2),
    )
    make_finding(
        db_session,
        acme.org.id,
        acme.root.id,
        title="new",
        location="b",
        last_seen=T0,
    )

    page = finding_views.list_findings(
        db_session, acme.org.id, FindingFilter(sort=FindingSort.LAST_SEEN)
    )

    assert _titles(page) == ["new", "old"]


def test_list_findings_paginates_and_clamps_the_page(
    db_session: Session, acme: Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(finding_views, "PAGE_SIZE", 2)
    for index in range(3):
        make_finding(db_session, acme.org.id, acme.root.id, title=f"f{index}", location=str(index))

    first = finding_views.list_findings(db_session, acme.org.id, FindingFilter())
    last = finding_views.list_findings(db_session, acme.org.id, FindingFilter(), page=99)

    assert len(first.items) == 2
    assert first.pages == 2
    assert len(last.items) == 1
    assert last.page == 2


def test_get_finding_detail_normalizes_evidence(db_session: Session, acme: Case) -> None:
    finding = make_finding(
        db_session,
        acme.org.id,
        acme.www.id,
        title="TXT payload",
        evidence=(
            (
                EvidenceKind.DNS_RECORD,
                {
                    "record": "TXT",
                    "name": "www.example.com",
                    "values": ['v=spf1 "><img src=x onerror=alert(1)>'],
                },
            ),
            (
                EvidenceKind.HTTP_RESPONSE,
                {
                    "url": "https://www.example.com/",
                    "status_code": 200,
                    "body_snippet": "<html>hello</html>",
                },
            ),
            (EvidenceKind.RAW, {"source": "rdap", "statuses": ["active"]}),
        ),
    )

    detail = finding_views.get_finding_detail(db_session, acme.org.id, finding.id)

    assert detail.finding.id == finding.id
    assert detail.evidence_total == 3
    by_kind = {row.kind: row for row in detail.evidence}
    dns = by_kind[EvidenceKind.DNS_RECORD]
    http = by_kind[EvidenceKind.HTTP_RESPONSE]
    raw = by_kind[EvidenceKind.RAW]
    assert dns.title == "TXT record"
    assert dns.fields[0].label == "Name"
    assert dns.body is not None
    assert "onerror" in dns.body
    assert http.title == "HTTP response"
    assert {field.label for field in http.fields} == {"URL", "Status"}
    assert http.body == "<html>hello</html>"
    assert raw.title == "Raw evidence"
    assert raw.body is not None
    assert '"source": "rdap"' in raw.body


def test_get_finding_detail_caps_evidence(
    db_session: Session, acme: Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(finding_views, "MAX_EVIDENCE", 1)
    finding = make_finding(
        db_session,
        acme.org.id,
        acme.root.id,
        evidence=(
            (EvidenceKind.RAW, {"index": 1}),
            (EvidenceKind.RAW, {"index": 2}),
        ),
    )

    detail = finding_views.get_finding_detail(db_session, acme.org.id, finding.id)

    assert len(detail.evidence) == 1
    assert detail.evidence_total == 2


def test_get_finding_detail_hides_other_orgs_findings(db_session: Session, acme: Case) -> None:
    finding = make_finding(db_session, acme.org.id, acme.root.id)
    other = make_org(db_session, "globex")

    with pytest.raises(FindingNotFound):
        finding_views.get_finding_detail(db_session, other.id, finding.id)


def test_dashboard_summarizes_open_findings_assets_and_last_scans(
    db_session: Session, acme: Case
) -> None:
    _scan(
        db_session,
        acme.org.id,
        acme.root.id,
        created_at=T0,
        finished_at=T0 + timedelta(minutes=1),
    )
    make_finding(db_session, acme.org.id, acme.root.id, severity=Severity.CRITICAL, title="c")
    make_finding(
        db_session,
        acme.org.id,
        acme.www.id,
        severity=Severity.LOW,
        title="l",
        location="low",
        first_seen=T0 + timedelta(days=1),
        last_seen=T0 + timedelta(days=1),
    )
    make_finding(
        db_session,
        acme.org.id,
        acme.www.id,
        title="fixed",
        status=FindingStatus.FIXED,
        location="fixed",
    )

    data = finding_views.get_dashboard(db_session, acme.org.id)

    assert data.open_findings == 2
    assert [(item.severity, item.count) for item in data.by_severity] == [
        (Severity.CRITICAL, 1),
        (Severity.HIGH, 0),
        (Severity.MEDIUM, 0),
        (Severity.LOW, 1),
        (Severity.INFO, 0),
    ]
    assert [row.title for row in data.newest] == ["l", "c"]
    assert data.active_assets == 3
    roots = {row.root_value: row for row in data.roots}
    assert roots["example.com"].scan_status is ScanStatus.COMPLETED
    assert roots["other.example"].scan_id is None


def test_export_findings_reports_truncation(
    db_session: Session, acme: Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(finding_views, "EXPORT_LIMIT", 1)
    make_finding(db_session, acme.org.id, acme.root.id, title="a", location="a")
    make_finding(db_session, acme.org.id, acme.www.id, title="b", location="b")

    export = finding_views.export_findings(db_session, acme.org.id, FindingFilter())

    assert len(export.items) == 1
    assert export.truncated is True
