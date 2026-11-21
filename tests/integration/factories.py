"""Row factories for DB tests."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.findings import (
    Confidence,
    EvidenceKind,
    FindingStatus,
    Severity,
    finding_fingerprint,
)
from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Evidence, Finding, Org, Scan
from attacksurf.services.assets import record_asset

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def make_org(session: Session, name: str = "acme") -> Org:
    org = Org(name=name, slug=name)
    session.add(org)
    session.flush()
    return org


def make_scan(session: Session, name: str = "acme") -> Scan:
    org = make_org(session, name)
    root: Asset = record_asset(
        session, org.id, AssetType.DOMAIN, f"{name}.example", source=AssetSource.USER
    )
    scan = Scan(
        org_id=org.id,
        root_asset_id=root.id,
        profile="dns_passive",
        status=ScanStatus.RUNNING,
        triggered_by=ScanTrigger.USER,
    )
    session.add(scan)
    session.flush()
    return scan


def make_finding(
    session: Session,
    org_id: UUID,
    asset_id: UUID,
    *,
    rule_id: str = "dns.email.dmarc_missing",
    location: str = "",
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.OPEN,
    title: str = "No DMARC record",
    description: str = "The domain publishes no DMARC policy.",
    first_seen: datetime = T0,
    last_seen: datetime = T0,
    fixed_at: datetime | None = None,
    scanner: str | None = "dns.email",
    evidence: tuple[tuple[EvidenceKind, dict[str, object]], ...] = (),
) -> Finding:
    finding = Finding(
        org_id=org_id,
        asset_id=asset_id,
        rule_id=rule_id,
        fingerprint=finding_fingerprint(org_id, asset_id, rule_id, location),
        location=location,
        scanner=scanner,
        title=title,
        description=description,
        severity=severity,
        confidence=Confidence.HIGH,
        status=status,
        first_seen=first_seen,
        last_seen=last_seen,
        fixed_at=(fixed_at or first_seen) if status is FindingStatus.FIXED else None,
    )
    session.add(finding)
    session.flush()
    for kind, data in evidence:
        session.add(
            Evidence(
                org_id=org_id,
                finding_id=finding.id,
                kind=kind,
                data=data,
                captured_at=last_seen,
            )
        )
    session.flush()
    return finding
