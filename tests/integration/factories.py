"""Row factories for DB tests."""

from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Org, Scan
from attacksurf.services.assets import record_asset


def make_scan(session: Session, name: str = "acme") -> Scan:
    org = Org(name=name, slug=name)
    session.add(org)
    session.flush()
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
