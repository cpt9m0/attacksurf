"""Normalize and persist a scanner result inside the caller's transaction (no commit)."""

import hashlib
import json
from collections.abc import Mapping
from uuid import UUID, uuid5

from sqlalchemy import case, func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from attacksurf.domain.assets import AssetNotFound, AssetSource, AssetType
from attacksurf.domain.events import FindingCreated
from attacksurf.domain.findings import finding_fingerprint
from attacksurf.domain.ids import uuid7
from attacksurf.domain.rules import RULES, Rule, get_rule
from attacksurf.domain.scanners import AssetRef, RawFinding, ScanOutput
from attacksurf.infra.db.models import Asset, Evidence, Finding, Scan
from attacksurf.infra.db.tenancy import get_scoped
from attacksurf.services.assets import record_asset, record_relation


def persist_scan_output(
    session: Session,
    scan: Scan,
    asset_id: UUID,
    output: ScanOutput,
    *,
    catalog: Mapping[str, Rule] = RULES,
) -> list[FindingCreated]:
    """Upsert observed data; caller commits then dispatches returned events.

    References may name only the input or explicitly discovered assets. Plugins cannot choose
    an org, a row ID, ownership, lifecycle state, or human-facing rule text.
    """
    asset = get_scoped(session, Asset, asset_id, scan.org_id)
    if asset is None:
        raise AssetNotFound("Asset not found.")
    refs = {(asset.type, asset.value): asset.id}
    # Validate references/catalog before doing writes; malformed plugins fail their whole job.
    allowed = set(refs) | {(a.type, a.value) for a in output.assets}
    for relation in output.relations:
        _resolve(allowed, relation.from_asset)
        _resolve(allowed, relation.to_asset)
    for raw in output.findings:
        get_rule(raw.rule_id, catalog)
        if raw.asset:
            _resolve(allowed, raw.asset)
    seen = scan.started_at or scan.created_at
    for discovered in output.assets:
        row = record_asset(
            session,
            scan.org_id,
            discovered.type,
            discovered.value,
            source=AssetSource.DISCOVERED,
            parent_id=scan.root_asset_id,
            seen_at=seen,
        )
        refs[(row.type, row.value)] = row.id
    for relation in output.relations:
        record_relation(
            session,
            scan.org_id,
            refs[(relation.from_asset.type, relation.from_asset.value)],
            refs[(relation.to_asset.type, relation.to_asset.value)],
            relation.kind,
            seen_at=seen,
        )
    events: list[FindingCreated] = []
    for raw in output.findings:
        target_id = refs[(raw.asset.type, raw.asset.value)] if raw.asset else asset_id
        finding_id, created = _upsert_finding(
            session, scan, target_id, raw, get_rule(raw.rule_id, catalog)
        )
        if created:
            events.append(FindingCreated(scan.org_id, scan.id, finding_id))
        for evidence in raw.evidence:
            data = json.dumps(evidence.data, sort_keys=True, ensure_ascii=False, allow_nan=False)
            digest = hashlib.sha256(f"{finding_id}:{evidence.kind}:{data}".encode()).hexdigest()
            # Replay of a task/scan cannot append the same evidence again. No schema change.
            session.execute(
                insert(Evidence)
                .values(
                    id=uuid5(scan.id, digest),
                    org_id=scan.org_id,
                    finding_id=finding_id,
                    kind=evidence.kind,
                    data=evidence.data,
                    captured_at=seen,
                )
                .on_conflict_do_nothing(index_elements=[Evidence.id])
            )
    return events


def _resolve(allowed: set[tuple[AssetType, str]], ref: AssetRef) -> None:
    if (ref.type, ref.value) not in allowed:
        raise ValueError("unknown asset reference")


def _upsert_finding(
    session: Session, scan: Scan, asset_id: UUID, raw: RawFinding, rule: Rule
) -> tuple[UUID, bool]:
    seen = scan.started_at or scan.created_at
    stmt = insert(Finding).values(
        id=uuid7(),
        org_id=scan.org_id,
        asset_id=asset_id,
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
        rule_id=rule.id,
        fingerprint=finding_fingerprint(scan.org_id, asset_id, rule.id, raw.location),
        location=raw.location,
        title=rule.title,
        description=rule.description,
        severity=raw.severity or rule.default_severity,
        confidence=raw.confidence,
        first_seen=seen,
        last_seen=seen,
        remediation=rule.render_remediation(raw.remediation_context),
        references=list(rule.references),
    )
    created_id = session.scalar(
        stmt.on_conflict_do_nothing(index_elements=[Finding.org_id, Finding.fingerprint]).returning(
            Finding.id
        )
    )
    if created_id is not None:
        return created_id, True
    new = stmt.excluded
    # Equal timestamps still need a deterministic order: replay must not move scan pointers.
    newer = (new.last_seen > Finding.last_seen) | (
        (new.last_seen == Finding.last_seen)
        & (
            Finding.last_seen_scan_id.is_(None)
            | (new.last_seen_scan_id >= Finding.last_seen_scan_id)
        )
    )
    earlier = (new.first_seen < Finding.first_seen) | (
        (new.first_seen == Finding.first_seen)
        & (
            Finding.first_seen_scan_id.is_(None)
            | (new.first_seen_scan_id < Finding.first_seen_scan_id)
        )
    )
    updates: dict[str, ColumnElement] = {
        name: case((newer, getattr(new, name)), else_=getattr(Finding, name))
        for name in (
            "title",
            "description",
            "severity",
            "confidence",
            "remediation",
            "references",
            "last_seen_scan_id",
        )
    }
    updates.update(
        first_seen=func.least(Finding.first_seen, new.first_seen),
        first_seen_scan_id=case(
            (earlier, new.first_seen_scan_id),
            else_=Finding.first_seen_scan_id,
        ),
        last_seen=func.greatest(Finding.last_seen, new.last_seen),
        updated_at=func.now(),
    )
    finding = session.scalars(
        stmt.on_conflict_do_update(
            index_elements=[Finding.org_id, Finding.fingerprint],
            set_=updates,
        ).returning(Finding),
        execution_options={"populate_existing": True},
    ).one()
    return finding.id, False
