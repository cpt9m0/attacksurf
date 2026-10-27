"""Normalize and persist a scanner result inside the caller's transaction (no commit)."""

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from uuid import UUID, uuid5

from sqlalchemy import case, func, tuple_
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
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.services.assets import record_asset, record_relation


def persist_scan_output(
    session: Session,
    scan: Scan,
    asset_id: UUID,
    output: ScanOutput,
    *,
    catalog: Mapping[str, Rule] = RULES,
    discovered_limit: int | None = None,
) -> list[FindingCreated]:
    """Upsert observed data; caller commits then dispatches returned events.

    References may name only the input or explicitly discovered assets. Plugins cannot choose
    an org, a row ID, ownership, lifecycle state, or human-facing rule text. `discovered_limit`
    (from the scan profile) caps what one root can add per run: a huge zone must not flood the
    tenant with assets. The limit covers the root's discovered assets in total (what exists plus
    what this run adds), so a huge zone can't be crawled in chunks across rescans. Relations
    and findings about dropped names are skipped: they are not attached to another asset, and
    exceeding the cap never fails the job.
    """
    asset = get_scoped(session, Asset, asset_id, scan.org_id)
    if asset is None:
        raise AssetNotFound("Asset not found.")
    refs = {(asset.type, asset.value): asset.id}
    # Every name the plugin reported is a valid reference, including ones the cap will drop
    # (a reference to a name it never reported is still a plugin bug and fails the job).
    declared = set(refs) | {(a.type, a.value) for a in output.assets}
    _validate_references(output, declared, catalog)
    admitted: set[tuple[AssetType, str]] | None = None
    if discovered_limit is not None:
        keep = _admit(session, scan.org_id, asset, output, limit=discovered_limit)
        admitted = {(ref.type, ref.value) for ref in keep}
        output = output.model_copy(update={"assets": keep})
    seen = scan.started_at or scan.created_at
    input_ref = (asset.type, asset.value)
    written: set[tuple[AssetType, str]] = set()
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
        written.add((row.type, row.value))
        refs[(row.type, row.value)] = row.id
    # The cap may have dropped a discovered name; links to it are skipped, never guessed.
    for relation in output.relations:
        if not _usable(relation.from_asset, written, input_ref, admitted):
            continue
        if not _usable(relation.to_asset, written, input_ref, admitted):
            continue
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
        target_ref = (raw.asset.type, raw.asset.value) if raw.asset else input_ref
        if not _usable(raw.asset, written, input_ref, admitted):
            continue  # reported for an asset the cap dropped: nothing to attach it to
        target_id = refs[target_ref]
        finding_id, created = _upsert_finding(
            session, scan, target_id, raw, get_rule(raw.rule_id, catalog)
        )
        if created:
            events.append(FindingCreated(scan.org_id, scan.id, finding_id))
        _upsert_evidence(session, scan, finding_id, raw, seen)
    return events


def _validate_references(
    output: ScanOutput, declared: set[tuple[AssetType, str]], catalog: Mapping[str, Rule]
) -> None:
    """Before any write: a malformed plugin fails its whole job, atomically."""
    for relation in output.relations:
        _resolve(declared, relation.from_asset)
        _resolve(declared, relation.to_asset)
    for raw in output.findings:
        get_rule(raw.rule_id, catalog)
        if raw.asset:
            _resolve(declared, raw.asset)


def _upsert_evidence(
    session: Session, scan: Scan, finding_id: UUID, raw: RawFinding, seen: datetime
) -> None:
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


def _resolve(allowed: set[tuple[AssetType, str]], ref: AssetRef) -> None:
    if (ref.type, ref.value) not in allowed:
        raise ValueError("unknown asset reference")


def _usable(
    ref: AssetRef | None,
    written: set[tuple[AssetType, str]],
    input_ref: tuple[AssetType, str],
    admitted: set[tuple[AssetType, str]] | None,
) -> bool:
    """Whether a reference has a row to point at (or no cap applied to it)."""
    if ref is None:
        return True
    key = (ref.type, ref.value)
    if key == input_ref:
        return True
    if admitted is not None and key not in admitted:
        return False
    return key in written


def _admit(
    session: Session, org_id: UUID, input_asset: Asset, output: ScanOutput, *, limit: int
) -> tuple[AssetRef, ...]:
    """Limit what one run adds under the root; exposed assets stay within it too.

    The cap is on the root's discovered assets in total (existing rows + new ones), so a large
    zone can never be crawled in chunks across runs. The input asset doesn't count. Scanners
    should stop at their own limit so the cap only has to drop an occasional overflow.
    """
    candidates = tuple(
        ref
        for ref in output.assets
        if (ref.type, ref.value) != (input_asset.type, input_asset.value)
    )
    if not candidates:
        return ()
    current = int(
        session.scalar(
            scoped(Asset, org_id)
            .where(Asset.parent_id == input_asset.id)
            .with_only_columns(func.count())
        )
        or 0
    )
    existing = {
        (row.type, row.value)
        for row in session.scalars(
            scoped(Asset, org_id).where(
                Asset.parent_id == input_asset.id,
                tuple_(Asset.type, Asset.value).in_([(ref.type, ref.value) for ref in candidates]),
            )
        )
    }
    admitted: list[AssetRef] = []
    room = max(0, limit - current)
    for ref in dict.fromkeys(candidates):  # deterministic order, no duplicate slots used
        if (ref.type, ref.value) in existing:
            admitted.append(ref)
        elif room > 0:
            admitted.append(ref)
            room -= 1
    return tuple(admitted)


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
