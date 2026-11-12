"""Normalize and persist a scanner result inside the caller's transaction (no commit)."""

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
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
from attacksurf.domain.scanners import AssetObservation, AssetRef, RawFinding, ScanOutput
from attacksurf.domain.scans import ScanCancelled
from attacksurf.infra.db.models import Asset, Evidence, Finding, Scan
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.services.assets import record_asset, record_relation
from attacksurf.services.scans import TERMINAL

OBSERVED_AT = "observed_at"


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
    exceeding the cap never fails the job. Wildcard-zone markers are merged into `Asset.details`
    for the root and the discovered zones that survived the cap (ADR 0022).

    Raises `ScanCancelled` for a cancelled scan and `AssetNotFound` when the scan's root is
    archived (ADR 0021). Locks are taken in the order `archive_root_domain` uses (scan rows, then
    the root): the caller already holds the scan row lock. The root is read `FOR KEY SHARE`,
    which never conflicts with the archive, or locked `FOR UPDATE` once when the cap or a root
    wildcard marker needs it. The input and discovered assets are then locked/upserted in a
    stable type/value order, so overlapping roots can't deadlock on opposite answer orders.
    """
    asset = get_scoped(session, Asset, asset_id, scan.org_id)
    if asset is None:
        raise AssetNotFound("Asset not found.")
    if scan.status in TERMINAL:
        raise ScanCancelled("Scan was cancelled.")
    input_ref = (asset.type, asset.value)
    root = _lock_root(session, scan, asset, output, discovered_limit=discovered_limit)
    root_ref = (root.type, root.value)
    # Every name the plugin reported is a valid reference, including ones the cap will drop
    # (a reference to a name it never reported is still a plugin bug and fails the job). The
    # scan root is always valid: a subdomain may CNAME to its apex.
    declared = {input_ref, root_ref} | {(a.type, a.value) for a in output.assets}
    _validate_references(output, declared, catalog)
    admitted: set[tuple[AssetType, str]] | None = None
    if discovered_limit is not None:
        keep = _admit(
            session, scan.org_id, scan.root_asset_id, asset, output, limit=discovered_limit
        )
        admitted = {(ref.type, ref.value) for ref in keep} | {root_ref}
        output = output.model_copy(update={"assets": keep})
    seen = scan.started_at or scan.created_at
    rows: dict[tuple[AssetType, str], Asset] = {root_ref: root}
    refs: dict[tuple[AssetType, str], UUID] = {root_ref: root.id}
    # The root exists independently of this output; `_usable` may link a subdomain's CNAME to it.
    written: set[tuple[AssetType, str]] = {root_ref}
    for asset_type, value in _ordered_asset_refs(input_ref, root_ref, output.assets):
        key = (asset_type, value)
        if key == input_ref:
            row = _lock_input(session, scan, asset_id)
        else:
            row = record_asset(
                session,
                scan.org_id,
                asset_type,
                value,
                source=AssetSource.DISCOVERED,
                parent_id=scan.root_asset_id,
                seen_at=seen,
            )
        written.add(key)
        refs[key] = row.id
        rows[key] = row
    asset = rows[input_ref]
    _apply_observations(
        output, rows=rows, written=written, input_ref=input_ref, admitted=admitted, seen=seen
    )
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
    _mark_wildcards(rows, output.wildcard_zones)
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


def _lock_root(
    session: Session,
    scan: Scan,
    asset: Asset,
    output: ScanOutput,
    *,
    discovered_limit: int | None,
) -> Asset:
    """Take the one root lock this persist needs, in the archive-compatible order.

    The cap needs the write lock (it counts and admits under it); a wildcard marker on the input
    root does too, because the marker updates the root row. A key-share lock is never upgraded:
    concurrent persists would deadlock doing that, so the choice is made before locking.
    """
    input_ref = (asset.type, asset.value)
    marks_input = any((z.type, z.value) == input_ref for z in output.wildcard_zones)
    if marks_input and asset.id != scan.root_asset_id:
        raise ValueError("wildcard markers apply to the scan root")
    if discovered_limit is not None or marks_input:
        return _writable_root(session, scan)
    return _check_root_archived(session, scan)


def _check_root_archived(session: Session, scan: Scan) -> Asset:
    """Fresh read of the scan's root; raises `AssetNotFound` unless it is active.

    `FOR KEY SHARE`, not `FOR UPDATE`: the caller already holds the scan row lock, and
    `archive_root_domain` takes rows scan-then-root, so waiting for the root's write lock here
    could deadlock against an archive that is waiting for this scan. Key-share still makes the
    archive's `UPDATE` of the root wait, so the rows next to this read's writes can't vanish
    under it.
    """
    root = session.scalars(
        scoped(Asset, scan.org_id)
        .where(Asset.id == scan.root_asset_id)
        .with_for_update(read=True, key_share=True),
        execution_options={"populate_existing": True},
    ).one_or_none()
    if root is None or not root.is_active:
        raise AssetNotFound("Root asset is archived.")
    return root


def _writable_root(session: Session, scan: Scan) -> Asset:
    """Lock the root `FOR UPDATE`, after the caller locked its scan rows (the cap path only).

    One exclusive lock, never an upgrade from the key-share read: two persists upgrading it
    would block on each other and deadlock. An archive that arrives later waits for this
    transaction and then deactivates what it wrote.
    """
    root = session.scalars(
        scoped(Asset, scan.org_id).where(Asset.id == scan.root_asset_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one_or_none()
    if root is None or not root.is_active:
        raise AssetNotFound("Root asset is archived.")
    return root


def _validate_references(
    output: ScanOutput, declared: set[tuple[AssetType, str]], catalog: Mapping[str, Rule]
) -> None:
    """Before any write: a malformed plugin fails its whole job, atomically."""
    for relation in output.relations:
        _resolve(declared, relation.from_asset)
        _resolve(declared, relation.to_asset)
    for zone in output.wildcard_zones:
        _resolve(declared, zone)
    for observation in output.observations:
        _resolve(declared, observation.asset)
    for raw in output.findings:
        get_rule(raw.rule_id, catalog)
        if raw.asset:
            _resolve(declared, raw.asset)


_ASSET_ORDER = {asset_type: index for index, asset_type in enumerate(AssetType)}


def _ordered_asset_refs(
    input_ref: tuple[AssetType, str],
    root_ref: tuple[AssetType, str],
    assets: tuple[AssetRef, ...],
) -> tuple[tuple[AssetType, str], ...]:
    """Input + discovered refs in the one order every persistence transaction locks them."""
    refs = {input_ref, root_ref}
    refs.update((asset.type, asset.value) for asset in assets)
    refs.discard(root_ref)
    return tuple(sorted(refs, key=lambda ref: (_ASSET_ORDER[ref[0]], ref[1])))


def _lock_input(session: Session, scan: Scan, asset_id: UUID) -> Asset:
    row = session.scalars(
        scoped(Asset, scan.org_id).where(Asset.id == asset_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one_or_none()
    if row is None:
        raise AssetNotFound("Asset not found.")
    return row


def _apply_observations(
    output: ScanOutput,
    *,
    rows: dict[tuple[AssetType, str], Asset],
    written: set[tuple[AssetType, str]],
    input_ref: tuple[AssetType, str],
    admitted: set[tuple[AssetType, str]] | None,
    seen: datetime,
) -> None:
    for observation in output.observations:
        if not _usable(observation.asset, written, input_ref, admitted):
            continue
        row = rows.get((observation.asset.type, observation.asset.value))
        if row is not None:
            _observe(row, observation, seen)


def _observe(row: Asset, observation: AssetObservation, seen: datetime) -> None:
    """Merge details and apply a lifecycle claim without moving state backwards.

    A scanner may deactivate only a discovered asset: roots are user-owned and stay active even
    when their DNS no longer resolves. Details are only replaced by an observation at least as
    new as the stored one, so a delayed older result cannot erase newer records; lifecycle has
    its own monotonic checks below.
    """
    if observation.details:
        observed_at = _details_time(row.details)
        if observed_at is None or seen >= observed_at:
            row.details = {
                **(row.details or {}),
                **observation.details,
                OBSERVED_AT: seen.isoformat(),
            }
    if observation.active is None:
        return
    if observation.active:
        row.last_seen = max(row.last_seen, seen)
        if row.deactivated_at is None or seen > row.deactivated_at:
            row.is_active = True
            row.deactivated_at = None
        return
    if row.parent_id is not None and seen >= row.last_seen:
        # Advance even when already inactive: a later negative observation must outrank a
        # delayed positive one that would otherwise pass the reactivation check.
        if row.deactivated_at is None or seen > row.deactivated_at:
            row.deactivated_at = seen
        row.is_active = False


def _details_time(details: object) -> datetime | None:
    """When the stored details were observed, or None for rows written before this marker."""
    if not isinstance(details, dict):
        return None
    raw = details.get(OBSERVED_AT)
    if not isinstance(raw, str):
        return None
    try:
        value = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


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


def _mark_wildcards(
    rows: Mapping[tuple[AssetType, str], Asset], zones: tuple[AssetRef, ...]
) -> None:
    """Merge the wildcard marker into the rows that exist; a cap-dropped zone has no row.

    `details` is a JSONB bag shared with later scanners (#16 adds DNS records), so the marker is
    merged rather than replacing whatever is already there.
    """
    for zone in zones:
        row = rows.get((zone.type, zone.value))
        if row is not None:
            row.details = {**(row.details or {}), "wildcard": True}


def _admit(
    session: Session,
    org_id: UUID,
    root_id: UUID,
    input_asset: Asset,
    output: ScanOutput,
    *,
    limit: int,
) -> tuple[AssetRef, ...]:
    """Limit what one run adds under the root; exposed assets stay within it too.

    The cap is on the root's discovered assets in total (existing rows + new ones), so a large
    zone can never be crawled in chunks across runs. The input asset doesn't count. Scanners
    should stop at their own limit so the cap only has to drop an occasional overflow.

    `root_id` is where rows are actually written (`parent_id=scan.root_asset_id`), so it is also
    what the count must use: a check on a discovered subdomain would otherwise see zero children
    and hand out a fresh allowance for every subdomain.

    `persist_scan_output` already holds the root's `FOR UPDATE` lock for the whole write, so
    overlapping scans of the same root (each locked only on its own `Scan`) can't both read the
    same count and each admit the full allowance.
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
            scoped(Asset, org_id).where(Asset.parent_id == root_id).with_only_columns(func.count())
        )
        or 0
    )
    existing = {
        (row.type, row.value)
        for row in session.scalars(
            scoped(Asset, org_id).where(
                Asset.parent_id == root_id,
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
