"""Ownership checks the ScopeGuard consults before any active check (#14, ADR 0014).

`DbOwnershipChecker` is the gate's synchronous view of the proofs; `check_ownership` is the
worker-side use case that performs one DNS lookup and records the outcome.
"""

from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.assets import AssetType
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import TxtError, TxtLookup
from attacksurf.domain.scanners import AssetRef
from attacksurf.domain.verification import (
    OwnershipState,
    VerificationStatus,
    ownership_state,
    record_name,
)
from attacksurf.infra.db.models import Asset, Verification
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import verifications
from attacksurf.services.audit import audit

log = structlog.get_logger(__name__)

# Types whose ownership a root's DNS TXT proof covers: the root's zone holds the record.
INHERITING_TYPES = frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN})


class DbOwnershipChecker:
    """`OwnershipChecker` over the `verifications` table: one indexed read, no writes.

    A `subdomain` inherits its root's proof (both are names in the root's zone); anything else,
    IPs included, has no TXT proof and stays unverified. Archived assets are never verified:
    verification follows the proof, not the history.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def is_verified(self, org_id: UUID, asset: AssetRef) -> bool:
        try:
            with self._session_factory() as session:
                return self._is_verified(session, org_id, asset)
        except Exception as exc:  # a database outage must deny, never allow
            log.warning("ownership check failed", error=type(exc).__name__)
            return False

    def _is_verified(self, session: Session, org_id: UUID, asset: AssetRef) -> bool:
        if asset.type not in INHERITING_TYPES:
            # A DNS TXT proof says nothing about owning an address, URL or repository: those
            # need their own method. Without it, active checks on them stay denied.
            return False
        asset_id, root_id, is_active = session.execute(
            scoped(Asset, org_id)
            .where(Asset.type == asset.type, Asset.value == asset.value)
            .with_only_columns(Asset.id, Asset.parent_id, Asset.is_active)
        ).one_or_none() or (None, None, False)
        if asset_id is None or not is_active:
            return False
        # Only same-org proof rows are visible, and the composite FK pins the asset to the org.
        # `parent_id` is provenance (what a scan found it under), not ownership: it is only
        # trusted for `subdomain`, where the root does control the name in its zone.
        proof_of = root_id if asset.type is AssetType.SUBDOMAIN and root_id else asset_id
        row = session.execute(
            scoped(Verification, org_id)
            .where(Verification.asset_id == proof_of)
            .with_only_columns(Verification.status, Verification.expires_at)
        ).one_or_none()
        if row is None:
            return False
        status, expires_at = row
        # The same rule the UI shows, so a badge never claims more than the gate allows.
        return ownership_state(status, expires_at, datetime.now(UTC)) is OwnershipState.VERIFIED


class VerificationNotFound(LookupError):
    """No such verification in this org (or another org's: never says which).

    A job whose row is gone is stale, not broken: the worker skips it rather than retrying.
    """


class UnsafeAssetForOwnership(ValueError):
    """An asset type that has no DNS TXT proof (IPs and URLs are proven another way, later)."""


def check_ownership(
    session: Session,
    lookup: TxtLookup,
    *,
    org_id: UUID,
    verification_id: UUID,
    now: datetime | None = None,
) -> VerificationStatus:
    """Run one authoritative TXT lookup for a verification and record the outcome.

    Commits (the row plus its audit entry). A lookup failure is transient: the worker retries
    it, and the existing proof keeps its `expires_at` grace in the meantime.
    """
    verification = _locked_verification(session, org_id, verification_id)
    if verification is None:
        raise VerificationNotFound(str(verification_id))
    asset = _active_root(session, org_id, verification.asset_id)
    if asset is None:
        raise VerificationNotFound(str(verification_id))  # archived: nothing to prove right now
    name = record_name(asset.value)
    previous = verification.status
    session.rollback()  # never hold a transaction across network I/O
    try:
        values = lookup.lookup_txt(asset.value, name)
    except TxtError as exc:
        _record_failure(session, org_id, verification_id)
        raise TransientJobError(
            "The domain's nameservers could not be queried; the check will be retried."
        ) from exc
    verification = _locked_verification(session, org_id, verification_id)
    asset = _active_root(session, org_id, verification.asset_id) if verification else None
    if verification is None or asset is None:  # deleted or archived while the lookup ran
        session.rollback()
        raise VerificationNotFound(str(verification_id))
    status = verifications.record_check(session, verification, values, now=now)
    if status is not previous:
        audit(
            session,
            org_id,
            f"asset.ownership_{status.value}",
            target_type="asset",
            target_id=str(asset.id),
            details={"value": asset.value},
        )
    session.commit()
    return status


def _record_failure(session: Session, org_id: UUID, verification_id: UUID) -> None:
    """Count a failed lookup so the next re-check backs off instead of retrying immediately.

    Commits on its own: the caller then raises (the job retries), and the counter must survive
    that rollback or a permanently unreachable domain would starve every other tenant's checks.
    """
    verification = _locked_verification(session, org_id, verification_id)
    if verification is None:
        session.rollback()
        return
    verifications.record_failure(verification)
    session.commit()


def _locked_verification(
    session: Session, org_id: UUID, verification_id: UUID
) -> Verification | None:
    return session.scalars(
        scoped(Verification, org_id).where(Verification.id == verification_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one_or_none()


def _active_root(session: Session, org_id: UUID, asset_id: UUID) -> Asset | None:
    """The root a proof applies to, or None if it's gone, archived or not a domain.

    `UnsafeAssetForOwnership` never surfaces here: the services only issue proofs for active
    roots, so anything else means the row changed under a running check.
    """
    asset = session.scalars(scoped(Asset, org_id).where(Asset.id == asset_id)).one_or_none()
    if asset is None or asset.type is not AssetType.DOMAIN or not asset.is_active:
        return None
    return asset
