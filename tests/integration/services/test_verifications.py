"""Ownership verification use cases: issuing tokens, recording checks, finding due proofs."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetNotFound, AssetSource, AssetType
from attacksurf.domain.scans import JobStatus
from attacksurf.domain.verification import (
    GRACE_AFTER_FAILURE,
    PROOF_VALID_FOR,
    RECHECK_AFTER,
    OwnershipState,
    VerificationStatus,
    ownership_state,
    record_value,
)
from attacksurf.infra.db.models import Asset, AuditLog, Job, Org, Verification
from attacksurf.services import verifications
from attacksurf.services.assets import record_asset
from tests.fakes import FakeQueue

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def org(db_session: Session) -> Org:
    org = Org(name="acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture
def root(db_session: Session, org: Org) -> Asset:
    return record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )


def _archive(session: Session, asset: Asset) -> None:
    asset.is_active = False
    asset.deactivated_at = NOW
    session.flush()


def _start(session: Session, queue: FakeQueue, org_id: UUID, asset_id: UUID) -> Verification:
    return verifications.start_verification(
        session, queue, org_id=org_id, asset_id=asset_id, actor_id=None
    )


def test_start_creates_a_pending_proof_with_a_token(
    db_session: Session, org: Org, root: Asset
) -> None:
    queue = FakeQueue(db_session)

    proof = _start(db_session, queue, org.id, root.id)

    assert proof.status is VerificationStatus.PENDING
    assert len(proof.token) >= 43
    assert (proof.verified_at, proof.last_checked_at, proof.expires_at) == (None, None, None)


def test_start_queues_one_verification_job_outside_any_scan(
    db_session: Session, org: Org, root: Asset
) -> None:
    queue = FakeQueue(db_session)

    _start(db_session, queue, org.id, root.id)

    job = db_session.query(Job).one()
    assert (job.scan_id, job.stage, job.asset_id) == (None, "verify", root.id)
    assert job.status is JobStatus.QUEUED
    assert queue.sent[0][0] == "passive.verify_ownership"
    assert queue.sent[0][3] is True  # the job row was committed before the task was sent


def test_start_audits_the_request_without_the_token(
    db_session: Session, org: Org, root: Asset
) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)

    entry = db_session.query(AuditLog).one()
    assert entry.action == "asset.verification_started"
    assert entry.details == {"value": "example.com"}
    assert proof.token not in str(entry.details)


def test_starting_again_rotates_the_token_and_keeps_one_row(
    db_session: Session, org: Org, root: Asset
) -> None:
    first = _start(db_session, FakeQueue(db_session), org.id, root.id)
    old_token = first.token

    second = _start(db_session, FakeQueue(db_session), org.id, root.id)

    assert second.id == first.id
    assert second.token != old_token
    assert db_session.query(Verification).count() == 1


def test_rotating_a_verified_proof_resets_it_to_pending(
    db_session: Session, org: Org, root: Asset
) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)
    verifications.record_check(db_session, proof, (record_value(proof.token),))
    db_session.commit()

    rotated = _start(db_session, FakeQueue(db_session), org.id, root.id)

    assert rotated.status is VerificationStatus.PENDING
    assert (rotated.verified_at, rotated.expires_at, rotated.recheck_at) == (None, None, None)


@pytest.fixture
def child(db_session: Session, org: Org, root: Asset) -> Asset:
    return record_asset(
        db_session,
        org.id,
        AssetType.SUBDOMAIN,
        "www.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
    )


def test_start_rejects_a_discovered_subdomain(db_session: Session, org: Org, child: Asset) -> None:
    with pytest.raises(AssetNotFound):
        _start(db_session, FakeQueue(db_session), org.id, child.id)


def test_start_rejects_an_archived_root(db_session: Session, org: Org, root: Asset) -> None:
    record_asset(db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER)
    _archive(db_session, root)

    with pytest.raises(AssetNotFound):
        _start(db_session, FakeQueue(db_session), org.id, root.id)


def test_start_cannot_reach_another_orgs_domain(db_session: Session, org: Org, root: Asset) -> None:
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()

    with pytest.raises(AssetNotFound):
        _start(db_session, FakeQueue(db_session), other.id, root.id)


def test_a_found_record_verifies_the_proof(db_session: Session, org: Org, root: Asset) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)

    status = verifications.record_check(
        db_session, proof, ("v=spf1 -all", record_value(proof.token)), now=NOW
    )

    assert status is VerificationStatus.VERIFIED
    assert (proof.verified_at, proof.last_checked_at, proof.expires_at) == (
        NOW,
        NOW,
        NOW + PROOF_VALID_FOR,
    )


def test_another_domains_token_does_not_verify(db_session: Session, org: Org, root: Asset) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)

    status = verifications.record_check(db_session, proof, (record_value("someone-else"),))

    assert status is VerificationStatus.PENDING


def test_a_missing_record_revokes_a_verified_proof_once_its_grace_is_over(
    db_session: Session, org: Org, root: Asset
) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)
    verifications.record_check(db_session, proof, (record_value(proof.token),), now=NOW)
    verified_at = proof.verified_at

    status = verifications.record_check(db_session, proof, (), now=NOW + PROOF_VALID_FOR)

    assert status is VerificationStatus.REVOKED
    assert proof.verified_at == verified_at  # a revocation never forgets when it was proven
    assert proof.expires_at is None


def test_a_missing_record_inside_the_grace_keeps_the_proof_verified(
    db_session: Session, org: Org, root: Asset
) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)
    verifications.record_check(db_session, proof, (record_value(proof.token),), now=NOW)

    status = verifications.record_check(db_session, proof, (), now=NOW + timedelta(hours=1))

    assert status is VerificationStatus.VERIFIED
    assert proof.last_checked_at == NOW + timedelta(hours=1)


def test_due_verifications_cover_expired_and_stale_pending_proofs(
    db_session: Session, org: Org, root: Asset
) -> None:
    expired = _start(db_session, FakeQueue(db_session), org.id, root.id)
    verifications.record_check(db_session, expired, (record_value(expired.token),), now=NOW)
    other_root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.net", source=AssetSource.USER
    )
    stale = _start(db_session, FakeQueue(db_session), org.id, other_root.id)
    # Stamp the failed check explicitly: the default `now` is wall-clock time, which decides
    # whether this proof is "stale" relative to the fixed NOW+grace used below.
    verifications.record_check(db_session, stale, (), now=NOW)

    due = verifications.due_verifications(db_session, NOW + GRACE_AFTER_FAILURE)

    # The verified proof is past its recheck date; the pending one never got a usable answer.
    assert {row[2] for row in due} == {expired.id, stale.id}


def test_due_verifications_skip_archived_roots(db_session: Session, org: Org, root: Asset) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)
    verifications.record_check(db_session, proof, (record_value(proof.token),))
    record_asset(db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER)
    _archive(db_session, root)

    assert verifications.due_verifications(db_session, NOW + RECHECK_AFTER) == ()


def test_renewal_is_due_while_the_proof_still_authorizes_checks(
    db_session: Session, org: Org, root: Asset
) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)
    verifications.record_check(db_session, proof, (record_value(proof.token),), now=NOW)
    db_session.flush()

    assert (
        verifications.due_verifications(db_session, NOW + RECHECK_AFTER - timedelta(seconds=1))
        == ()
    )
    # Allow an hourly beat delay and one failed lookup's two-hour backoff.
    renewal = NOW + RECHECK_AFTER + timedelta(hours=3)
    assert [row[2] for row in verifications.due_verifications(db_session, renewal)] == [proof.id]
    assert ownership_state(proof.status, proof.expires_at, renewal) is OwnershipState.VERIFIED

    verifications.record_check(db_session, proof, (record_value(proof.token),), now=renewal)
    db_session.flush()

    assert proof.expires_at == renewal + PROOF_VALID_FOR
    assert verifications.due_verifications(db_session, NOW + PROOF_VALID_FOR) == ()


def test_verified_proof_without_a_recheck_deadline_is_due(
    db_session: Session, org: Org, root: Asset
) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)
    verifications.record_check(db_session, proof, (record_value(proof.token),), now=NOW)
    proof.recheck_at = None
    db_session.flush()

    assert [row[2] for row in verifications.due_verifications(db_session, NOW)] == [proof.id]


def test_enqueue_due_checks_queues_one_job_per_due_proof(
    db_session: Session, org: Org, root: Asset
) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)
    verifications.record_check(db_session, proof, (record_value(proof.token),), now=NOW)
    db_session.commit()
    queue = FakeQueue(db_session)

    queued = verifications.enqueue_due_checks(
        db_session, queue, now=NOW + RECHECK_AFTER + timedelta(minutes=1)
    )

    assert queued == 1
    assert queue.sent[0][0] == "passive.verify_ownership"
    assert queue.sent[0][3] is True


def test_get_verification_returns_the_roots_proof_for_a_subdomain(
    db_session: Session, org: Org, root: Asset, child: Asset
) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)

    view = verifications.get_verification(db_session, org.id, child.id)

    assert view is not None
    assert view.record_name == "_attacksurf-verify.example.com"
    assert view.record_value == f"attacksurf-verification={proof.token}"
    assert view.status is VerificationStatus.PENDING


def test_get_verification_is_none_before_a_token_is_issued(
    db_session: Session, org: Org, root: Asset
) -> None:
    assert verifications.get_verification(db_session, org.id, root.id) is None


def test_get_verification_cannot_reach_another_orgs_asset(
    db_session: Session, org: Org, root: Asset
) -> None:
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()

    with pytest.raises(AssetNotFound):
        verifications.get_verification(db_session, other.id, root.id)


def test_queue_check_reuses_the_token_and_queues_a_job(
    db_session: Session, org: Org, root: Asset
) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)
    token = proof.token
    queue = FakeQueue(db_session)

    verifications.queue_check(db_session, queue, org_id=org.id, asset_id=root.id)

    assert db_session.get_one(Verification, proof.id).token == token
    assert [task for task, *_ in queue.sent] == ["passive.verify_ownership"]
    assert queue.sent[0][3] is True  # the job row committed before the task was sent


def test_queue_check_needs_an_existing_proof(db_session: Session, org: Org, root: Asset) -> None:
    with pytest.raises(AssetNotFound):
        verifications.queue_check(
            db_session, FakeQueue(db_session), org_id=org.id, asset_id=root.id
        )


def test_queue_check_cannot_reach_another_orgs_domain(
    db_session: Session, org: Org, root: Asset
) -> None:
    _start(db_session, FakeQueue(db_session), org.id, root.id)
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()

    with pytest.raises(AssetNotFound):
        verifications.queue_check(
            db_session, FakeQueue(db_session), org_id=other.id, asset_id=root.id
        )


def test_a_failing_proof_backs_off_instead_of_blocking_the_batch(
    db_session: Session, org: Org, root: Asset
) -> None:
    """Regression: permanently unreachable proofs kept taking the fixed batch's slots."""
    failing = _start(db_session, FakeQueue(db_session), org.id, root.id)
    verifications.record_check(db_session, failing, (record_value(failing.token),), now=NOW)
    verifications.record_failure(failing, now=NOW)  # retry_after = NOW + 2 h
    db_session.flush()

    # Due (expired), but its backoff has not elapsed, so this run skips it entirely.
    assert {
        row[2] for row in verifications.due_verifications(db_session, NOW + timedelta(hours=1))
    } == set()
    # It is picked up again at its expiry once the backoff is over (2 h << 1 day).
    expired = NOW + RECHECK_AFTER
    assert {row[2] for row in verifications.due_verifications(db_session, expired)} == {failing.id}


def test_a_full_batch_still_reaches_healthy_proofs(
    db_session: Session, org: Org, root: Asset
) -> None:
    """Regression: failing proofs sorted first and took every slot in a `limit=1` batch."""
    other_root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "healthy.example.net", source=AssetSource.USER
    )
    healthy = _start(db_session, FakeQueue(db_session), org.id, other_root.id)
    verifications.record_check(db_session, healthy, (record_value(healthy.token),), now=NOW)
    broken = _start(db_session, FakeQueue(db_session), org.id, root.id)
    verifications.record_check(db_session, broken, (record_value(broken.token),), now=NOW)
    db_session.flush()

    # The healthy proof expires a day later than the broken one, so without the attempt-based
    # ordering a one-slot batch would always pick the broken proof first.
    broken.expires_at = NOW + timedelta(hours=1)
    db_session.flush()
    verifications.record_failure(broken, now=NOW)
    verifications.record_failure(broken, now=NOW)  # back off 4 h, past its expiry
    db_session.flush()

    picked = verifications.due_verifications(
        db_session, NOW + RECHECK_AFTER + timedelta(minutes=1), limit=1
    )

    assert [row[2] for row in picked] == [healthy.id]


def test_a_successful_check_clears_the_backoff(db_session: Session, org: Org, root: Asset) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)
    verifications.record_failure(proof, now=NOW)

    verifications.record_check(db_session, proof, (record_value(proof.token),), now=NOW)

    assert (proof.failed_attempts, proof.retry_after) == (0, None)


def test_backoff_grows_per_consecutive_failure(db_session: Session, org: Org, root: Asset) -> None:
    proof = _start(db_session, FakeQueue(db_session), org.id, root.id)

    verifications.record_failure(proof, now=NOW)
    first = proof.retry_after
    verifications.record_failure(proof, now=NOW)

    assert first == NOW + timedelta(hours=2)
    assert proof.retry_after == NOW + timedelta(hours=4)
