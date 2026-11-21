from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.accounts import Role
from attacksurf.domain.findings import FindingStatus, Severity
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.notifications import EmailMessageData, EmailRecipientRefused
from attacksurf.domain.scanners import RawFinding, ScanOutput
from attacksurf.domain.scans import JobStatus, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import (
    Job,
    Membership,
    NotificationDelivery,
    Scan,
    User,
)
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.events import InProcessDispatcher
from attacksurf.services import assets as assets_service
from attacksurf.services import notifications, scan_diff, triage
from attacksurf.services.scan_results import persist_scan_output
from tests.fakes import FakeQueue
from tests.helpers import make_settings
from tests.integration.factories import make_finding, make_org, make_scan
from tests.scanner_fixtures import RULE, FakeCheck


class _FakeEmailSender:
    def __init__(
        self,
        *,
        fail_emails: set[str] | None = None,
        refuse_emails: set[str] | None = None,
    ) -> None:
        self.outbox: list[EmailMessageData] = []
        self.fail_emails = fail_emails or set()
        self.refuse_emails = refuse_emails or set()

    def send(self, message: EmailMessageData) -> None:
        if message.to_email in self.fail_emails:
            raise TransientJobError("Temporary SMTP error.")
        if message.to_email in self.refuse_emails:
            raise EmailRecipientRefused("SMTP recipient refused.")
        self.outbox.append(message)


def _add_member(session: Session, org_id, email: str, *, is_active: bool = True) -> User:
    user = User(email=email, password_hash="fake$hash", is_active=is_active)
    session.add(user)
    session.flush()
    session.add(Membership(org_id=org_id, user_id=user.id, role=Role.MEMBER))
    session.flush()
    return user


def _notify_job(session: Session, org_id, scan_id) -> Job:
    job = Job(
        org_id=org_id,
        scan_id=scan_id,
        stage=notifications.NOTIFY_STAGE,
        status=JobStatus.QUEUED,
    )
    session.add(job)
    session.flush()
    return job


def test_scheduled_scan_with_new_high_finding_sends_exactly_one_email(
    db_session: Session,
) -> None:
    scan = make_scan(db_session)
    scan.triggered_by = ScanTrigger.SCHEDULE
    scan.finished_at = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)
    scan.ai_summary = {
        "headline": "DMARC policy is missing on acme.example.",
        "key_risks": [],
        "notable_assets": [],
        "changes": "1 new high finding.",
        "next_actions": ["Publish a DMARC record."],
        "prompt_version": "summary/v1",
        "provider": "anthropic",
        "model": "claude-test",
        "generated_at": "2026-11-20T10:01:00Z",
    }
    _add_member(db_session, scan.org_id, "sec@acme.example")
    persist_scan_output(
        db_session,
        scan,
        scan.root_asset_id,
        ScanOutput(findings=(RawFinding(rule_id=RULE.id, severity=Severity.HIGH),)),
        catalog={RULE.id: RULE},
        scanner=FakeCheck.name,
    )
    scan.status = ScanStatus.COMPLETED
    job = _notify_job(db_session, scan.org_id, scan.id)
    db_session.commit()
    sender = _FakeEmailSender()

    sent_first = notifications.run_scan_notification(
        db_session, scan.org_id, job.id, sender, app_base_url="https://asm.acme.example"
    )
    sent_second = notifications.run_scan_notification(
        db_session, scan.org_id, job.id, sender, app_base_url="https://asm.acme.example"
    )

    assert sent_first == 1
    assert sent_second == 0
    assert len(sender.outbox) == 1
    email = sender.outbox[0]
    assert email.to_email == "sec@acme.example"
    assert "1 new" in email.subject
    assert "DMARC policy is missing on acme.example." in email.text_body
    assert "DMARC policy is missing on acme.example." in email.html_body
    assert f"https://asm.acme.example/scans/{scan.id}" in email.html_body


def test_regressed_finding_notifies_once_and_not_on_next_scan(db_session: Session) -> None:
    first = make_scan(db_session)
    _add_member(db_session, first.org_id, "sec@acme.example")
    base = datetime(2026, 11, 1, tzinfo=UTC)
    first.status = ScanStatus.COMPLETED
    first.started_at = base
    first.finished_at = base
    finding = make_finding(
        db_session,
        first.org_id,
        first.root_asset_id,
        rule_id=RULE.id,
        severity=Severity.HIGH,
        status=FindingStatus.FIXED,
        first_seen=base,
        last_seen=base,
        fixed_at=base,
    )

    # Scan 2 observes the previously fixed finding -> regresses.
    second = Scan(
        org_id=first.org_id,
        root_asset_id=first.root_asset_id,
        profile="dns_passive",
        status=ScanStatus.RUNNING,
        triggered_by=ScanTrigger.SCHEDULE,
        started_at=base + timedelta(days=1),
    )
    db_session.add(second)
    db_session.flush()
    persist_scan_output(
        db_session,
        second,
        second.root_asset_id,
        ScanOutput(findings=(RawFinding(rule_id=finding.rule_id, severity=Severity.HIGH),)),
        catalog={RULE.id: RULE},
        scanner=FakeCheck.name,
    )
    diff_job = Job(org_id=first.org_id, scan_id=second.id, stage="diff", status=JobStatus.RUNNING)
    db_session.add(diff_job)
    db_session.flush()
    scan_diff.diff_scan(db_session, first.org_id, diff_job.id, events=InProcessDispatcher())
    second.status = ScanStatus.COMPLETED
    second.finished_at = base + timedelta(days=1)

    sender = _FakeEmailSender()
    notify2 = _notify_job(db_session, first.org_id, second.id)
    db_session.commit()
    assert notifications.run_scan_notification(db_session, first.org_id, notify2.id, sender) == 1
    assert "1 regressed" in sender.outbox[0].subject

    # Scan 3 observes the same still-REGRESSED finding again -> should NOT re-notify.
    third = Scan(
        org_id=first.org_id,
        root_asset_id=first.root_asset_id,
        profile="dns_passive",
        status=ScanStatus.RUNNING,
        triggered_by=ScanTrigger.SCHEDULE,
        started_at=base + timedelta(days=2),
    )
    db_session.add(third)
    db_session.flush()
    persist_scan_output(
        db_session,
        third,
        third.root_asset_id,
        ScanOutput(findings=(RawFinding(rule_id=finding.rule_id, severity=Severity.HIGH),)),
        catalog={RULE.id: RULE},
        scanner=FakeCheck.name,
    )
    diff_job3 = Job(org_id=first.org_id, scan_id=third.id, stage="diff", status=JobStatus.RUNNING)
    db_session.add(diff_job3)
    db_session.flush()
    scan_diff.diff_scan(db_session, first.org_id, diff_job3.id, events=InProcessDispatcher())
    third.status = ScanStatus.COMPLETED
    third.finished_at = base + timedelta(days=2)

    notify3 = _notify_job(db_session, first.org_id, third.id)
    db_session.commit()
    assert notifications.run_scan_notification(db_session, first.org_id, notify3.id, sender) == 0
    assert len(sender.outbox) == 1


def test_preferences_filter_by_enabled_and_min_severity(db_session: Session) -> None:
    scan = make_scan(db_session)
    u_off = _add_member(db_session, scan.org_id, "off@acme.example")
    u_crit = _add_member(db_session, scan.org_id, "crit@acme.example")
    u_med = _add_member(db_session, scan.org_id, "med@acme.example")

    notifications.save_notification_preference(
        db_session, scan.org_id, u_off.id, email_enabled=False, min_severity=Severity.INFO
    )
    notifications.save_notification_preference(
        db_session, scan.org_id, u_crit.id, email_enabled=True, min_severity=Severity.CRITICAL
    )
    notifications.save_notification_preference(
        db_session, scan.org_id, u_med.id, email_enabled=True, min_severity=Severity.MEDIUM
    )

    persist_scan_output(
        db_session,
        scan,
        scan.root_asset_id,
        ScanOutput(findings=(RawFinding(rule_id=RULE.id, severity=Severity.HIGH),)),
        catalog={RULE.id: RULE},
        scanner=FakeCheck.name,
    )
    scan.status = ScanStatus.COMPLETED
    job = _notify_job(db_session, scan.org_id, scan.id)
    db_session.commit()
    sender = _FakeEmailSender()

    sent = notifications.run_scan_notification(db_session, scan.org_id, job.id, sender)

    assert sent == 1
    assert [m.to_email for m in sender.outbox] == ["med@acme.example"]


def test_partial_smtp_failure_records_first_delivery_and_retries_second(
    db_session: Session,
) -> None:
    scan = make_scan(db_session)
    _add_member(db_session, scan.org_id, "a@acme.example")
    _add_member(db_session, scan.org_id, "b@acme.example")
    persist_scan_output(
        db_session,
        scan,
        scan.root_asset_id,
        ScanOutput(findings=(RawFinding(rule_id=RULE.id, severity=Severity.HIGH),)),
        catalog={RULE.id: RULE},
        scanner=FakeCheck.name,
    )
    scan.status = ScanStatus.COMPLETED
    job = _notify_job(db_session, scan.org_id, scan.id)
    db_session.commit()
    sender = _FakeEmailSender(fail_emails={"b@acme.example"})

    with pytest.raises(TransientJobError):
        notifications.run_scan_notification(db_session, scan.org_id, job.id, sender)

    assert [m.to_email for m in sender.outbox] == ["a@acme.example"]
    assert len(db_session.scalars(scoped(NotificationDelivery, scan.org_id)).all()) == 1

    sender.fail_emails.clear()
    sent_retry = notifications.run_scan_notification(db_session, scan.org_id, job.id, sender)
    assert sent_retry == 1
    assert [m.to_email for m in sender.outbox] == ["a@acme.example", "b@acme.example"]


def test_skips_when_nothing_new_or_smtp_unset_or_archived(db_session: Session) -> None:
    scan = make_scan(db_session)
    scan.status = ScanStatus.COMPLETED
    user = _add_member(db_session, scan.org_id, "a@acme.example")
    job = _notify_job(db_session, scan.org_id, scan.id)
    db_session.commit()

    assert notifications.run_scan_notification(db_session, scan.org_id, job.id, None) == 0
    assert job.status is JobStatus.SKIPPED

    job2 = _notify_job(db_session, scan.org_id, scan.id)
    db_session.commit()
    assert (
        notifications.run_scan_notification(db_session, scan.org_id, job2.id, _FakeEmailSender())
        == 0
    )
    assert job2.status is JobStatus.SKIPPED

    assets_service.archive_root_domain(
        db_session, scan.org_id, scan.root_asset_id, actor_id=user.id
    )
    job3 = _notify_job(db_session, scan.org_id, scan.id)
    db_session.commit()
    assert (
        notifications.run_scan_notification(db_session, scan.org_id, job3.id, _FakeEmailSender())
        == 0
    )
    assert job3.status is JobStatus.SKIPPED


def test_tenant_isolation_never_emails_other_org_members(db_session: Session) -> None:
    scan_a = make_scan(db_session, name="alpha")
    org_b = make_org(db_session, name="beta")
    _add_member(db_session, scan_a.org_id, "alice@alpha.example")
    _add_member(db_session, org_b.id, "bob@beta.example")
    persist_scan_output(
        db_session,
        scan_a,
        scan_a.root_asset_id,
        ScanOutput(findings=(RawFinding(rule_id=RULE.id, severity=Severity.HIGH),)),
        catalog={RULE.id: RULE},
        scanner=FakeCheck.name,
    )
    scan_a.status = ScanStatus.COMPLETED
    job = _notify_job(db_session, scan_a.org_id, scan_a.id)
    db_session.commit()
    sender = _FakeEmailSender()

    sent = notifications.run_scan_notification(db_session, scan_a.org_id, job.id, sender)

    assert sent == 1
    assert [m.to_email for m in sender.outbox] == ["alice@alpha.example"]


def test_post_ai_skip_queues_notification_once(db_session: Session) -> None:
    scan = make_scan(db_session)
    scan.status = ScanStatus.COMPLETED
    triage_job = Job(org_id=scan.org_id, scan_id=scan.id, stage="triage", status=JobStatus.QUEUED)
    db_session.add(triage_job)
    db_session.flush()
    queue = FakeQueue(db_session)

    # AI unconfigured -> run_triage skips and queues passive.notify_scan.
    triage.run_triage(
        db_session,
        queue,  # type: ignore[arg-type]
        scan.org_id,
        triage_job.id,
        make_settings(),
    )

    assert [name for name, *_ in queue.sent] == [notifications.NOTIFY_TASK_NAME]
    # Calling queue_scan_notification again is a no-op.
    notifications.queue_scan_notification(db_session, queue, scan.org_id, scan.id)
    assert len(queue.sent) == 1


def test_permanent_recipient_refusal_continues_to_remaining_recipients(
    db_session: Session,
) -> None:
    scan = make_scan(db_session)
    _add_member(db_session, scan.org_id, "a-bad@acme.example")
    _add_member(db_session, scan.org_id, "b-good@acme.example")
    persist_scan_output(
        db_session,
        scan,
        scan.root_asset_id,
        ScanOutput(findings=(RawFinding(rule_id=RULE.id, severity=Severity.HIGH),)),
        catalog={RULE.id: RULE},
        scanner=FakeCheck.name,
    )
    scan.status = ScanStatus.COMPLETED
    job = _notify_job(db_session, scan.org_id, scan.id)
    db_session.commit()
    sender = _FakeEmailSender(refuse_emails={"a-bad@acme.example"})

    sent = notifications.run_scan_notification(db_session, scan.org_id, job.id, sender)

    assert sent == 1
    assert [m.to_email for m in sender.outbox] == ["b-good@acme.example"]


def test_claimed_delivery_prevents_concurrent_duplicate_send(db_session: Session) -> None:
    scan = make_scan(db_session)
    user = _add_member(db_session, scan.org_id, "a@acme.example")
    persist_scan_output(
        db_session,
        scan,
        scan.root_asset_id,
        ScanOutput(findings=(RawFinding(rule_id=RULE.id, severity=Severity.HIGH),)),
        catalog={RULE.id: RULE},
        scanner=FakeCheck.name,
    )
    scan.status = ScanStatus.COMPLETED
    job = _notify_job(db_session, scan.org_id, scan.id)
    db_session.commit()

    # Simulate another worker claiming the delivery right before `sender.send()`.
    sender = _FakeEmailSender()
    orig_send = sender.send

    def _race_then_send(msg: EmailMessageData) -> None:
        orig_send(msg)

    sender.send = _race_then_send  # type: ignore[method-assign]
    assert notifications._claim_delivery(db_session, scan.org_id, scan.id, user.id) is not None
    assert notifications._claim_delivery(db_session, scan.org_id, scan.id, user.id) is None
    assert notifications.run_scan_notification(db_session, scan.org_id, job.id, sender) == 0
    assert sender.outbox == []
