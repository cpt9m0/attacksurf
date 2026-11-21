"""The AI exposure summary job and input selection (ADR 0030)."""

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from pydantic import SecretStr
from sqlalchemy import func, update
from sqlalchemy.orm import Session

from attacksurf.ai.schemas import FindingTriage, StoredTriage
from attacksurf.ai.summary import MAX_SUMMARY_ASSETS, MAX_SUMMARY_FINDINGS, SUMMARY_PURPOSE
from attacksurf.ai.triage import TRIAGE_PROMPT_VERSION
from attacksurf.config import Settings
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.findings import FindingStatus, Severity
from attacksurf.domain.jobs import JobNotFound
from attacksurf.domain.llm import KeySource, LLMConfig, LLMUnavailable, ProviderKind, TokenUsage
from attacksurf.domain.scans import JobStatus, ScanNotFound, ScanStatus
from attacksurf.infra.db.models import Asset, Finding, FindingObservation, Job, LLMUsage, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import jobs, summary, triage
from attacksurf.services.assets import record_asset
from tests.fakes import FakeLLMProvider
from tests.helpers import make_settings
from tests.integration.factories import make_finding, make_scan
from tests.integration.services.test_triage_jobs import RecordingPipelineQueue

MODEL = "muse-spark-1.3"
_CONFIG = LLMConfig(
    provider=ProviderKind.ANTHROPIC,
    model=MODEL,
    api_key=SecretStr("instance-key"),
    source=KeySource.INSTANCE,
)


def _settings(budget: int = 500_000) -> Settings:
    return make_settings(
        env="test",
        secret_key=SecretStr("test-secret-key"),
        llm_api_key=SecretStr("instance-key"),
        llm_model=MODEL,
        llm_monthly_instance_token_budget=budget,
    )


def _completed_scan(session: Session, name: str = "acme") -> Scan:
    scan = make_scan(session, name)
    scan.status = ScanStatus.COMPLETED
    session.flush()
    return scan


def _subdomain(session: Session, scan: Scan, label: str, *, active: bool = True) -> Asset:
    asset = record_asset(
        session,
        scan.org_id,
        AssetType.SUBDOMAIN,
        f"{label}.acme.example",
        source=AssetSource.DISCOVERED,
        parent_id=scan.root_asset_id,
    )
    if not active:
        asset.is_active = False
        asset.deactivated_at = datetime(2026, 11, 19, tzinfo=UTC)
        session.flush()
    return asset


def _observed(session: Session, scan: Scan, asset_id: UUID, **fields: Any) -> Finding:
    finding = make_finding(session, scan.org_id, asset_id, **fields)
    session.add(
        FindingObservation(
            org_id=scan.org_id, scan_id=scan.id, finding_id=finding.id, severity=finding.severity
        )
    )
    session.flush()
    return finding


def _judge(
    session: Session,
    finding: Finding,
    *,
    priority: str = "P1",
    adjusted: str = "critical",
    rationale: str = "Confirmed by DNS records.",
    stale: bool = False,
) -> None:
    judgment = FindingTriage.model_validate(
        {
            "ref": "F1",
            "adjusted_severity": adjusted,
            "confidence": "high",
            "false_positive_likelihood": "low",
            "priority": priority,
            "rationale": rationale,
            "exploitability": "",
            "remediation_steps": ["Fix the record."],
        }
    )
    finding.ai_triage = StoredTriage.from_judgment(
        judgment,
        prompt_version=TRIAGE_PROMPT_VERSION,
        config=_CONFIG,
        cache_key="0" * 64 if stale else triage.finding_cache_key(finding, MODEL),
        triaged_at=datetime(2026, 11, 19, tzinfo=UTC),
    ).model_dump(mode="json")
    session.flush()


def _job(session: Session, scan: Scan, stage: str = "summary") -> Job:
    job = jobs.record_job(session, org_id=scan.org_id, scan_id=scan.id, stage=stage)
    session.commit()
    return job


def _reply(**overrides: Any) -> str:
    data: dict[str, Any] = {
        "headline": "High-risk subdomain takeover and exposed Jenkins host.",
        "key_risks": [{"finding_ref": "F1", "why": "Dangling CNAME can be claimed."}],
        "notable_assets": [{"asset_ref": "A1", "reason": "Root or sensitive host."}],
        "changes": "1 new high finding since the last scan.",
        "next_actions": ["Remove the dangling CNAME."],
    } | overrides
    return json.dumps(data)


def _use_provider(monkeypatch: pytest.MonkeyPatch, provider: FakeLLMProvider) -> None:
    monkeypatch.setattr(summary, "build_provider", lambda _config: provider)


def _usage(session: Session, scan: Scan) -> list[LLMUsage]:
    return list(session.scalars(scoped(LLMUsage, scan.org_id)))


def _refreshed(session: Session, row: Any) -> Any:
    session.expire_all()
    return session.get(type(row), row.id)


# --- Queueing hooks ------------------------------------------------------------------------


def test_summary_is_queued_after_triage_batches_finish_and_not_duplicated(
    db_session: Session,
) -> None:
    scan = _completed_scan(db_session)
    done = _job(db_session, scan, "triage_done")
    _job(db_session, scan, "triage_failure")
    queue = RecordingPipelineQueue(db_session)

    triage.finish_triage(db_session, queue, scan.org_id, done.id)
    triage.finish_triage(db_session, queue, scan.org_id, done.id)

    assert [name for name, _, _ in queue.enqueued] == ["ai.summarize"]
    summary_jobs = db_session.scalars(
        scoped(Job, scan.org_id).where(Job.scan_id == scan.id, Job.stage == "summary")
    ).all()
    assert len(summary_jobs) == 1


def test_summary_is_queued_when_triage_has_nothing_new(db_session: Session) -> None:
    scan = _completed_scan(db_session)
    coordinator = _job(db_session, scan, "triage")
    queue = RecordingPipelineQueue(db_session)

    triage.run_triage(db_session, queue, scan.org_id, coordinator.id, _settings())

    assert queue.published == []
    assert [name for name, _, _ in queue.enqueued] == ["ai.summarize"]


def test_summary_is_not_queued_when_triage_is_skipped_for_budget(db_session: Session) -> None:
    scan = _completed_scan(db_session)
    db_session.add(
        LLMUsage(
            org_id=scan.org_id,
            provider=ProviderKind.ANTHROPIC,
            model=MODEL,
            purpose="triage",
            key_source=KeySource.INSTANCE,
            input_tokens=900,
            output_tokens=100,
            usage_reported=True,
            estimated_cost_usd=None,
            latency_ms=100,
            success=True,
        )
    )
    coordinator = _job(db_session, scan, "triage")
    queue = RecordingPipelineQueue(db_session)

    triage.run_triage(db_session, queue, scan.org_id, coordinator.id, _settings(budget=1_000))

    assert queue.enqueued == []
    assert _refreshed(db_session, coordinator).status is JobStatus.SKIPPED


# --- Input selection -----------------------------------------------------------------------


def test_build_summary_input_orders_triaged_first_ignores_stale_and_respects_caps(
    db_session: Session,
) -> None:
    scan = _completed_scan(db_session)
    scan.stats = {
        "findings": {
            "new": {"total": 2, "by_severity": {"high": 2}},
            "fixed": {"total": 0, "by_severity": {}},
            "regressed": {"total": 0, "by_severity": {}},
            "total": {"total": 2, "by_severity": {"high": 2}},
        },
        "assets": {
            "new": {
                "total": 1,
                "assets": [
                    {"id": "not-sent", "type": "subdomain", "value": "jenkins.acme.example"}
                ],
            },
            "disappeared": {"total": 0, "assets": []},
        },
    }
    jenkins = _subdomain(db_session, scan, "jenkins")
    _subdomain(db_session, scan, "gone", active=False)
    other_root = record_asset(
        db_session, scan.org_id, AssetType.DOMAIN, "other.example", source=AssetSource.USER
    )
    record_asset(
        db_session,
        scan.org_id,
        AssetType.SUBDOMAIN,
        "admin.other.example",
        source=AssetSource.DISCOVERED,
        parent_id=other_root.id,
    )

    untriaged_critical = _observed(
        db_session,
        scan,
        scan.root_asset_id,
        location="untriaged-crit",
        severity=Severity.CRITICAL,
    )
    stale_p1 = _observed(
        db_session, scan, scan.root_asset_id, location="stale-p1", severity=Severity.LOW
    )
    _judge(db_session, stale_p1, priority="P1", adjusted="critical", stale=True)
    triaged_p2 = _observed(
        db_session, scan, jenkins.id, location="triaged-p2", severity=Severity.MEDIUM
    )
    _judge(db_session, triaged_p2, priority="P2", adjusted="high", rationale="Current triage.")
    triaged_p1 = _observed(
        db_session, scan, jenkins.id, location="triaged-p1", severity=Severity.LOW
    )
    _judge(db_session, triaged_p1, priority="P1", adjusted="critical", rationale="Top priority.")
    _observed(
        db_session,
        scan,
        jenkins.id,
        location="suppressed",
        status=FindingStatus.ACCEPTED_RISK,
    )

    built = summary.build_summary_input(db_session, scan.org_id, scan.id)

    assert built.root_domain == "acme.example"
    assert built.changes is not None
    assert built.changes.new_findings.total == 2
    assert built.changes.new_assets.names == ("jenkins.acme.example",)
    assert [f.finding_id for f in built.findings] == [
        triaged_p1.id,
        triaged_p2.id,
        untriaged_critical.id,
        stale_p1.id,
    ]
    assert [f.ref for f in built.findings] == ["F1", "F2", "F3", "F4"]
    assert built.findings[0].triage is not None
    assert built.findings[0].triage.rationale == "Top priority."
    assert built.findings[3].triage is None  # stale triage ignored
    assert [a.name for a in built.assets] == ["acme.example", "jenkins.acme.example"]
    assert [a.ref for a in built.assets] == ["A1", "A2"]


def test_build_summary_input_caps_findings_at_25_and_assets_at_200(db_session: Session) -> None:
    scan = _completed_scan(db_session)
    for index in range(MAX_SUMMARY_FINDINGS + 5):
        _observed(db_session, scan, scan.root_asset_id, location=f"loc-{index:03d}")
    for index in range(MAX_SUMMARY_ASSETS + 5):
        _subdomain(db_session, scan, f"host-{index:03d}")

    built = summary.build_summary_input(db_session, scan.org_id, scan.id)

    assert len(built.findings) == MAX_SUMMARY_FINDINGS == 25
    assert len(built.assets) == MAX_SUMMARY_ASSETS == 200


def test_build_summary_input_isolates_tenants(db_session: Session) -> None:
    scan = _completed_scan(db_session, "acme")
    other = _completed_scan(db_session, "globex")
    _observed(db_session, other, other.root_asset_id, title="Globex secret finding")

    built = summary.build_summary_input(db_session, scan.org_id, scan.id)

    assert built.findings == ()
    assert [a.name for a in built.assets] == ["acme.example"]
    with pytest.raises(ScanNotFound):
        summary.build_summary_input(db_session, other.org_id, scan.id)


# --- Running ai.summarize ------------------------------------------------------------------


def test_run_summary_stores_only_real_ids_and_records_usage(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Acceptance criterion of #26: a stored summary only ever references real finding and asset IDs.
    scan = _completed_scan(db_session)
    jenkins = _subdomain(db_session, scan, "jenkins")
    finding = _observed(db_session, scan, jenkins.id)
    job = _job(db_session, scan)
    reply = _reply(
        key_risks=[
            {"finding_ref": "F99", "why": "Invented finding."},
            {"finding_ref": "F1", "why": "Real finding."},
            {"finding_ref": "F1", "why": "Duplicate."},
        ],
        notable_assets=[
            {"asset_ref": "A99", "reason": "Invented asset."},
            {"asset_ref": "A2", "reason": "Exposed Jenkins host."},
            {"asset_ref": "A2", "reason": "Duplicate."},
        ],
    )
    _use_provider(monkeypatch, FakeLLMProvider(reply))

    summary.run_summary(db_session, scan.org_id, job.id, _settings(), retry_allowed=True)

    stored = summary.stored_summary(_refreshed(db_session, scan))
    assert stored is not None
    assert [risk.finding_id for risk in stored.key_risks] == [finding.id]
    assert [asset.asset_id for asset in stored.notable_assets] == [jenkins.id]
    assert stored.prompt_version == "summary/v1"
    [usage] = _usage(db_session, scan)
    assert (usage.purpose, usage.success, usage.key_source) == (
        SUMMARY_PURPOSE,
        True,
        KeySource.INSTANCE,
    )
    assert _refreshed(db_session, scan).status is ScanStatus.COMPLETED


def test_redelivered_summary_job_does_not_pay_twice(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _completed_scan(db_session)
    _observed(db_session, scan, scan.root_asset_id)
    job = _job(db_session, scan)
    provider = FakeLLMProvider(_reply())  # one reply: a second call would fail the test
    _use_provider(monkeypatch, provider)

    summary.run_summary(db_session, scan.org_id, job.id, _settings(), retry_allowed=True)
    summary.run_summary(db_session, scan.org_id, job.id, _settings(), retry_allowed=True)

    assert len(provider.calls) == 1
    assert len(_usage(db_session, scan)) == 1


def test_summary_is_skipped_when_budget_is_spent(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _completed_scan(db_session)
    db_session.add(
        LLMUsage(
            org_id=scan.org_id,
            provider=ProviderKind.ANTHROPIC,
            model=MODEL,
            purpose="triage",
            key_source=KeySource.INSTANCE,
            input_tokens=900,
            output_tokens=100,
            usage_reported=True,
            estimated_cost_usd=None,
            latency_ms=100,
            success=True,
        )
    )
    job = _job(db_session, scan)
    provider = FakeLLMProvider()
    _use_provider(monkeypatch, provider)

    summary.run_summary(
        db_session, scan.org_id, job.id, _settings(budget=1_000), retry_allowed=True
    )

    refreshed = _refreshed(db_session, job)
    assert refreshed.status is JobStatus.SKIPPED
    assert "budget exceeded" in (refreshed.error or "").lower()
    assert provider.calls == []
    assert _refreshed(db_session, scan).ai_summary is None


def test_summary_is_skipped_when_domain_is_archived(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _completed_scan(db_session)
    db_session.execute(
        update(Asset)
        .where(Asset.id == scan.root_asset_id)
        .values(is_active=False, deactivated_at=func.now())
    )
    job = _job(db_session, scan)
    provider = FakeLLMProvider()
    _use_provider(monkeypatch, provider)

    summary.run_summary(db_session, scan.org_id, job.id, _settings(), retry_allowed=True)

    refreshed = _refreshed(db_session, job)
    assert refreshed.status is JobStatus.SKIPPED
    assert refreshed.error == "The domain was archived."
    assert provider.calls == []


def test_invalid_reply_fails_only_the_summary_job_and_records_usage(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _completed_scan(db_session)
    finding = _observed(db_session, scan, scan.root_asset_id)
    _judge(db_session, finding)
    job = _job(db_session, scan)
    _use_provider(monkeypatch, FakeLLMProvider("not json", "still not json"))

    summary.run_summary(db_session, scan.org_id, job.id, _settings(), retry_allowed=True)

    refreshed_job = _refreshed(db_session, job)
    assert refreshed_job.status is JobStatus.FAILED
    assert refreshed_job.error.startswith("LLMOutputError: ")
    [usage] = _usage(db_session, scan)
    assert (usage.purpose, usage.success, usage.error_type, usage.input_tokens) == (
        SUMMARY_PURPOSE,
        False,
        "LLMOutputError",
        20,
    )
    assert _refreshed(db_session, scan).status is ScanStatus.COMPLETED
    assert _refreshed(db_session, scan).ai_summary is None
    assert triage.stored_triage(_refreshed(db_session, finding)) is not None


def test_unavailable_provider_retries_then_fails_job_with_usage(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _completed_scan(db_session)
    job = _job(db_session, scan)
    busy = LLMUnavailable("The AI provider is busy.", usage=TokenUsage(12, 0))
    _use_provider(monkeypatch, FakeLLMProvider(busy))

    with pytest.raises(LLMUnavailable):
        summary.run_summary(db_session, scan.org_id, job.id, _settings(), retry_allowed=True)

    [first_usage] = _usage(db_session, scan)
    assert (first_usage.purpose, first_usage.success, first_usage.input_tokens) == (
        SUMMARY_PURPOSE,
        False,
        12,
    )

    _use_provider(monkeypatch, FakeLLMProvider(busy))
    summary.run_summary(db_session, scan.org_id, job.id, _settings(), retry_allowed=False)

    assert _refreshed(db_session, job).status is JobStatus.FAILED
    assert len(_usage(db_session, scan)) == 2


def test_run_summary_never_reads_another_orgs_job(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _completed_scan(db_session, "acme")
    other = _completed_scan(db_session, "globex")
    job = _job(db_session, scan)
    _use_provider(monkeypatch, FakeLLMProvider())

    with pytest.raises(JobNotFound):
        summary.run_summary(db_session, other.org_id, job.id, _settings(), retry_allowed=True)


# --- Notable asset tagging (ADR 0030) ------------------------------------------------------


def test_run_summary_adds_and_removes_notable_tag_while_preserving_other_tags(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _completed_scan(db_session)
    jenkins = _subdomain(db_session, scan, "jenkins")
    staging = _subdomain(db_session, scan, "staging")
    www = _subdomain(db_session, scan, "www")
    jenkins.tags = ["ci"]
    staging.tags = ["preprod", summary.NOTABLE_TAG]
    www.tags = ["public", summary.NOTABLE_TAG]
    db_session.flush()

    # Sorted active assets: A1=acme.example, A2=jenkins, A3=staging, A4=www
    job = _job(db_session, scan)
    reply = _reply(
        key_risks=[],
        notable_assets=[{"asset_ref": "A2", "reason": "Exposed Jenkins server."}],
    )
    _use_provider(monkeypatch, FakeLLMProvider(reply))

    summary.run_summary(db_session, scan.org_id, job.id, _settings(), retry_allowed=True)

    assert _refreshed(db_session, jenkins).tags == ["ci", "notable"]
    assert _refreshed(db_session, staging).tags == ["preprod"]
    assert _refreshed(db_session, www).tags == ["public"]


@pytest.mark.parametrize("same_created_at", [False, True])
@pytest.mark.parametrize("newer_has_summary", [False, True])
def test_older_summary_preserves_newer_notable_tags(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    same_created_at: bool,
    newer_has_summary: bool,
) -> None:
    older = _completed_scan(db_session)
    older.created_at = datetime(2026, 11, 19, tzinfo=UTC)
    jenkins = _subdomain(db_session, older, "jenkins")
    staging = _subdomain(db_session, older, "staging")
    jenkins.tags = ["ci"]
    staging.tags = ["preprod"]
    newer = Scan(
        id=UUID("ffffffff-ffff-7fff-bfff-ffffffffffff"),
        org_id=older.org_id,
        root_asset_id=older.root_asset_id,
        profile=older.profile,
        status=ScanStatus.COMPLETED,
        triggered_by=older.triggered_by,
        created_at=older.created_at if same_created_at else datetime(2026, 11, 20, tzinfo=UTC),
    )
    db_session.add(newer)
    older_job = _job(db_session, older)
    newer_job = _job(db_session, newer)
    newer_reply = _reply(
        key_risks=[],
        notable_assets=[{"asset_ref": "A3", "reason": "Sensitive staging host."}],
    )
    older_reply = _reply(
        key_risks=[],
        notable_assets=[{"asset_ref": "A2", "reason": "Exposed Jenkins host."}],
    )
    provider = FakeLLMProvider(
        *([newer_reply, older_reply] if newer_has_summary else [older_reply])
    )
    _use_provider(monkeypatch, provider)
    if newer_has_summary:
        summary.run_summary(db_session, newer.org_id, newer_job.id, _settings(), retry_allowed=True)

    summary.run_summary(db_session, older.org_id, older_job.id, _settings(), retry_allowed=True)

    stored = summary.stored_summary(_refreshed(db_session, older))
    assert stored is not None
    assert [asset.asset_id for asset in stored.notable_assets] == [jenkins.id]
    assert _refreshed(db_session, jenkins).tags == (
        ["ci"] if newer_has_summary else ["ci", "notable"]
    )
    assert _refreshed(db_session, staging).tags == (
        ["preprod", "notable"] if newer_has_summary else ["preprod"]
    )
    assert len(_usage(db_session, older)) == len(provider.calls)


def test_notable_tagging_never_touches_another_root_or_another_org(db_session: Session) -> None:
    acme_scan = _completed_scan(db_session, "acme")
    acme_host = _subdomain(db_session, acme_scan, "jenkins")
    other_root = record_asset(
        db_session, acme_scan.org_id, AssetType.DOMAIN, "second.example", source=AssetSource.USER
    )
    other_root_host = record_asset(
        db_session,
        acme_scan.org_id,
        AssetType.SUBDOMAIN,
        "admin.second.example",
        source=AssetSource.DISCOVERED,
        parent_id=other_root.id,
    )
    other_root_host.tags = ["keep", summary.NOTABLE_TAG]

    globex_scan = _completed_scan(db_session, "globex")
    globex_host = record_asset(
        db_session,
        globex_scan.org_id,
        AssetType.SUBDOMAIN,
        "vpn.globex.example",
        source=AssetSource.DISCOVERED,
        parent_id=globex_scan.root_asset_id,
    )
    globex_host.tags = ["corp"]
    db_session.flush()

    # Even if IDs from another root or org are passed, only acme_scan's root is touched.
    summary.apply_notable_tags(
        db_session,
        acme_scan.org_id,
        acme_scan.root_asset_id,
        [acme_host.id, other_root.id, globex_host.id],
    )
    db_session.commit()

    assert _refreshed(db_session, acme_host).tags == ["notable"]
    assert _refreshed(db_session, other_root).tags == []
    assert _refreshed(db_session, other_root_host).tags == ["keep", "notable"]
    assert _refreshed(db_session, globex_host).tags == ["corp"]
