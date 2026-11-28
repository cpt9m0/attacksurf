"""Triage selection and storage (ADR 0029): which findings a scan sends, and where judgments go."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from pydantic import SecretStr
from sqlalchemy.orm import Session

from attacksurf.ai.schemas import FindingTriage, StoredTriage
from attacksurf.ai.triage import TRIAGE_PROMPT_VERSION, TriageCacheInput, triage_cache_key
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.findings import Confidence, EvidenceKind, FindingStatus, Severity
from attacksurf.domain.llm import KeySource, LLMConfig, ProviderKind
from attacksurf.infra.db.models import Asset, Evidence, Finding, FindingObservation, Scan
from attacksurf.services.assets import record_asset
from attacksurf.services.finding_views import get_finding_detail
from attacksurf.services.triage import (
    assets_to_triage,
    build_asset_batch,
    finding_cache_key,
    store_triage,
    stored_triage,
    triage_is_stale,
    url_context_digests,
)
from attacksurf.services.triage_views import get_scan_triage
from tests.integration.factories import T0, make_finding, make_scan

MODEL = "muse-spark-1.3"
NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)


def _config(model: str = MODEL) -> LLMConfig:
    return LLMConfig(
        provider=ProviderKind.ANTHROPIC,
        model=model,
        api_key=SecretStr("instance-key"),
        source=KeySource.INSTANCE,
    )


def _subdomain(session: Session, scan: Scan, name: str = "cdn") -> Asset:
    return record_asset(
        session,
        scan.org_id,
        AssetType.SUBDOMAIN,
        f"{name}.acme.example",
        source=AssetSource.DISCOVERED,
        parent_id=scan.root_asset_id,
    )


def _observed(session: Session, scan: Scan, asset_id: UUID, **fields: Any) -> Finding:
    finding = make_finding(session, scan.org_id, asset_id, **fields)
    session.add(
        FindingObservation(
            org_id=scan.org_id, scan_id=scan.id, finding_id=finding.id, severity=finding.severity
        )
    )
    session.flush()
    return finding


def _judgment(ref: str = "F1") -> FindingTriage:
    return FindingTriage.model_validate(
        {
            "ref": ref,
            "adjusted_severity": "critical",
            "confidence": "high",
            "false_positive_likelihood": "low",
            "priority": "P1",
            "rationale": "The record points at an unclaimed resource.",
            "exploitability": "Anyone can claim it.",
            "remediation_steps": ["Remove the record."],
        }
    )


def _judge(session: Session, finding: Finding, model: str = MODEL) -> None:
    digest = url_context_digests(session, finding.org_id, [finding.asset_id]).get(finding.asset_id)
    finding.ai_triage = StoredTriage.from_judgment(
        _judgment(),
        prompt_version=TRIAGE_PROMPT_VERSION,
        config=_config(model),
        cache_key=finding_cache_key(finding, model, context_digest=digest),
        triaged_at=NOW,
    ).model_dump(mode="json")
    session.flush()


def _assets(session: Session, scan: Scan, *, include_info: bool = False) -> list[UUID]:
    return assets_to_triage(session, scan.org_id, scan.id, model=MODEL, include_info=include_info)


def _rules(
    session: Session, scan: Scan, asset_id: UUID, *, include_info: bool = False
) -> list[str]:
    planned = build_asset_batch(
        session, scan.org_id, scan.id, asset_id, model=MODEL, include_info=include_info
    )
    return [] if planned is None else [finding.rule_id for finding in planned.batch.findings]


# --- Which findings a scan sends -----------------------------------------------------------


def test_assets_with_untriaged_findings_are_listed(db_session: Session) -> None:
    scan = make_scan(db_session)
    with_findings = _subdomain(db_session, scan, "cdn")
    _subdomain(db_session, scan, "www")
    _observed(db_session, scan, with_findings.id)

    assert _assets(db_session, scan) == [with_findings.id]


def test_only_findings_this_scan_observed_are_sent(db_session: Session) -> None:
    scan = make_scan(db_session)
    make_finding(db_session, scan.org_id, scan.root_asset_id, rule_id="dns.caa.missing")
    _observed(db_session, scan, scan.root_asset_id, rule_id="dns.email.spf_missing")

    assert _rules(db_session, scan, scan.root_asset_id) == ["dns.email.spf_missing"]


@pytest.mark.parametrize(
    ("status", "sent"),
    [
        (FindingStatus.OPEN, True),
        (FindingStatus.REGRESSED, True),
        (FindingStatus.FIXED, False),
        (FindingStatus.ACCEPTED_RISK, False),
        (FindingStatus.FALSE_POSITIVE, False),
    ],
)
def test_only_active_findings_are_sent(
    db_session: Session, status: FindingStatus, sent: bool
) -> None:
    scan = make_scan(db_session)
    _observed(db_session, scan, scan.root_asset_id, status=status)

    assert bool(_rules(db_session, scan, scan.root_asset_id)) is sent


@pytest.mark.parametrize("include_info", [False, True])
def test_info_findings_are_sent_only_when_included(db_session: Session, include_info: bool) -> None:
    scan = make_scan(db_session)
    _observed(db_session, scan, scan.root_asset_id, severity=Severity.INFO)

    rules = _rules(db_session, scan, scan.root_asset_id, include_info=include_info)

    assert bool(rules) is include_info
    assert bool(_assets(db_session, scan, include_info=include_info)) is include_info


def test_a_current_judgment_is_not_sent_again(db_session: Session) -> None:
    scan = make_scan(db_session)
    _judge(db_session, _observed(db_session, scan, scan.root_asset_id))

    assert _rules(db_session, scan, scan.root_asset_id) == []
    assert _assets(db_session, scan) == []


def test_a_judgment_from_another_model_is_sent_again(db_session: Session) -> None:
    scan = make_scan(db_session)
    _judge(db_session, _observed(db_session, scan, scan.root_asset_id), model="older-model")

    assert _rules(db_session, scan, scan.root_asset_id) == ["dns.email.dmarc_missing"]


def test_changed_evidence_is_sent_again(db_session: Session) -> None:
    scan = make_scan(db_session)
    finding = _observed(db_session, scan, scan.root_asset_id)
    _judge(db_session, finding)
    finding.evidence_digest = "f" * 64  # a later scan saw different evidence
    db_session.flush()

    assert _rules(db_session, scan, scan.root_asset_id) == ["dns.email.dmarc_missing"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", Severity.CRITICAL),
        ("confidence", Confidence.LOW),
        ("title", "DMARC record missing"),
        ("description", "Reworded by a rule catalog update."),
    ],
)
def test_a_changed_finding_the_prompt_shows_is_sent_again(
    db_session: Session, field: str, value: object
) -> None:
    # Regression: a later scan updated these (`_upsert_finding`) under the same fingerprint and
    # evidence, the model had judged the old values, and the stale judgment counted as current.
    scan = make_scan(db_session)
    finding = _observed(db_session, scan, scan.root_asset_id)
    _judge(db_session, finding)
    setattr(finding, field, value)
    db_session.flush()

    assert _rules(db_session, scan, scan.root_asset_id) == ["dns.email.dmarc_missing"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", Severity.CRITICAL),
        ("confidence", Confidence.LOW),
        ("title", "DMARC record missing"),
        ("description", "Reworded by a rule catalog update."),
        ("evidence_digest", "f" * 64),
    ],
)
def test_a_judgment_goes_stale_when_its_finding_changes(
    db_session: Session, field: str, value: object
) -> None:
    # Regression: pages showed the old judgment as current until a new run replaced it, which
    # never happens when that run is skipped or fails.
    scan = make_scan(db_session)
    finding = _observed(db_session, scan, scan.root_asset_id)
    _judge(db_session, finding)
    stored = stored_triage(finding)
    assert stored is not None
    assert not triage_is_stale(finding, stored)

    setattr(finding, field, value)

    assert triage_is_stale(finding, stored)


def test_a_judgment_by_another_model_is_not_stale(db_session: Session) -> None:
    # A new model or prompt version schedules a fresh judgment, but the old one still describes
    # this finding as it is: only a change to the finding makes a judgment stale.
    scan = make_scan(db_session)
    finding = _observed(db_session, scan, scan.root_asset_id)
    _judge(db_session, finding, model="older-model")
    stored = stored_triage(finding)
    assert stored is not None

    assert not triage_is_stale(finding, stored)


def test_a_stored_judgment_that_does_not_parse_counts_as_untriaged(db_session: Session) -> None:
    scan = make_scan(db_session)
    finding = _observed(db_session, scan, scan.root_asset_id)
    finding.ai_triage = {"written": "by an older version"}
    db_session.flush()

    assert stored_triage(finding) is None
    assert _rules(db_session, scan, scan.root_asset_id) == ["dns.email.dmarc_missing"]


def test_another_orgs_findings_never_enter_a_batch(db_session: Session) -> None:
    scan = make_scan(db_session)
    _observed(db_session, scan, scan.root_asset_id)
    other = make_scan(db_session, "other")

    assert assets_to_triage(db_session, other.org_id, scan.id, model=MODEL, include_info=True) == []
    assert (
        build_asset_batch(
            db_session, other.org_id, scan.id, scan.root_asset_id, model=MODEL, include_info=True
        )
        is None
    )


# --- One asset's batch ---------------------------------------------------------------------


def test_a_batch_numbers_refs_most_severe_first(db_session: Session) -> None:
    scan = make_scan(db_session)
    low = _observed(
        db_session, scan, scan.root_asset_id, rule_id="dns.caa.missing", severity=Severity.LOW
    )
    critical = _observed(
        db_session,
        scan,
        scan.root_asset_id,
        rule_id="dns.takeover.dangling_cname",
        severity=Severity.CRITICAL,
    )

    planned = build_asset_batch(
        db_session, scan.org_id, scan.id, scan.root_asset_id, model=MODEL, include_info=False
    )

    assert planned is not None
    assert planned.asset_id == scan.root_asset_id
    assert planned.batch.asset_value == "acme.example"
    assert planned.batch.asset_type is AssetType.DOMAIN
    assert [(f.ref, f.rule_id) for f in planned.batch.findings] == [
        ("F1", "dns.takeover.dangling_cname"),
        ("F2", "dns.caa.missing"),
    ]
    assert planned.finding_ids == {"F1": critical.id, "F2": low.id}
    assert planned.cache_keys["F1"] == finding_cache_key(critical, MODEL)


def test_a_batch_holds_twenty_findings_and_the_rest_come_next(db_session: Session) -> None:
    scan = make_scan(db_session)
    for index in range(25):
        _observed(db_session, scan, scan.root_asset_id, location=f"selector{index:02d}")

    first = build_asset_batch(
        db_session, scan.org_id, scan.id, scan.root_asset_id, model=MODEL, include_info=False
    )
    assert first is not None
    assert len(first.batch.findings) == 20
    store_triage(
        db_session,
        scan.org_id,
        first,
        {ref: _judgment(ref) for ref in first.finding_ids},
        config=_config(),
        triaged_at=NOW,
    )

    second = build_asset_batch(
        db_session, scan.org_id, scan.id, scan.root_asset_id, model=MODEL, include_info=False
    )
    assert second is not None
    assert len(second.batch.findings) == 5
    assert not set(second.finding_ids.values()) & set(first.finding_ids.values())


def test_a_batch_carries_each_findings_latest_evidence(db_session: Session) -> None:
    scan = make_scan(db_session)
    finding = _observed(db_session, scan, scan.root_asset_id)
    for minutes in range(7):
        db_session.add(
            Evidence(
                org_id=scan.org_id,
                finding_id=finding.id,
                kind=EvidenceKind.DNS_RECORD,
                data={"value": f"record {minutes}"},
                captured_at=T0 + timedelta(minutes=minutes),
            )
        )
    db_session.flush()

    planned = build_asset_batch(
        db_session, scan.org_id, scan.id, scan.root_asset_id, model=MODEL, include_info=False
    )

    assert planned is not None
    values = [dict(item.data)["value"] for item in planned.batch.findings[0].evidence]
    assert values == ["record 6", "record 5", "record 4", "record 3", "record 2"]


def test_nothing_to_triage_builds_no_batch(db_session: Session) -> None:
    scan = make_scan(db_session)

    assert (
        build_asset_batch(
            db_session, scan.org_id, scan.id, scan.root_asset_id, model=MODEL, include_info=True
        )
        is None
    )


# --- Storing judgments ---------------------------------------------------------------------


def test_store_triage_writes_judgments_without_touching_the_finding(db_session: Session) -> None:
    scan = make_scan(db_session)
    finding = _observed(db_session, scan, scan.root_asset_id, severity=Severity.MEDIUM)
    planned = build_asset_batch(
        db_session, scan.org_id, scan.id, scan.root_asset_id, model=MODEL, include_info=False
    )
    assert planned is not None

    stored = store_triage(
        db_session, scan.org_id, planned, {"F1": _judgment()}, config=_config(), triaged_at=NOW
    )

    assert stored == 1
    db_session.flush()  # a building block: its caller commits
    db_session.expire_all()
    refreshed = db_session.get(Finding, finding.id)
    assert refreshed is not None
    triage = stored_triage(refreshed)
    assert triage is not None
    assert triage.adjusted_severity is Severity.CRITICAL
    assert triage.cache_key == planned.cache_keys["F1"]
    assert triage.model == MODEL
    assert refreshed.severity is Severity.MEDIUM  # the scanner's severity stays
    assert refreshed.status is FindingStatus.OPEN  # the AI never changes the status


def test_store_triage_ignores_refs_outside_the_batch(db_session: Session) -> None:
    scan = make_scan(db_session)
    _observed(db_session, scan, scan.root_asset_id)
    planned = build_asset_batch(
        db_session, scan.org_id, scan.id, scan.root_asset_id, model=MODEL, include_info=False
    )
    assert planned is not None

    stored = store_triage(
        db_session, scan.org_id, planned, {"F7": _judgment("F7")}, config=_config(), triaged_at=NOW
    )

    assert stored == 0


def test_store_triage_never_writes_another_orgs_finding(db_session: Session) -> None:
    scan = make_scan(db_session)
    finding = _observed(db_session, scan, scan.root_asset_id)
    planned = build_asset_batch(
        db_session, scan.org_id, scan.id, scan.root_asset_id, model=MODEL, include_info=False
    )
    assert planned is not None
    other = make_scan(db_session, "other")

    stored = store_triage(
        db_session, other.org_id, planned, {"F1": _judgment()}, config=_config(), triaged_at=NOW
    )

    assert stored == 0
    db_session.flush()  # without it, a wrong write would be discarded and the test pass anyway
    db_session.expire_all()
    refreshed = db_session.get(Finding, finding.id)
    assert refreshed is not None
    assert refreshed.ai_triage is None


def test_url_batch_includes_web_context_headers_tech_and_other_findings(
    db_session: Session,
) -> None:
    scan = make_scan(db_session)
    url = record_asset(
        db_session,
        scan.org_id,
        AssetType.URL,
        "https://admin.acme.example/",
        source=AssetSource.DISCOVERED,
        parent_id=scan.root_asset_id,
    )
    url.details = {
        "web": {
            "status_code": 200,
            "title": "Acme Admin",
            "content_type": "text/html; charset=utf-8",
            "headers": {
                "server": "Apache/2.4.49",
                "set-cookie": "session=<redacted>",
                "authorization": "Bearer tok",
            },
        },
        "technologies": [
            {"name": "Apache HTTP Server", "version": "2.4.49", "categories": ["Web servers"]}
        ],
    }
    db_session.flush()
    vuln = _observed(
        db_session,
        scan,
        url.id,
        rule_id="web.components.known_vulnerable",
        title="Web component matches known vulnerabilities",
        severity=Severity.CRITICAL,
        location="apache http server",
    )
    admin_panel = _observed(
        db_session,
        scan,
        url.id,
        rule_id="web.exposure.admin_panel",
        title="Publicly reachable administrative or login interface",
        severity=Severity.INFO,
        location="/admin",
    )
    already_triaged = make_finding(
        db_session,
        scan.org_id,
        url.id,
        rule_id="web.headers.csp_missing",
        title="HTML response lacks Content-Security-Policy header",
        severity=Severity.LOW,
        location="csp",
    )
    _judge(db_session, already_triaged)
    fixed = make_finding(
        db_session,
        scan.org_id,
        url.id,
        rule_id="web.exposure.env_file",
        title="Fixed env",
        severity=Severity.CRITICAL,
        status=FindingStatus.FIXED,
        location="/.env",
    )
    other_org = make_scan(db_session, "other")
    make_finding(
        db_session,
        other_org.org_id,
        other_org.root_asset_id,
        rule_id="web.exposure.git_repo",
        title="Other org finding",
        severity=Severity.HIGH,
        location="/.git/HEAD",
    )

    planned = build_asset_batch(
        db_session, scan.org_id, scan.id, url.id, model=MODEL, include_info=False
    )

    assert planned is not None
    assert planned.finding_ids == {"F1": vuln.id}
    ctx = planned.batch.web_context
    assert ctx is not None
    assert ctx.host == "admin.acme.example"
    assert ctx.host_hints == ("admin",)
    assert ctx.status_code == 200
    assert ctx.title == "Acme Admin"
    assert ctx.headers == {"server": "Apache/2.4.49"}
    assert [tech.name for tech in ctx.technologies] == ["Apache HTTP Server"]
    other_rules = [other.rule_id for other in ctx.other_findings]
    assert admin_panel.rule_id in other_rules
    assert already_triaged.rule_id in other_rules
    assert vuln.rule_id not in other_rules
    assert fixed.rule_id not in other_rules
    assert "web.exposure.git_repo" not in other_rules


def test_triage_v1_judgment_stays_not_stale_while_v2_reschedules(db_session: Session) -> None:
    scan = make_scan(db_session)
    finding = _observed(db_session, scan, scan.root_asset_id)
    v1_key = triage_cache_key(
        "triage/v1",
        MODEL,
        TriageCacheInput(
            fingerprint=finding.fingerprint,
            evidence_digest=finding.evidence_digest,
            severity=finding.severity,
            confidence=finding.confidence,
            title=finding.title,
            description=finding.description,
        ),
    )
    finding.ai_triage = StoredTriage.from_judgment(
        _judgment(),
        prompt_version="triage/v1",
        config=_config(),
        cache_key=v1_key,
        triaged_at=NOW,
    ).model_dump(mode="json")
    db_session.flush()
    stored = stored_triage(finding)
    assert stored is not None
    assert not triage_is_stale(finding, stored)
    assert _rules(db_session, scan, scan.root_asset_id) == [finding.rule_id]


def test_url_triage_cache_invalidates_when_sibling_finding_is_added_or_fixed(
    db_session: Session,
) -> None:
    scan = make_scan(db_session)
    url = record_asset(
        db_session,
        scan.org_id,
        AssetType.URL,
        "https://admin.acme.example/",
        source=AssetSource.DISCOVERED,
        parent_id=scan.root_asset_id,
    )
    url.details = {
        "web": {
            "status_code": 200,
            "title": "Admin Console",
            "headers": {
                "server": "Apache",
                "date": "Fri, 28 Nov 2026 01:00:00 GMT",
                "x-request-id": "req-1",
            },
        },
        "technologies": [{"name": "Apache HTTP Server", "version": "2.4.49"}],
    }
    db_session.flush()
    vuln = _observed(
        db_session,
        scan,
        url.id,
        rule_id="web.components.known_vulnerable",
        title="Web component matches known vulnerabilities",
        severity=Severity.CRITICAL,
        location="apache http server",
    )

    first = build_asset_batch(
        db_session, scan.org_id, scan.id, url.id, model=MODEL, include_info=False
    )
    assert first is not None
    assert first.batch.web_context is not None
    assert first.batch.web_context.headers == {"server": "Apache"}
    store_triage(
        db_session, scan.org_id, first, {"F1": _judgment()}, config=_config(), triaged_at=NOW
    )
    db_session.flush()

    # Changing per-request volatile headers on the next probe must stay a cache hit.
    url.details = {
        "web": {
            "status_code": 200,
            "title": "Admin Console",
            "headers": {
                "server": "Apache",
                "date": "Fri, 28 Nov 2026 02:00:00 GMT",
                "x-request-id": "req-2",
            },
        },
        "technologies": [{"name": "Apache HTTP Server", "version": "2.4.49"}],
    }
    db_session.flush()

    assert _assets(db_session, scan) == []
    assert get_finding_detail(db_session, scan.org_id, vuln.id).ai_triage_stale is False
    assert get_scan_triage(db_session, scan.org_id, scan.id).rows[0].stale is False

    # Adding a sibling admin-panel finding must invalidate the URL component's cache and stale view.
    admin_panel = _observed(
        db_session,
        scan,
        url.id,
        rule_id="web.exposure.admin_panel",
        title="Publicly reachable administrative or login interface",
        severity=Severity.INFO,
        location="/admin",
    )
    digests = url_context_digests(db_session, scan.org_id, [url.id])
    stored = stored_triage(vuln)
    assert stored is not None
    assert triage_is_stale(vuln, stored, context_digest=digests[url.id]) is True
    assert get_finding_detail(db_session, scan.org_id, vuln.id).ai_triage_stale is True
    assert get_scan_triage(db_session, scan.org_id, scan.id).rows[0].stale is True

    second = build_asset_batch(
        db_session, scan.org_id, scan.id, url.id, model=MODEL, include_info=False
    )
    assert second is not None
    assert second.batch.web_context is not None
    assert [other.rule_id for other in second.batch.web_context.other_findings] == [
        "web.exposure.admin_panel"
    ]
    store_triage(
        db_session, scan.org_id, second, {"F1": _judgment()}, config=_config(), triaged_at=NOW
    )
    db_session.flush()
    assert _assets(db_session, scan) == []

    # Resolving the sibling admin-panel finding must likewise invalidate the cached judgment.
    admin_panel.status = FindingStatus.FIXED
    admin_panel.fixed_at = NOW
    db_session.flush()
    digests_after_fix = url_context_digests(db_session, scan.org_id, [url.id])
    stored_after = stored_triage(vuln)
    assert stored_after is not None
    assert triage_is_stale(vuln, stored_after, context_digest=digests_after_fix[url.id]) is True

    third = build_asset_batch(
        db_session, scan.org_id, scan.id, url.id, model=MODEL, include_info=False
    )
    assert third is not None
    assert third.batch.web_context is not None
    assert third.batch.web_context.other_findings == ()

    # Historical triage/v1 judgments on URLs are never marked stale by context_digest alone.
    v1_key = triage_cache_key(
        "triage/v1",
        MODEL,
        TriageCacheInput(
            fingerprint=vuln.fingerprint,
            evidence_digest=vuln.evidence_digest,
            severity=vuln.severity,
            confidence=vuln.confidence,
            title=vuln.title,
            description=vuln.description,
        ),
    )
    vuln.ai_triage = StoredTriage.from_judgment(
        _judgment(),
        prompt_version="triage/v1",
        config=_config(),
        cache_key=v1_key,
        triaged_at=NOW,
    ).model_dump(mode="json")
    db_session.flush()
    stored_v1 = stored_triage(vuln)
    assert stored_v1 is not None
    assert triage_is_stale(vuln, stored_v1, context_digest=digests_after_fix[url.id]) is False
