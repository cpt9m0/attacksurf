"""The exposure summary contract (ADR 0030): what goes in, what comes out, and what is stored."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import anthropic
import pytest
from openai.lib._pydantic import to_strict_json_schema
from pydantic import ValidationError

from attacksurf.ai.schemas import (
    MAX_CHAIN_FINDINGS,
    MAX_CHAIN_TITLE_LENGTH,
    MAX_CHAIN_WHY_LENGTH,
    MAX_CHANGES_LENGTH,
    MAX_HEADLINE_LENGTH,
    MAX_KEY_RISK_WHY_LENGTH,
    MAX_KEY_RISKS,
    MAX_NEXT_ACTION_LENGTH,
    MAX_NEXT_ACTIONS,
    MAX_NOTABLE_ASSETS,
    MAX_NOTABLE_REASON_LENGTH,
    MAX_RISK_CHAINS,
    MAX_WEB_EXPOSURE_LENGTH,
    MIN_CHAIN_FINDINGS,
    ExposureSummary,
    KeyRisk,
    NotableAsset,
    RiskChain,
    StoredKeyRisk,
    StoredNotableAsset,
    StoredRiskChain,
    StoredSummary,
)
from attacksurf.ai.summary import (
    MAX_SUMMARY_ASSETS,
    MAX_SUMMARY_FINDINGS,
    MAX_SUMMARY_RATIONALE_LENGTH,
    SUMMARY_PROMPT_VERSION,
    SUMMARY_PURPOSE,
    SummaryAsset,
    SummaryFinding,
    SummaryInput,
)
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Severity
from attacksurf.domain.llm import Message, ProviderKind
from tests.fakes import FakeLLMProvider

SCHEMA_SNAPSHOT = Path(__file__).parents[2] / "fixtures" / "ai" / "exposure_summary_schema.json"
STORED_METADATA = {"prompt_version", "provider", "model", "generated_at"}
FINDING_ID = UUID("01960000-0000-7000-8000-000000000001")
ASSET_ID = UUID("01960000-0000-7000-8000-000000000002")


def _risk(**overrides: Any) -> dict[str, Any]:
    return {
        "finding_ref": "F1",
        "why": "Dangling CNAME on assets.acme.example allows subdomain takeover.",
    } | overrides


def _notable(**overrides: Any) -> dict[str, Any]:
    return {
        "asset_ref": "A1",
        "reason": "Jenkins host exposed on the public internet.",
    } | overrides


def _chain(**overrides: Any) -> dict[str, Any]:
    return {
        "title": "Outdated Jenkins paired with exposed login",
        "finding_refs": ["F1", "F2"],
        "asset_ref": "A1",
        "why": "Known Jenkins CVEs combined with public console access heighten compromise risk.",
    } | overrides


def _reply(**overrides: Any) -> dict[str, Any]:
    return {
        "headline": "One high-risk takeover and two sensitive hosts need attention.",
        "web_exposure": "Jenkins 2.346 on ci.acme.example exposes an admin panel and CVEs.",
        "key_risks": [_risk()],
        "risk_chains": [_chain()],
        "notable_assets": [_notable()],
        "changes": "1 new high finding and 1 new subdomain since the last scan.",
        "next_actions": ["Remove the dangling CNAME on assets.acme.example."],
    } | overrides


def _stored(**overrides: Any) -> StoredSummary:
    data: dict[str, Any] = {
        "headline": "One high-risk takeover needs attention.",
        "web_exposure": "Exposed Jenkins instance.",
        "key_risks": [{"finding_id": str(FINDING_ID), "why": "Subdomain takeover risk."}],
        "risk_chains": [],
        "notable_assets": [{"asset_id": str(ASSET_ID), "reason": "Exposed Jenkins host."}],
        "changes": "1 new high finding since the last scan.",
        "next_actions": ["Remove the dangling CNAME."],
        "prompt_version": "summary/v2",
        "provider": ProviderKind.ANTHROPIC,
        "model": "test-model",
        "generated_at": datetime(2026, 11, 20, 12, 0, tzinfo=UTC),
    } | overrides
    return StoredSummary.model_validate(data)


def _finding(ref: str = "F1", index: int = 1) -> SummaryFinding:
    return SummaryFinding(
        ref=ref,
        finding_id=UUID(int=index),
        rule_id="dns.takeover.dangling_cname",
        title="Dangling CNAME",
        severity=Severity.HIGH,
        asset_name="assets.acme.example",
    )


def _asset(ref: str = "A1", index: int = 1) -> SummaryAsset:
    return SummaryAsset(
        ref=ref,
        asset_id=UUID(int=10_000 + index),
        name=f"host{index}.acme.example",
        asset_type=AssetType.SUBDOMAIN,
    )


# --- The reply a model must send ------------------------------------------------------------


def test_valid_summary_reply_parses() -> None:
    reply = ExposureSummary.model_validate_json(json.dumps(_reply()))

    assert reply.headline.startswith("One high-risk takeover")
    assert reply.key_risks == [KeyRisk(**_risk())]
    assert reply.notable_assets == [NotableAsset(**_notable())]
    assert reply.next_actions == ["Remove the dangling CNAME on assets.acme.example."]


def test_a_clean_scan_reply_with_empty_lists_is_valid() -> None:
    reply = ExposureSummary.model_validate(
        _reply(web_exposure="", key_risks=[], risk_chains=[], notable_assets=[], next_actions=[])
    )

    assert reply.web_exposure == ""
    assert reply.key_risks == []
    assert reply.risk_chains == []
    assert reply.notable_assets == []
    assert reply.next_actions == []


@pytest.mark.parametrize("ref", ["F1", "F9", "F25", "F99"])
def test_finding_refs_are_accepted(ref: str) -> None:
    assert KeyRisk.model_validate(_risk(finding_ref=ref)).finding_ref == ref


@pytest.mark.parametrize("ref", ["f1", "F0", "F01", "F100", "A1", "1", "", str(FINDING_ID)])
def test_invalid_finding_refs_are_rejected(ref: str) -> None:
    with pytest.raises(ValidationError):
        KeyRisk.model_validate(_risk(finding_ref=ref))


@pytest.mark.parametrize("ref", ["A1", "A9", "A50", "A200", "A999"])
def test_asset_refs_are_accepted(ref: str) -> None:
    assert NotableAsset.model_validate(_notable(asset_ref=ref)).asset_ref == ref


@pytest.mark.parametrize("ref", ["a1", "A0", "A01", "A1000", "F1", "1", "", str(ASSET_ID)])
def test_invalid_asset_refs_are_rejected(ref: str) -> None:
    with pytest.raises(ValidationError):
        NotableAsset.model_validate(_notable(asset_ref=ref))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("headline", "x" * MAX_HEADLINE_LENGTH),
        ("web_exposure", ""),
        ("web_exposure", "x" * MAX_WEB_EXPOSURE_LENGTH),
        (
            "key_risks",
            [
                _risk(finding_ref=f"F{i}", why="x" * MAX_KEY_RISK_WHY_LENGTH)
                for i in range(1, MAX_KEY_RISKS + 1)
            ],
        ),
        (
            "risk_chains",
            [
                _chain(
                    title="x" * MAX_CHAIN_TITLE_LENGTH,
                    finding_refs=[f"F{j}" for j in range(1, MAX_CHAIN_FINDINGS + 1)],
                    asset_ref=None,
                    why="x" * MAX_CHAIN_WHY_LENGTH,
                )
                for _ in range(MAX_RISK_CHAINS)
            ],
        ),
        (
            "notable_assets",
            [
                _notable(asset_ref=f"A{i}", reason="x" * MAX_NOTABLE_REASON_LENGTH)
                for i in range(1, MAX_NOTABLE_ASSETS + 1)
            ],
        ),
        ("changes", "x" * MAX_CHANGES_LENGTH),
        ("next_actions", ["x" * MAX_NEXT_ACTION_LENGTH] * MAX_NEXT_ACTIONS),
    ],
)
def test_values_at_the_limit_are_accepted(field: str, value: Any) -> None:
    ExposureSummary.model_validate(_reply(**{field: value}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("headline", ""),
        ("headline", "x" * (MAX_HEADLINE_LENGTH + 1)),
        ("web_exposure", "x" * (MAX_WEB_EXPOSURE_LENGTH + 1)),
        ("key_risks", [_risk(finding_ref=f"F{i}") for i in range(1, MAX_KEY_RISKS + 2)]),
        ("key_risks", [_risk(why="")]),
        ("key_risks", [_risk(why="x" * (MAX_KEY_RISK_WHY_LENGTH + 1))]),
        ("risk_chains", [_chain() for _ in range(MAX_RISK_CHAINS + 1)]),
        ("risk_chains", [_chain(finding_refs=["F1"])]),
        ("risk_chains", [_chain(finding_refs=[f"F{i}" for i in range(1, MAX_CHAIN_FINDINGS + 2)])]),
        ("risk_chains", [_chain(title="")]),
        ("risk_chains", [_chain(why="x" * (MAX_CHAIN_WHY_LENGTH + 1))]),
        ("notable_assets", [_notable(asset_ref=f"A{i}") for i in range(1, MAX_NOTABLE_ASSETS + 2)]),
        ("notable_assets", [_notable(reason="")]),
        ("notable_assets", [_notable(reason="x" * (MAX_NOTABLE_REASON_LENGTH + 1))]),
        ("changes", ""),
        ("changes", "x" * (MAX_CHANGES_LENGTH + 1)),
        ("next_actions", ["x"] * (MAX_NEXT_ACTIONS + 1)),
        ("next_actions", [""]),
        ("next_actions", ["x" * (MAX_NEXT_ACTION_LENGTH + 1)]),
    ],
)
def test_values_outside_the_limit_are_rejected(field: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        ExposureSummary.model_validate(_reply(**{field: value}))


@pytest.mark.parametrize(
    "missing",
    [
        "headline",
        "web_exposure",
        "key_risks",
        "risk_chains",
        "notable_assets",
        "changes",
        "next_actions",
    ],
)
def test_required_fields_are_required(missing: str) -> None:
    fields = _reply()
    del fields[missing]

    with pytest.raises(ValidationError):
        ExposureSummary.model_validate(fields)


def test_extra_fields_are_rejected_at_every_level() -> None:
    with pytest.raises(ValidationError):
        ExposureSummary.model_validate(_reply(extra="nope"))
    with pytest.raises(ValidationError):
        KeyRisk.model_validate(_risk(severity="critical"))
    with pytest.raises(ValidationError):
        RiskChain.model_validate(_chain(severity="critical"))
    with pytest.raises(ValidationError):
        NotableAsset.model_validate(_notable(tags=["notable"]))


def test_every_reply_field_is_described_for_the_model() -> None:
    assert all(field.description for field in KeyRisk.model_fields.values())
    assert all(field.description for field in RiskChain.model_fields.values())
    assert all(field.description for field in NotableAsset.model_fields.values())
    assert all(field.description for field in ExposureSummary.model_fields.values())


def test_reply_schema_matches_the_snapshot() -> None:
    assert ExposureSummary.model_json_schema() == json.loads(SCHEMA_SNAPSHOT.read_text())


def test_reply_schema_converts_for_both_provider_formats() -> None:
    anthropic_schema = anthropic.transform_schema(ExposureSummary)
    openai_schema = to_strict_json_schema(ExposureSummary)

    assert anthropic_schema["additionalProperties"] is False
    assert openai_schema["additionalProperties"] is False


def test_reply_round_trips_through_a_provider() -> None:
    provider = FakeLLMProvider(json.dumps(_reply()))

    result = provider.complete(
        [Message("user", "Summarize acme.example.")], schema=ExposureSummary, max_tokens=500
    )

    assert result.parsed.key_risks[0].finding_ref == "F1"
    assert result.parsed.notable_assets[0].asset_ref == "A1"
    assert result.attempts == 1


# --- What is stored in Scan.ai_summary -------------------------------------------------------


def test_stored_summary_keeps_every_reply_field_plus_metadata() -> None:
    assert set(StoredSummary.model_fields) == set(ExposureSummary.model_fields) | STORED_METADATA


def test_stored_summary_round_trips_through_json() -> None:
    stored = _stored()

    data = stored.model_dump(mode="json")

    assert json.loads(json.dumps(data)) == data
    assert StoredSummary.model_validate(data) == stored
    assert stored.key_risks == [
        StoredKeyRisk(finding_id=FINDING_ID, why="Subdomain takeover risk.")
    ]
    assert stored.notable_assets == [
        StoredNotableAsset(asset_id=ASSET_ID, reason="Exposed Jenkins host.")
    ]


def test_stored_summary_needs_a_timezone() -> None:
    data = _stored().model_dump(mode="json") | {"generated_at": "2026-11-20T12:00:00"}

    with pytest.raises(ValidationError):
        StoredSummary.model_validate(data)


def test_stored_summary_rejects_unknown_provider_and_extra_fields() -> None:
    data = _stored().model_dump(mode="json")

    with pytest.raises(ValidationError):
        StoredSummary.model_validate(data | {"provider": "unknown"})
    with pytest.raises(ValidationError):
        StoredSummary.model_validate(data | {"extra": "bad"})
    with pytest.raises(ValidationError):
        StoredKeyRisk.model_validate({"finding_id": "not-a-uuid", "why": "bad"})
    with pytest.raises(ValidationError):
        StoredNotableAsset.model_validate({"asset_id": "not-a-uuid", "reason": "bad"})


# --- What goes into a summary call -----------------------------------------------------------


def test_constants_match_adr_0030() -> None:
    assert SUMMARY_PURPOSE == "summary"
    assert SUMMARY_PROMPT_VERSION == "summary/v2"
    assert MIN_CHAIN_FINDINGS == 2
    assert MAX_SUMMARY_FINDINGS == 25
    assert MAX_SUMMARY_ASSETS == 200
    assert MAX_SUMMARY_RATIONALE_LENGTH == 300


def test_v1_stored_summary_without_web_fields_still_validates() -> None:
    legacy = {
        "headline": "Legacy scan summary.",
        "key_risks": [{"finding_id": str(FINDING_ID), "why": "Subdomain takeover risk."}],
        "notable_assets": [{"asset_id": str(ASSET_ID), "reason": "Exposed Jenkins host."}],
        "changes": "No changes.",
        "next_actions": ["Review findings."],
        "prompt_version": "summary/v1",
        "provider": "anthropic",
        "model": "test-model",
        "generated_at": "2026-11-20T12:00:00Z",
    }
    parsed = StoredSummary.model_validate(legacy)
    assert parsed.web_exposure == ""
    assert parsed.risk_chains == []
    chain_record = StoredRiskChain(
        title="Legacy test", finding_ids=[FINDING_ID, ASSET_ID], asset_id=ASSET_ID, why="Compounds."
    )
    assert len(chain_record.finding_ids) == 2


def test_summary_input_accepts_zero_up_to_its_limits() -> None:
    empty = SummaryInput(root_domain="acme.example", changes=None, findings=(), assets=())
    full = SummaryInput(
        root_domain="acme.example",
        changes=None,
        findings=tuple(_finding(f"F{i}", i) for i in range(1, MAX_SUMMARY_FINDINGS + 1)),
        assets=tuple(_asset(f"A{i}", i) for i in range(1, MAX_SUMMARY_ASSETS + 1)),
    )

    assert len(empty.findings) == 0
    assert len(empty.assets) == 0
    assert len(full.findings) == MAX_SUMMARY_FINDINGS
    assert len(full.assets) == MAX_SUMMARY_ASSETS


def test_summary_input_rejects_over_limit_collections() -> None:
    with pytest.raises(ValueError, match="at most 25 findings"):
        SummaryInput(
            root_domain="acme.example",
            changes=None,
            findings=tuple(_finding(f"F{i}", i) for i in range(1, MAX_SUMMARY_FINDINGS + 2)),
            assets=(),
        )
    with pytest.raises(ValueError, match="at most 200 assets"):
        SummaryInput(
            root_domain="acme.example",
            changes=None,
            findings=(),
            assets=tuple(_asset(f"A{i}", i) for i in range(1, MAX_SUMMARY_ASSETS + 2)),
        )


def test_summary_input_rejects_bad_or_duplicate_refs_without_echoing_them() -> None:
    with pytest.raises(ValueError, match="F1 to F99") as excinfo:
        SummaryInput(
            root_domain="acme.example",
            changes=None,
            findings=(_finding("secret-finding-id", 1),),
            assets=(),
        )
    assert "secret-finding-id" not in str(excinfo.value)

    with pytest.raises(ValueError, match="unique"):
        SummaryInput(
            root_domain="acme.example",
            changes=None,
            findings=(_finding("F1", 1), _finding("F1", 2)),
            assets=(),
        )

    with pytest.raises(ValueError, match="A1 to A999") as excinfo2:
        SummaryInput(
            root_domain="acme.example",
            changes=None,
            findings=(),
            assets=(_asset("secret-asset-id", 1),),
        )
    assert "secret-asset-id" not in str(excinfo2.value)

    with pytest.raises(ValueError, match="unique"):
        SummaryInput(
            root_domain="acme.example",
            changes=None,
            findings=(),
            assets=(_asset("A1", 1), _asset("A1", 2)),
        )


def test_summary_input_is_immutable() -> None:
    summary_input = SummaryInput(root_domain="acme.example", changes=None, findings=(), assets=())

    with pytest.raises(AttributeError):
        summary_input.root_domain = "other.example"  # type: ignore[misc]
