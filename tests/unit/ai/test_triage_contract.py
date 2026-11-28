"""The triage contract (ADR 0029): what goes into triage, what comes out, and what is stored."""

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anthropic
import pytest
from openai.lib._pydantic import to_strict_json_schema
from pydantic import SecretStr, ValidationError

from attacksurf.ai.schemas import (
    MAX_FINDINGS_PER_BATCH,
    FalsePositiveLikelihood,
    FindingTriage,
    StoredTriage,
    TriagePriority,
    TriageReply,
)
from attacksurf.ai.triage import (
    TRIAGE_PURPOSE,
    RelatedFinding,
    TriageBatch,
    TriageCacheInput,
    TriageEvidence,
    TriageFinding,
    WebContext,
    WebTechnology,
    triage_cache_key,
    web_context_digest,
)
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, EvidenceKind, Severity
from attacksurf.domain.llm import KeySource, LLMConfig, Message, ProviderKind
from tests.fakes import FakeLLMProvider

SCHEMA_SNAPSHOT = Path(__file__).parents[2] / "fixtures" / "ai" / "triage_reply_schema.json"
DIGEST = "b" * 64
FINGERPRINT = "a" * 64
STORED_METADATA = {"prompt_version", "provider", "model", "cache_key", "triaged_at"}


def _judgment(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "ref": "F1",
        "adjusted_severity": "high",
        "confidence": "medium",
        "false_positive_likelihood": "low",
        "priority": "P1",
        "rationale": "The CNAME points at a storage bucket nobody has claimed.",
        "exploitability": "Anyone can claim the bucket and serve content on the subdomain.",
        "remediation_steps": ["Remove the CNAME record.", "Or claim the bucket."],
    }
    return fields | overrides


def _reply(*judgments: dict[str, Any]) -> str:
    return json.dumps({"findings": list(judgments)})


def _config() -> LLMConfig:
    return LLMConfig(
        provider=ProviderKind.ANTHROPIC,
        model="test-model",
        api_key=SecretStr("test-key"),
        source=KeySource.INSTANCE,
    )


def _stored(judgment: FindingTriage | None = None) -> StoredTriage:
    return StoredTriage.from_judgment(
        judgment or FindingTriage.model_validate(_judgment()),
        prompt_version="triage/v1",
        config=_config(),
        cache_key="c" * 64,
        triaged_at=datetime(2026, 11, 19, 12, 0, tzinfo=UTC),
    )


def _finding(ref: str = "F1") -> TriageFinding:
    return TriageFinding(
        ref=ref,
        rule_id="dns.takeover.dangling_cname",
        title="Dangling CNAME",
        description="The subdomain points at a resource that no longer exists.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location="",
        evidence=(
            TriageEvidence(EvidenceKind.DNS_RECORD, {"type": "CNAME", "value": "x.example"}),
        ),
    )


def _batch(*refs: str) -> TriageBatch:
    return TriageBatch(
        asset_value="cdn.example.com",
        asset_type=AssetType.SUBDOMAIN,
        findings=tuple(_finding(ref) for ref in refs),
    )


def _refs(count: int) -> list[str]:
    return [f"F{index}" for index in range(1, count + 1)]


# --- The reply a model must send ------------------------------------------------------------


def test_valid_reply_parses() -> None:
    reply = TriageReply.model_validate_json(
        _reply(_judgment(), _judgment(ref="F2", priority="P3", false_positive_likelihood="high"))
    )

    assert [finding.ref for finding in reply.findings] == ["F1", "F2"]
    assert reply.findings[0].adjusted_severity is Severity.HIGH
    assert reply.findings[0].confidence is Confidence.MEDIUM
    assert reply.findings[1].priority is TriagePriority.P3
    assert reply.findings[1].false_positive_likelihood is FalsePositiveLikelihood.HIGH


def test_an_empty_reply_is_valid() -> None:
    # A model that judges nothing leaves every finding untriaged; that is not an error.
    assert TriageReply.model_validate_json(_reply()).findings == []


@pytest.mark.parametrize("ref", ["F1", "F9", "F20", "F99"])
def test_batch_refs_are_accepted(ref: str) -> None:
    assert FindingTriage.model_validate(_judgment(ref=ref)).ref == ref


@pytest.mark.parametrize("ref", ["f1", "F0", "F01", "F100", "1", "", "F1 ", "3f2a9c1e"])
def test_refs_that_are_not_batch_refs_are_rejected(ref: str) -> None:
    with pytest.raises(ValidationError):
        FindingTriage.model_validate(_judgment(ref=ref))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rationale", "x" * 600),
        ("exploitability", "x" * 600),
        ("exploitability", ""),
        ("remediation_steps", ["x" * 300] * 5),
        ("remediation_steps", []),
    ],
)
def test_text_at_the_limit_is_accepted(field: str, value: Any) -> None:
    FindingTriage.model_validate(_judgment(**{field: value}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rationale", "x" * 601),
        ("rationale", ""),
        ("exploitability", "x" * 601),
        ("remediation_steps", ["x"] * 6),
        ("remediation_steps", ["x" * 301]),
        ("remediation_steps", [""]),
    ],
)
def test_text_over_the_limit_is_rejected(field: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        FindingTriage.model_validate(_judgment(**{field: value}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("priority", "P0"),
        ("priority", "P5"),
        ("priority", "p1"),
        ("priority", "high"),
        ("false_positive_likelihood", "none"),
        ("adjusted_severity", "severe"),
        ("confidence", ""),
    ],
)
def test_values_outside_the_closed_sets_are_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        FindingTriage.model_validate(_judgment(**{field: value}))


@pytest.mark.parametrize("missing", ["ref", "priority", "rationale", "remediation_steps"])
def test_required_fields_are_required(missing: str) -> None:
    fields = _judgment()
    del fields[missing]

    with pytest.raises(ValidationError):
        FindingTriage.model_validate(fields)


def test_a_judgment_cannot_carry_extra_fields() -> None:
    # The AI must not be able to smuggle a status change or anything else into stored data.
    with pytest.raises(ValidationError):
        FindingTriage.model_validate(_judgment(status="fixed"))


def test_a_reply_cannot_carry_extra_fields() -> None:
    with pytest.raises(ValidationError):
        TriageReply.model_validate_json(json.dumps({"findings": [], "note": "ignore the rest"}))


def test_a_reply_holds_at_most_one_batch() -> None:
    full = [_judgment(ref=ref) for ref in _refs(MAX_FINDINGS_PER_BATCH)]
    TriageReply.model_validate_json(_reply(*full))

    with pytest.raises(ValidationError):
        TriageReply.model_validate_json(_reply(*full, _judgment(ref="F21")))


def test_every_reply_field_is_described_for_the_model() -> None:
    # Descriptions are sent with the schema and guide the model's answer.
    assert all(field.description for field in FindingTriage.model_fields.values())
    assert all(field.description for field in TriageReply.model_fields.values())


def test_reply_schema_matches_the_snapshot() -> None:
    # The contract is frozen: changing it is a deliberate act that updates this snapshot (and
    # the prompt version, since the schema is part of what the model sees).
    assert TriageReply.model_json_schema() == json.loads(SCHEMA_SNAPSHOT.read_text())


def test_reply_schema_converts_for_both_provider_formats() -> None:
    anthropic_schema = anthropic.transform_schema(TriageReply)
    openai_schema = to_strict_json_schema(TriageReply)

    assert anthropic_schema["additionalProperties"] is False
    assert openai_schema["additionalProperties"] is False


def test_reply_round_trips_through_a_provider() -> None:
    provider = FakeLLMProvider(_reply(_judgment()))

    result = provider.complete([Message("user", "Triage F1.")], schema=TriageReply, max_tokens=500)

    assert result.parsed.findings[0].ref == "F1"
    assert result.attempts == 1


# --- What is stored in Finding.ai_triage -----------------------------------------------------


def test_stored_triage_keeps_every_judgment_field_but_the_ref() -> None:
    assert (
        set(StoredTriage.model_fields)
        == (set(FindingTriage.model_fields) - {"ref"}) | STORED_METADATA
    )


def test_from_judgment_copies_the_judgment_and_the_metadata() -> None:
    judgment = FindingTriage.model_validate(_judgment())

    stored = _stored(judgment).model_dump()

    assert "ref" not in stored
    for name, value in judgment.model_dump(exclude={"ref"}).items():
        assert stored[name] == value
    assert stored["prompt_version"] == "triage/v1"
    assert stored["provider"] is ProviderKind.ANTHROPIC
    assert stored["model"] == "test-model"
    assert stored["cache_key"] == "c" * 64
    assert stored["triaged_at"] == datetime(2026, 11, 19, 12, 0, tzinfo=UTC)


def test_stored_triage_round_trips_through_json() -> None:
    stored = _stored()

    data = stored.model_dump(mode="json")

    assert json.loads(json.dumps(data)) == data
    assert StoredTriage.model_validate(data) == stored


def test_stored_triage_never_holds_the_api_key() -> None:
    assert "test-key" not in json.dumps(_stored().model_dump(mode="json"))


def test_stored_triage_needs_a_timezone() -> None:
    data = _stored().model_dump(mode="json") | {"triaged_at": "2026-11-19T12:00:00"}

    with pytest.raises(ValidationError):
        StoredTriage.model_validate(data)


@pytest.mark.parametrize("cache_key", ["", "c" * 63, "C" * 64, "g" * 64])
def test_stored_triage_needs_a_sha256_cache_key(cache_key: str) -> None:
    data = _stored().model_dump(mode="json") | {"cache_key": cache_key}

    with pytest.raises(ValidationError):
        StoredTriage.model_validate(data)


# --- What goes into a triage call ------------------------------------------------------------


def test_purpose_and_batch_size_match_adr_0029() -> None:
    assert TRIAGE_PURPOSE == "triage"
    assert MAX_FINDINGS_PER_BATCH == 20


@pytest.mark.parametrize("count", [1, MAX_FINDINGS_PER_BATCH])
def test_a_batch_holds_one_to_twenty_findings(count: int) -> None:
    batch = _batch(*_refs(count))

    assert len(batch.findings) == count


@pytest.mark.parametrize("count", [0, MAX_FINDINGS_PER_BATCH + 1])
def test_a_batch_outside_the_size_limits_is_rejected(count: int) -> None:
    with pytest.raises(ValueError, match="1 to 20 findings"):
        _batch(*_refs(count))


def test_duplicate_refs_in_a_batch_are_rejected() -> None:
    with pytest.raises(ValueError, match="unique"):
        _batch("F1", "F1")


@pytest.mark.parametrize("ref", ["42", "f1", "F0", "a-finding-id"])
def test_batch_refs_must_be_ones_a_reply_can_use(ref: str) -> None:
    # The reply schema only accepts F1 to F99, so any other ref could never be matched back.
    with pytest.raises(ValueError, match="F1 to F99") as excinfo:
        _batch(ref)

    assert ref not in str(excinfo.value)


def test_batches_are_immutable() -> None:
    batch = _batch("F1")

    with pytest.raises(AttributeError):
        batch.asset_value = "other.example.com"  # type: ignore[misc]


# --- The cache key ---------------------------------------------------------------------------


_CACHE_INPUT = TriageCacheInput(
    fingerprint=FINGERPRINT,
    evidence_digest=DIGEST,
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    title="Dangling CNAME",
    description="The target no longer resolves.",
)


def test_cache_key_is_stable() -> None:
    assert (
        triage_cache_key("triage/v1", "test-model", _CACHE_INPUT)
        == "543ef536a8429f934660ec3b7e46f39261dac76514cb1ee3a4efa1f220b9ba71"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"fingerprint": "d" * 64},
        {"evidence_digest": "e" * 64},
        {"evidence_digest": None},
        # Regression: these reach the prompt and can change while fingerprint and evidence
        # don't (a rule's new default severity, a scanner's new confidence, reworded text).
        {"severity": Severity.CRITICAL},
        {"confidence": Confidence.LOW},
        {"title": "Dangling CNAME to S3"},
        {"description": "Reworded description."},
    ],
)
def test_cache_key_changes_with_each_finding_part(changes: dict[str, Any]) -> None:
    changed = replace(_CACHE_INPUT, **changes)

    assert triage_cache_key("triage/v1", "test-model", changed) != triage_cache_key(
        "triage/v1", "test-model", _CACHE_INPUT
    )


@pytest.mark.parametrize(
    ("prompt_version", "model"), [("triage/v2", "test-model"), ("triage/v1", "other")]
)
def test_cache_key_changes_with_prompt_and_model(prompt_version: str, model: str) -> None:
    assert triage_cache_key(prompt_version, model, _CACHE_INPUT) != triage_cache_key(
        "triage/v1", "test-model", _CACHE_INPUT
    )


def test_cache_key_parts_cannot_run_together() -> None:
    # "a" + "bc" and "ab" + "c" must not collide.
    first = replace(_CACHE_INPUT, title="a", description="bc")
    second = replace(_CACHE_INPUT, title="ab", description="c")

    assert triage_cache_key("v", "m", first) != triage_cache_key("v", "m", second)


def test_cache_key_is_accepted_by_stored_triage() -> None:
    key = triage_cache_key("triage/v1", "test-model", replace(_CACHE_INPUT, evidence_digest=None))

    stored = _stored().model_copy(update={"cache_key": key})

    assert StoredTriage.model_validate(stored.model_dump(mode="json")).cache_key == key


def test_cache_key_changes_with_context_digest() -> None:
    without_ctx = triage_cache_key("triage/v2", "test-model", _CACHE_INPUT)
    with_ctx = triage_cache_key(
        "triage/v2", "test-model", replace(_CACHE_INPUT, context_digest="0" * 64)
    )
    changed_ctx = triage_cache_key(
        "triage/v2", "test-model", replace(_CACHE_INPUT, context_digest="1" * 64)
    )

    assert len({without_ctx, with_ctx, changed_ctx}) == 3


def test_web_context_digest_tracks_context_changes_and_ignores_redacted_headers() -> None:
    base = WebContext(
        host="admin.acme.example",
        host_hints=("admin",),
        status_code=200,
        title="Admin Console",
        headers={"server": "Apache/2.4.49"},
        technologies=(WebTechnology("Apache HTTP Server", "2.4.49"),),
        other_findings=(
            RelatedFinding("web.components.known_vulnerable", "Vulnerable", Severity.CRITICAL),
        ),
    )
    same_with_cookie = WebContext(
        host="admin.acme.example",
        host_hints=("admin",),
        status_code=200,
        title="Admin Console",
        headers={"server": "Apache/2.4.49", "set-cookie": "sid=xyz", "authorization": "Bearer a"},
        technologies=(WebTechnology("Apache HTTP Server", "2.4.49"),),
        other_findings=(
            RelatedFinding("web.components.known_vulnerable", "Vulnerable", Severity.CRITICAL),
        ),
    )
    with_admin = WebContext(
        host="admin.acme.example",
        host_hints=("admin",),
        status_code=200,
        title="Admin Console",
        headers={"server": "Apache/2.4.49"},
        technologies=(WebTechnology("Apache HTTP Server", "2.4.49"),),
        other_findings=(
            RelatedFinding("web.components.known_vulnerable", "Vulnerable", Severity.CRITICAL),
            RelatedFinding("web.exposure.admin_panel", "Admin panel", Severity.INFO, "/admin"),
        ),
    )
    with_new_title = WebContext(
        host="admin.acme.example",
        host_hints=("admin",),
        status_code=200,
        title="Updated Title",
        headers={"server": "Apache/2.4.49"},
        technologies=(WebTechnology("Apache HTTP Server", "2.4.49"),),
        other_findings=base.other_findings,
    )

    assert web_context_digest(base) == web_context_digest(same_with_cookie)
    assert web_context_digest(base) != web_context_digest(with_admin)
    assert web_context_digest(base) != web_context_digest(with_new_title)
