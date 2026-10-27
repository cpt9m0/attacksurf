import pytest
from pydantic import ValidationError

from attacksurf.domain.assets import AssetType
from attacksurf.domain.scanners import (
    MAX_EVIDENCE_BYTES,
    AssetRef,
    RawEvidence,
    RawFinding,
    ScanOutput,
)


def test_asset_reference_normalizes_values() -> None:
    assert AssetRef(type=AssetType.SUBDOMAIN, value=" WWW.Example.COM. ").value == "www.example.com"


def test_output_rejects_oversize_evidence() -> None:
    with pytest.raises(ValidationError):
        RawEvidence(data={"text": "x" * MAX_EVIDENCE_BYTES})


def test_output_rejects_extra_fields_and_invalid_assets() -> None:
    with pytest.raises(ValidationError):
        ScanOutput.model_validate({"org_id": "untrusted"})
    with pytest.raises(ValidationError):
        AssetRef(type=AssetType.URL, value="https://user:password@example.com")


def test_empty_output_round_trips_as_json() -> None:
    output = ScanOutput()
    assert ScanOutput.model_validate_json(output.model_dump_json()) == output


def test_finding_requires_a_dotted_rule_id() -> None:
    with pytest.raises(ValidationError, match="invalid rule"):
        RawFinding(rule_id="invalid")


def test_output_caps_aggregate_size_not_just_individual_evidence() -> None:
    evidence = RawEvidence(data={"text": "x" * (MAX_EVIDENCE_BYTES - 100)})
    finding = RawFinding(rule_id="test.fixture.issue", evidence=(evidence,) * 10)
    with pytest.raises(ValidationError, match="output exceeds"):
        ScanOutput(findings=(finding,) * 4)


def test_evidence_limits_utf8_bytes_and_rejects_nonfinite_json() -> None:
    with pytest.raises(ValidationError):
        RawEvidence(data={"text": "é" * (MAX_EVIDENCE_BYTES // 2)})
    with pytest.raises(ValidationError):
        RawEvidence(data={"number": float("nan")})
