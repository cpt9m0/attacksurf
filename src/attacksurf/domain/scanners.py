"""The scanner boundary: validated data, never ORM objects or tenant-selected IDs."""

import json
from dataclasses import dataclass
from typing import Protocol, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from attacksurf.domain.assets import AssetError, AssetType, RelationKind, normalize_asset_value
from attacksurf.domain.findings import MAX_LOCATION_LENGTH, Confidence, EvidenceKind, Severity
from attacksurf.domain.jobs import JobError
from attacksurf.domain.rules import is_valid_rule_id

MAX_EVIDENCE_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024


class ScannerError(JobError):
    """Safe scanner failure; never interpolate evidence or upstream errors."""


class OutputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AssetRef(OutputModel):
    type: AssetType
    value: str = Field(min_length=1, max_length=2048)

    @model_validator(mode="after")
    def normalize(self) -> Self:
        try:
            object.__setattr__(self, "value", normalize_asset_value(self.type, self.value))
        except AssetError:
            raise ValueError("invalid asset value") from None
        return self


class DiscoveredRelation(OutputModel):
    from_asset: AssetRef
    to_asset: AssetRef
    kind: RelationKind


class RawEvidence(OutputModel):
    kind: EvidenceKind = EvidenceKind.RAW
    data: dict[str, JsonValue]

    @model_validator(mode="after")
    def cap_size(self) -> Self:
        # Match what we store, not Python's in-memory size or ASCII character count.
        if (
            len(json.dumps(self.data, ensure_ascii=False, allow_nan=False).encode())
            > MAX_EVIDENCE_BYTES
        ):
            raise ValueError("evidence exceeds the byte limit")
        return self


class RawFinding(OutputModel):
    rule_id: str = Field(max_length=100)
    asset: AssetRef | None = None  # None means the input asset
    location: str = Field(default="", max_length=MAX_LOCATION_LENGTH)
    confidence: Confidence = Confidence.HIGH
    severity: Severity | None = None
    remediation_context: dict[str, str] = Field(default_factory=dict, max_length=20)
    evidence: tuple[RawEvidence, ...] = Field(default=(), max_length=10)

    @model_validator(mode="after")
    def validate_rule(self) -> Self:
        if not is_valid_rule_id(self.rule_id):
            raise ValueError("invalid rule id")
        return self


class ScanOutput(OutputModel):
    assets: tuple[AssetRef, ...] = Field(default=(), max_length=1000)
    relations: tuple[DiscoveredRelation, ...] = Field(default=(), max_length=2000)
    findings: tuple[RawFinding, ...] = Field(default=(), max_length=1000)

    @model_validator(mode="after")
    def cap_size(self) -> Self:
        if len(self.model_dump_json().encode()) > MAX_OUTPUT_BYTES:
            raise ValueError("scanner output exceeds the byte limit")
        return self


@dataclass(frozen=True)
class ScanContext:
    org_id: UUID
    scan_id: UUID
    root_asset: AssetRef
    profile: str


@dataclass(frozen=True)
class ScanProfile:
    name: str
    discover: tuple[str, ...] = ()
    checks: tuple[str, ...] = ()


class Scanner(Protocol):
    name: str
    asset_types: frozenset[AssetType]
    queue: str
    requires_verification: bool
    timeout_seconds: float

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput: ...


class ScannerGate(Protocol):
    def check(self, ctx: ScanContext, asset: AssetRef, scanner: Scanner) -> None:
        """Raise ScannerError on denial. Replaced by ScopeGuard in #12."""
        ...


class ClosedGate:
    def check(self, ctx: ScanContext, asset: AssetRef, scanner: Scanner) -> None:
        raise ScannerError("Scanner execution requires ScopeGuard (#12).")
