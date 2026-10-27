"""The scanner boundary: validated data, never ORM objects or tenant-selected IDs."""

import json
import re
from dataclasses import dataclass
from typing import Protocol, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from attacksurf.domain.assets import AssetError, AssetType, RelationKind, normalize_asset_value
from attacksurf.domain.findings import MAX_LOCATION_LENGTH, Confidence, EvidenceKind, Severity
from attacksurf.domain.jobs import JobError
from attacksurf.domain.net import ScannerRuntime
from attacksurf.domain.rules import is_valid_rule_id
from attacksurf.domain.scope import HttpPermission, ScopeError

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


_HOSTNAME = re.compile(r"(?=.{1,253}$)([a-z0-9_-]{1,63}\.)*[a-z0-9-]{1,63}")


@dataclass(frozen=True)
class ScannerGrant:
    """What a plugin declared it may reach; the gate enforces it on every request."""

    http: HttpPermission = HttpPermission.NONE
    http_hosts: frozenset[str] = frozenset()  # public data services the scanner may query
    dns_lookups: int = 0  # cap on resolver calls per run

    def __post_init__(self) -> None:
        if self.http is HttpPermission.SERVICES and not self.http_hosts:
            raise ValueError("a services grant needs at least one http host")
        if self.http is not HttpPermission.SERVICES and self.http_hosts:
            raise ValueError("http hosts are only meaningful for services")
        if self.dns_lookups < 0:
            raise ValueError("negative dns budget")
        for host in self.http_hosts:
            if not _HOSTNAME.fullmatch(host) or "." not in host:
                raise ValueError("invalid http host")


@dataclass(frozen=True)
class ScanContext:
    org_id: UUID
    scan_id: UUID
    root_asset: AssetRef
    profile: str
    runtime: ScannerRuntime | None = None  # set by the worker after the gate approves the run


@dataclass(frozen=True)
class ScanProfile:
    name: str
    discover: tuple[str, ...] = ()
    checks: tuple[str, ...] = ()
    # Profile-level cap shared by every scanner in it, e.g. discovered assets per root.
    max_discovered_assets: int | None = None


class Scanner(Protocol):
    name: str
    asset_types: frozenset[AssetType]
    queue: str
    requires_verification: bool
    timeout_seconds: float
    # Declared, enforced network budget: anything a plugin does beyond this is denied by the
    # gate. Immutable (frozensets) so one instance can't widen it after registration.
    grant: ScannerGrant

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput: ...


class ScannerGate(Protocol):
    def check(self, ctx: ScanContext, asset: AssetRef, scanner: Scanner) -> ScannerRuntime:
        """Validate/authorize the run and return its adapters. Raises `ScopeError` on denial."""
        ...


class UnconfiguredGate:
    """Tests and unconfigured processes: fail closed until a real gate is wired."""

    def check(self, ctx: ScanContext, asset: AssetRef, scanner: Scanner) -> ScannerRuntime:
        raise ScopeError("Scanner execution is disabled: no network gate is configured. (#12)")


ClosedGate = UnconfiguredGate  # older name kept for callers/tests written before #12
