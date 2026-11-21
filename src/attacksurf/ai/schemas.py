"""Output models of the AI features (ADR 0029): what a model must reply, and what is stored.

Field descriptions are sent with the JSON schema and guide the model, so a change to one changes
what the model sees: release it with a new prompt version.
"""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from attacksurf.domain.findings import Confidence, Severity
from attacksurf.domain.llm import LLMConfig, ProviderKind

MAX_FINDINGS_PER_BATCH = 20
# Batch-local references (F1 to F99), never database IDs: a reply can only point at findings
# of its own batch.
FINDING_REF_PATTERN = r"^F[1-9][0-9]?$"
# Batch-local asset references (A1 to A999), never database IDs.
ASSET_REF_PATTERN = r"^A[1-9][0-9]{0,2}$"
MAX_RATIONALE_LENGTH = 600
MAX_EXPLOITABILITY_LENGTH = 600
MAX_REMEDIATION_STEPS = 5
MAX_REMEDIATION_STEP_LENGTH = 300
MAX_HEADLINE_LENGTH = 200
MAX_KEY_RISKS = 5
MAX_KEY_RISK_WHY_LENGTH = 300
MAX_NOTABLE_ASSETS = 10
MAX_NOTABLE_REASON_LENGTH = 200
MAX_CHANGES_LENGTH = 600
MAX_NEXT_ACTIONS = 5
MAX_NEXT_ACTION_LENGTH = 200
_SHA256_HEX = r"^[0-9a-f]{64}$"


# How soon to act. Comparable across batches, unlike a rank within one call.
class TriagePriority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class FalsePositiveLikelihood(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Each judgment field once, shared by the reply and the stored record.
FindingRef = Annotated[
    str,
    Field(
        pattern=FINDING_REF_PATTERN,
        description="The finding's reference exactly as given in the input, for example F1.",
    ),
]
AdjustedSeverity = Annotated[
    Severity,
    Field(
        description=(
            "Your severity for this finding given its context and evidence. It may differ from "
            "the scanner's severity."
        )
    ),
]
JudgmentConfidence = Annotated[Confidence, Field(description="How sure you are of this judgment.")]
FalsePositive = Annotated[
    FalsePositiveLikelihood,
    Field(description="How likely it is that the finding is not a real issue."),
]
Priority = Annotated[
    TriagePriority,
    Field(description="How soon to act: P1 now, P2 within days, P3 plan it, P4 when convenient."),
]
Rationale = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_RATIONALE_LENGTH,
        description="Why, in one or two sentences, based on the evidence.",
    ),
]
Exploitability = Annotated[
    str,
    Field(
        max_length=MAX_EXPLOITABILITY_LENGTH,
        description="How an attacker could use this issue, or an empty string if they cannot.",
    ),
]
RemediationSteps = Annotated[
    list[Annotated[str, Field(min_length=1, max_length=MAX_REMEDIATION_STEP_LENGTH)]],
    Field(
        max_length=MAX_REMEDIATION_STEPS,
        description="Concrete steps that fix the issue, most important first.",
    ),
]


# Docstrings of the models a reply is validated against are sent with the schema: they speak to
# the model. Extra fields are rejected, so a reply can't carry anything else (a status change,
# say) into stored data.
class FindingTriage(BaseModel):
    """Your judgment of one finding."""

    model_config = ConfigDict(extra="forbid")

    ref: FindingRef
    adjusted_severity: AdjustedSeverity
    confidence: JudgmentConfidence
    false_positive_likelihood: FalsePositive
    priority: Priority
    rationale: Rationale
    exploitability: Exploitability
    remediation_steps: RemediationSteps


class TriageReply(BaseModel):
    """Your judgments of the findings in the input."""

    model_config = ConfigDict(extra="forbid")

    findings: list[FindingTriage] = Field(
        max_length=MAX_FINDINGS_PER_BATCH,
        description="One judgment per finding in the input.",
    )


class StoredTriage(BaseModel):
    """`Finding.ai_triage`: one judgment, with what produced it and the cache key it answers.

    A row that doesn't validate (written by an older version) counts as not triaged.
    """

    model_config = ConfigDict(extra="forbid")

    adjusted_severity: AdjustedSeverity
    confidence: JudgmentConfidence
    false_positive_likelihood: FalsePositive
    priority: Priority
    rationale: Rationale
    exploitability: Exploitability
    remediation_steps: RemediationSteps
    prompt_version: str = Field(min_length=1, max_length=50)
    provider: ProviderKind
    model: str = Field(min_length=1, max_length=200)  # as long as `LLMUsage.model`
    cache_key: str = Field(pattern=_SHA256_HEX)
    triaged_at: AwareDatetime

    @classmethod
    def from_judgment(
        cls,
        judgment: FindingTriage,
        *,
        prompt_version: str,
        config: LLMConfig,
        cache_key: str,
        triaged_at: datetime,
    ) -> Self:
        """The record to store for `judgment`; the batch-local `ref` is dropped."""
        return cls(
            **judgment.model_dump(exclude={"ref"}),
            prompt_version=prompt_version,
            provider=config.provider,
            model=config.model,
            cache_key=cache_key,
            triaged_at=triaged_at,
        )


# --- Exposure summary (ADR 0030) -------------------------------------------------------------

AssetRef = Annotated[
    str,
    Field(
        pattern=ASSET_REF_PATTERN,
        description="The asset's reference exactly as given in the input, for example A1.",
    ),
]
SummaryHeadline = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_HEADLINE_LENGTH,
        description="One short sentence capturing the domain's current exposure.",
    ),
]
RiskWhy = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_KEY_RISK_WHY_LENGTH,
        description="Why this finding matters to the security team, in one or two sentences.",
    ),
]
NotableReason = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_NOTABLE_REASON_LENGTH,
        description="Why this host looks sensitive or worth inspecting first.",
    ),
]
SummaryChanges = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_CHANGES_LENGTH,
        description=(
            "What changed since the previous scan (new, fixed, or regressed findings and assets), "
            "or that nothing changed."
        ),
    ),
]
NextActions = Annotated[
    list[Annotated[str, Field(min_length=1, max_length=MAX_NEXT_ACTION_LENGTH)]],
    Field(
        max_length=MAX_NEXT_ACTIONS,
        description="Concrete next steps for the security team, most urgent first.",
    ),
]


class KeyRisk(BaseModel):
    """One top risk citing a finding from the input."""

    model_config = ConfigDict(extra="forbid")

    finding_ref: FindingRef
    why: RiskWhy


class NotableAsset(BaseModel):
    """One host from the input that looks sensitive or worth checking first."""

    model_config = ConfigDict(extra="forbid")

    asset_ref: AssetRef
    reason: NotableReason


class ExposureSummary(BaseModel):
    """A short exposure summary for the scanned domain."""

    model_config = ConfigDict(extra="forbid")

    headline: SummaryHeadline
    key_risks: list[KeyRisk] = Field(
        max_length=MAX_KEY_RISKS,
        description=(
            "Up to five top risks, ranked most urgent first, each citing a finding from the input."
        ),
    )
    notable_assets: list[NotableAsset] = Field(
        max_length=MAX_NOTABLE_ASSETS,
        description=(
            "Up to ten hosts from the input whose names suggest sensitive, internal, or legacy "
            "services (such as admin, jenkins, vpn, staging, or old)."
        ),
    )
    changes: SummaryChanges
    next_actions: NextActions


class StoredKeyRisk(BaseModel):
    """One validated top risk linked to a real finding ID."""

    model_config = ConfigDict(extra="forbid")

    finding_id: UUID
    why: RiskWhy


class StoredNotableAsset(BaseModel):
    """One validated notable host linked to a real asset ID."""

    model_config = ConfigDict(extra="forbid")

    asset_id: UUID
    reason: NotableReason


class StoredSummary(BaseModel):
    """`Scan.ai_summary`: one validated exposure summary with real IDs and provenance.

    A row that doesn't validate (written by an older version) counts as missing.
    """

    model_config = ConfigDict(extra="forbid")

    headline: SummaryHeadline
    key_risks: list[StoredKeyRisk] = Field(max_length=MAX_KEY_RISKS)
    notable_assets: list[StoredNotableAsset] = Field(max_length=MAX_NOTABLE_ASSETS)
    changes: SummaryChanges
    next_actions: NextActions
    prompt_version: str = Field(min_length=1, max_length=50)
    provider: ProviderKind
    model: str = Field(min_length=1, max_length=200)  # as long as `LLMUsage.model`
    generated_at: AwareDatetime
