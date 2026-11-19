"""Output models of the AI features (ADR 0029): what a model must reply, and what is stored.

Field descriptions are sent with the JSON schema and guide the model, so a change to one changes
what the model sees: release it with a new prompt version.
"""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from attacksurf.domain.findings import Confidence, Severity
from attacksurf.domain.llm import LLMConfig, ProviderKind

MAX_FINDINGS_PER_BATCH = 20
# Batch-local references (F1 to F99), never database IDs: a reply can only point at findings
# of its own batch.
FINDING_REF_PATTERN = r"^F[1-9][0-9]?$"
MAX_RATIONALE_LENGTH = 600
MAX_EXPLOITABILITY_LENGTH = 600
MAX_REMEDIATION_STEPS = 5
MAX_REMEDIATION_STEP_LENGTH = 300
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
