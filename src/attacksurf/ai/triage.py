"""Triage calls (ADR 0029): one asset's findings in, one judgment per finding out.

`services/triage.py` builds batches from database rows. A batch holds no database IDs: each
finding gets a batch-local reference (`F1` to `F99`), the only way a reply can point at it.
Everything about a finding goes to the model inside one `scan_data_block`, as untrusted data.
"""

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from attacksurf.ai.prompts import load_prompt
from attacksurf.ai.schemas import (
    FINDING_REF_PATTERN,
    MAX_FINDINGS_PER_BATCH,
    FindingTriage,
    TriageReply,
)
from attacksurf.ai.untrusted import cap, scan_data_block
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, EvidenceKind, Severity
from attacksurf.domain.llm import LLMProvider, LLMResult, Message

TRIAGE_PURPOSE = "triage"  # `LLMUsage.purpose` of every triage call
TRIAGE_PROMPT_VERSION = "triage/v2"
# A cap, not a spend: room for 20 judgments, and for models whose thinking counts against it.
TRIAGE_MAX_TOKENS = 8192
EVIDENCE_ITEMS_PER_FINDING = 5
EVIDENCE_STRING_LENGTH = 2000
WEB_TITLE_MAX_LENGTH = 200
WEB_CONTENT_TYPE_MAX_LENGTH = 128
WEB_HEADER_KEY_MAX_LENGTH = 64
WEB_HEADER_VALUE_MAX_LENGTH = 256
WEB_EXCERPT_MAX_LENGTH = 500
MAX_WEB_CONTEXT_HEADERS = 15
MAX_WEB_CONTEXT_TECHNOLOGIES = 25
MAX_OTHER_FINDINGS = 25
MAX_HOST_HINTS = 8
REDACTED_HEADER_NAMES = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie"})
_TITLE_KEYS = frozenset({"title", "page_title"})
_BANNER_KEYS = frozenset({"banner", "server", "x-powered-by", "x_powered_by", "header_value"})
_EXCERPT_KEYS = frozenset({"excerpt", "body_excerpt", "file_excerpt", "snippet"})
_HOST_HINT_TOKENS = frozenset(
    {
        "admin",
        "adm",
        "manage",
        "console",
        "panel",
        "dashboard",
        "portal",
        "auth",
        "login",
        "sso",
        "oauth",
        "id",
        "api",
        "graphql",
        "staging",
        "stage",
        "stg",
        "dev",
        "test",
        "qa",
        "uat",
        "sandbox",
        "beta",
        "preview",
        "internal",
        "intranet",
        "corp",
        "vpn",
        "jenkins",
        "gitlab",
        "grafana",
        "kibana",
        "static",
        "assets",
        "cdn",
        "docs",
        "blog",
        "www",
        "prod",
        "app",
        "shop",
        "pay",
        "billing",
        "legacy",
        "old",
    }
)
_CACHE_KEY_VERSION = "v2"  # v2 adds the finding fields the prompt shows
_REF = re.compile(FINDING_REF_PATTERN)
_LABEL_SPLIT = re.compile(r"[-_]+")


def extract_host_hints(host: str) -> tuple[str, ...]:
    """Return bounded role/environment hint tokens extracted from subdomain labels of ``host``."""
    cleaned = host.strip().rstrip(".").lower()
    labels = [label for label in cleaned.split(".") if label]
    subdomain_labels = labels[:-2]
    if not subdomain_labels:
        return ()
    seen: list[str] = []
    for label in subdomain_labels:
        for part in _LABEL_SPLIT.split(label):
            token = part.rstrip("0123456789")
            if token in _HOST_HINT_TOKENS and token not in seen:
                seen.append(token)
                if len(seen) >= MAX_HOST_HINTS:
                    return tuple(seen)
    return tuple(seen)


@dataclass(frozen=True)
class WebTechnology:
    """One fingerprinted component carried in website context."""

    name: str
    version: str | None = None
    categories: tuple[str, ...] = ()


@dataclass(frozen=True)
class RelatedFinding:
    """Summary of another active finding on the same URL asset for triage context."""

    rule_id: str
    title: str
    severity: Severity
    location: str = ""


@dataclass(frozen=True)
class WebContext:
    """Website role, response metadata, tech stack, and sibling findings for a URL asset."""

    host: str
    host_hints: tuple[str, ...] = ()
    status_code: int | None = None
    title: str = ""
    content_type: str = ""
    headers: Mapping[str, str] = MappingProxyType({})
    technologies: tuple[WebTechnology, ...] = ()
    other_findings: tuple[RelatedFinding, ...] = ()


@dataclass(frozen=True)
class TriageEvidence:
    kind: EvidenceKind
    data: Mapping[str, Any]


@dataclass(frozen=True)
class TriageFinding:
    """One normalized finding: scanner output only, never anything the AI produced."""

    ref: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    location: str
    evidence: tuple[TriageEvidence, ...] = ()


@dataclass(frozen=True)
class TriageBatch:
    """One asset's findings for one LLM call."""

    asset_value: str
    asset_type: AssetType
    findings: tuple[TriageFinding, ...]
    web_context: WebContext | None = None

    def __post_init__(self) -> None:
        # Messages never echo a value: refs and asset names stay out of logs and job errors.
        if not 1 <= len(self.findings) <= MAX_FINDINGS_PER_BATCH:
            raise ValueError(f"a triage batch holds 1 to {MAX_FINDINGS_PER_BATCH} findings")
        refs = [finding.ref for finding in self.findings]
        # A ref the reply schema rejects could never be matched back to its finding.
        if not all(_REF.fullmatch(ref) for ref in refs):
            raise ValueError("finding refs must be F1 to F99")
        if len(set(refs)) != len(refs):
            raise ValueError("finding refs must be unique within a batch")


def build_triage_messages(batch: TriageBatch) -> list[Message]:
    """The released triage prompt with `batch` as its scan data."""
    payload: dict[str, Any] = {
        "asset": {"name": batch.asset_value, "type": batch.asset_type},
        "findings": [_finding_payload(finding) for finding in batch.findings],
    }
    if batch.web_context is not None:
        payload["web_context"] = _web_context_payload(batch.web_context)
    block = scan_data_block(payload, max_string_length=EVIDENCE_STRING_LENGTH)
    return load_prompt(TRIAGE_PROMPT_VERSION).messages(scan_data=block)


def triage_batch(provider: LLMProvider, batch: TriageBatch) -> LLMResult[TriageReply]:
    """One triage call for `batch`. Provider errors (`LLMError`) pass through unchanged."""
    return provider.complete(
        build_triage_messages(batch), schema=TriageReply, max_tokens=TRIAGE_MAX_TOKENS
    )


def match_results(batch: TriageBatch, reply: TriageReply) -> dict[str, FindingTriage]:
    """The reply's judgments by ref, keeping only refs of `batch` that were judged once.

    A ref outside the batch is a hallucination; a ref judged twice has two conflicting answers
    and neither is trusted. Findings left out of the reply simply stay untriaged.
    """
    counts = Counter(judgment.ref for judgment in reply.findings)
    known = {finding.ref for finding in batch.findings}
    return {
        judgment.ref: judgment
        for judgment in reply.findings
        if judgment.ref in known and counts[judgment.ref] == 1
    }


@dataclass(frozen=True)
class TriageCacheInput:
    """What a judgment of one finding answers: a change to any part means a new judgment.

    The fingerprint covers rule, asset and location, and the digest the evidence. The other
    fields reach the prompt too and can change under the same fingerprint and evidence (a
    rule's new default severity, a scanner's new confidence, reworded text).
    """

    fingerprint: str
    evidence_digest: str | None
    severity: Severity
    confidence: Confidence
    title: str
    description: str


def triage_cache_key(prompt_version: str, model: str, finding: TriageCacheInput) -> str:
    """SHA-256 hex naming one judgment: a finding is triaged again only when a part changes.

    Same scheme as `finding_fingerprint`: a JSON array keeps the parts unambiguous, and the
    version prefix lets the scheme change without colliding with stored keys.
    """
    payload = json.dumps(
        [
            _CACHE_KEY_VERSION,
            prompt_version,
            model,
            finding.fingerprint,
            finding.evidence_digest,
            finding.severity,
            finding.confidence,
            finding.title,
            finding.description,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


_WEB_FIELD_CAPS: dict[str, int] = {
    **dict.fromkeys(_TITLE_KEYS, WEB_TITLE_MAX_LENGTH),
    **dict.fromkeys(_BANNER_KEYS, WEB_HEADER_VALUE_MAX_LENGTH),
    **dict.fromkeys(_EXCERPT_KEYS, WEB_EXCERPT_MAX_LENGTH),
}


def _sanitize_headers_mapping(headers: Mapping[Any, Any]) -> dict[Any, Any]:
    sanitized: dict[Any, Any] = {}
    for raw_k, raw_v in headers.items():
        if isinstance(raw_k, str) and raw_k.strip().lower() in REDACTED_HEADER_NAMES:
            continue
        k_out = cap(raw_k, WEB_HEADER_KEY_MAX_LENGTH) if isinstance(raw_k, str) else raw_k
        v_out = (
            cap(raw_v, WEB_HEADER_VALUE_MAX_LENGTH)
            if isinstance(raw_v, str)
            else _sanitize_evidence_data(raw_v)
        )
        sanitized[k_out] = v_out
    return sanitized


def _sanitize_evidence_data(value: Any, *, key: str | None = None) -> Any:
    """Enforce tight web untrusted-field caps without mutating input evidence."""
    if isinstance(value, Mapping):
        if key is not None and key.lower() == "headers":
            return _sanitize_headers_mapping(value)
        return {
            raw_k: _sanitize_evidence_data(raw_v, key=raw_k if isinstance(raw_k, str) else None)
            for raw_k, raw_v in value.items()
        }
    if isinstance(value, list | tuple):
        return [_sanitize_evidence_data(item, key=key) for item in value]
    if isinstance(value, str) and key is not None:
        limit = _WEB_FIELD_CAPS.get(key.lower())
        if limit is not None:
            return cap(value, limit)
    return value


def _web_context_payload(ctx: WebContext) -> dict[str, Any]:
    headers: dict[str, str] = {}
    for raw_k, raw_v in ctx.headers.items():
        if raw_k.strip().lower() in REDACTED_HEADER_NAMES:
            continue
        headers[cap(raw_k, WEB_HEADER_KEY_MAX_LENGTH)] = cap(raw_v, WEB_HEADER_VALUE_MAX_LENGTH)
        if len(headers) >= MAX_WEB_CONTEXT_HEADERS:
            break

    payload: dict[str, Any] = {
        "host": cap(ctx.host, 255),
        "host_hints": [cap(hint, 32) for hint in ctx.host_hints[:MAX_HOST_HINTS]],
    }
    if ctx.status_code is not None:
        payload["status_code"] = ctx.status_code
    if ctx.title:
        payload["title"] = cap(ctx.title, WEB_TITLE_MAX_LENGTH)
    if ctx.content_type:
        payload["content_type"] = cap(ctx.content_type, WEB_CONTENT_TYPE_MAX_LENGTH)
    if headers:
        payload["headers"] = headers
    payload["technologies"] = [
        {
            "name": cap(tech.name, 128),
            **({"version": cap(tech.version, 64)} if tech.version else {}),
            **(
                {"categories": [cap(cat, 64) for cat in tech.categories[:8]]}
                if tech.categories
                else {}
            ),
        }
        for tech in ctx.technologies[:MAX_WEB_CONTEXT_TECHNOLOGIES]
    ]
    payload["other_findings"] = [
        {
            "rule_id": cap(other.rule_id, 128),
            "title": cap(other.title, WEB_TITLE_MAX_LENGTH),
            "severity": other.severity,
            **({"location": cap(other.location, 256)} if other.location else {}),
        }
        for other in ctx.other_findings[:MAX_OTHER_FINDINGS]
    ]
    return payload


def _finding_payload(finding: TriageFinding) -> dict[str, Any]:
    # Only what the model needs to judge the finding; the order is the order it reads.
    return {
        "ref": finding.ref,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "scanner_severity": finding.severity,
        "scanner_confidence": finding.confidence,
        "location": finding.location,
        "evidence": [
            {"kind": item.kind, "data": _sanitize_evidence_data(item.data)}
            for item in finding.evidence[:EVIDENCE_ITEMS_PER_FINDING]
        ],
    }
