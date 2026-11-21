"""Email digest notifications: preferences, digest data, and sender port (pure Python)."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from attacksurf.domain.findings import Severity
from attacksurf.domain.jobs import JobError
from attacksurf.domain.scans import ScanTrigger

DEFAULT_EMAIL_ENABLED = True
DEFAULT_MIN_SEVERITY = Severity.HIGH
MAX_DIGEST_FINDINGS = 25


class InvalidNotificationPreference(ValueError):
    """Raised when a user's notification preference input is invalid."""


class EmailDeliveryError(JobError):
    """Permanent SMTP delivery failure with a sanitized message (no credentials or addresses)."""


@dataclass(frozen=True)
class EmailMessageData:
    """One rendered email ready for the `EmailSender` port."""

    to_email: str
    subject: str
    text_body: str
    html_body: str


@dataclass(frozen=True)
class DigestFinding:
    """One new or regressed finding included in a scan digest."""

    finding_id: UUID
    rule_id: str
    title: str
    severity: Severity
    asset_value: str
    change: Literal["new", "regressed"]


@dataclass(frozen=True)
class ScanDigest:
    """All data needed to render one recipient's scan notification email."""

    org_name: str
    scan_id: UUID
    root_domain: str
    triggered_by: ScanTrigger
    finished_at: datetime | None
    ai_headline: str | None
    findings: tuple[DigestFinding, ...]
    total_matching: int
    truncated: bool
    app_base_url: str | None = None


class EmailSender(Protocol):
    """Outbound email port.

    Implementations raise `TransientJobError` for temporary failures (network/4xx SMTP) so
    Celery retries, and `EmailDeliveryError` for permanent failures (5xx/auth/refused).
    """

    def send(self, message: EmailMessageData) -> None: ...
