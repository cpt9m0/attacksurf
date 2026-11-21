import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage
from uuid import uuid4

import pytest
from pydantic import SecretStr

from attacksurf.domain.findings import Severity
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.notifications import (
    DigestFinding,
    EmailDeliveryError,
    EmailMessageData,
    EmailRecipientRefused,
    ScanDigest,
)
from attacksurf.domain.scans import ScanTrigger
from attacksurf.infra.email import SmtpEmailSender, render_digest_email


class _FakeSMTP:
    def __init__(self, host: str, port: int, *, timeout: float, **_kwargs: object) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.actions: list[tuple[str, object]] = []
        self.sent: list[EmailMessage] = []

    def __enter__(self) -> "_FakeSMTP":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def ehlo(self) -> tuple[int, bytes]:
        self.actions.append(("ehlo", None))
        return (250, b"ok")

    def starttls(self, *, context: object = None) -> tuple[int, bytes]:
        self.actions.append(("starttls", context is not None))
        return (220, b"ready")

    def login(self, user: str, password: str) -> tuple[int, bytes]:
        self.actions.append(("login", (user, password)))
        return (235, b"ok")

    def send_message(self, msg: EmailMessage) -> dict[str, object]:
        self.sent.append(msg)
        return {}


def _sample_digest(
    *,
    count: int = 2,
    ai_headline: str | None = "Exposed admin panel and missing DMARC.",
    app_base_url: str | None = "https://app.example",
) -> ScanDigest:
    items = tuple(
        DigestFinding(
            finding_id=uuid4(),
            rule_id="dns.email.dmarc_missing",
            title=f"Finding {idx} <script>alert(1)</script>",
            severity=Severity.HIGH if idx == 1 else Severity.MEDIUM,
            asset_value=f"sub{idx}.example.com",
            change="new" if idx % 2 == 1 else "regressed",
        )
        for idx in range(1, count + 1)
    )
    return ScanDigest(
        org_name="Acme <Corp>",
        scan_id=uuid4(),
        root_domain="example.com",
        triggered_by=ScanTrigger.SCHEDULE,
        finished_at=datetime(2026, 11, 20, 12, 0, tzinfo=UTC),
        ai_headline=ai_headline,
        findings=items[:25],
        total_matching=count,
        truncated=count > 25,
        app_base_url=app_base_url,
    )


def test_render_digest_email_includes_plain_and_escaped_html_without_tracking() -> None:
    digest = _sample_digest()
    msg = render_digest_email(digest, "alice@example.com")

    assert msg.to_email == "alice@example.com"
    assert msg.subject == "[attacksurf] example.com: 1 new, 1 regressed"
    assert "Exposed admin panel and missing DMARC." in msg.text_body
    assert "Finding 1 <script>alert(1)</script>" in msg.text_body
    assert "https://app.example/scans/" in msg.text_body
    assert "https://app.example/settings" in msg.text_body

    # HTML escapes untrusted scan/AI text and contains no tracking/scripts/external images.
    assert "<script>alert(1)</script>" not in msg.html_body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in msg.html_body
    assert "Acme &lt;Corp&gt;" in msg.html_body
    assert "<img" not in msg.html_body
    assert "<script" not in msg.html_body
    assert "Exposed admin panel and missing DMARC." in msg.html_body


def test_render_digest_email_handles_truncation_and_missing_headline() -> None:
    digest = _sample_digest(count=30, ai_headline=None, app_base_url=None)
    msg = render_digest_email(digest, "alice@example.com")

    assert "30 findings" in msg.subject
    assert "AI Summary" not in msg.text_body
    assert "Showing 25 of 30 findings." in msg.html_body
    assert "... and 5 more." in msg.text_body


def test_smtp_sender_starttls_and_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    clients: list[_FakeSMTP] = []

    def _factory(host: str, port: int, *, timeout: float) -> _FakeSMTP:
        client = _FakeSMTP(host, port, timeout=timeout)
        clients.append(client)
        return client

    monkeypatch.setattr(smtplib, "SMTP", _factory)
    sender = SmtpEmailSender(
        host="smtp.example",
        port=587,
        from_addr="noreply@example.com",
        tls="starttls",
        user="mailer",
        password=SecretStr("pw-secret"),
    )

    sender.send(
        EmailMessageData(
            to_email="alice@example.com",
            subject="Test subject",
            text_body="Plain body",
            html_body="<p>HTML body</p>",
        )
    )

    assert len(clients) == 1
    client = clients[0]
    assert client.actions == [
        ("ehlo", None),
        ("starttls", True),
        ("ehlo", None),
        ("login", ("mailer", "pw-secret")),
    ]
    mime = client.sent[0]
    assert mime["From"] == "noreply@example.com"
    assert mime["To"] == "alice@example.com"
    assert mime["Subject"] == "Test subject"
    assert mime["Auto-Submitted"] == "auto-generated"
    assert mime.is_multipart()


def test_smtp_sender_ssl_mode_and_none_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    ssl_clients: list[_FakeSMTP] = []
    plain_clients: list[_FakeSMTP] = []

    def _ssl_factory(host: str, port: int, *, timeout: float, context: object) -> _FakeSMTP:
        assert context is not None
        c = _FakeSMTP(host, port, timeout=timeout)
        ssl_clients.append(c)
        return c

    def _plain_factory(host: str, port: int, *, timeout: float) -> _FakeSMTP:
        c = _FakeSMTP(host, port, timeout=timeout)
        plain_clients.append(c)
        return c

    monkeypatch.setattr(smtplib, "SMTP_SSL", _ssl_factory)
    monkeypatch.setattr(smtplib, "SMTP", _plain_factory)

    msg = EmailMessageData(
        to_email="alice@example.com", subject="Hi", text_body="t", html_body="<p>h</p>"
    )
    SmtpEmailSender(host="smtp.example", port=465, from_addr="a@b.com", tls="ssl").send(msg)
    SmtpEmailSender(host="mailpit", port=1025, from_addr="a@b.com", tls="none").send(msg)

    assert len(ssl_clients) == 1
    assert ssl_clients[0].actions == []
    assert len(plain_clients) == 1
    assert plain_clients[0].actions == []


def test_smtp_sender_rejects_header_injection() -> None:
    sender = SmtpEmailSender(host="mailpit", port=1025, from_addr="a@b.com", tls="none")
    with pytest.raises(EmailDeliveryError, match="Invalid To header"):
        sender.send(
            EmailMessageData(
                to_email="alice@example.com\r\nBcc: evil@x",
                subject="Hi",
                text_body="t",
                html_body="<p>h</p>",
            )
        )


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (smtplib.SMTPServerDisconnected("bye"), TransientJobError),
        (TimeoutError("timed out"), TransientJobError),
        (smtplib.SMTPResponseException(421, b"try again"), TransientJobError),
        (smtplib.SMTPRecipientsRefused({"a@b.com": (450, b"greylisted")}), TransientJobError),
        (smtplib.SMTPSenderRefused(421, b"rate limited", "a@b.com"), TransientJobError),
        (smtplib.SMTPAuthenticationError(454, b"temporary auth failure"), TransientJobError),
        (smtplib.SMTPAuthenticationError(535, b"bad password secret"), EmailDeliveryError),
        (smtplib.SMTPRecipientsRefused({"a@b.com": (550, b"no user")}), EmailRecipientRefused),
        (smtplib.SMTPSenderRefused(550, b"bad sender", "a@b.com"), EmailDeliveryError),
        (smtplib.SMTPResponseException(550, b"rejected"), EmailDeliveryError),
    ],
)
def test_smtp_sender_maps_transient_and_permanent_errors_safely(
    monkeypatch: pytest.MonkeyPatch, exc: Exception, expected: type[Exception]
) -> None:
    class _FailingSMTP(_FakeSMTP):
        def send_message(self, msg: EmailMessage) -> dict[str, object]:
            raise exc

    monkeypatch.setattr(
        smtplib, "SMTP", lambda host, port, *, timeout: _FailingSMTP(host, port, timeout=timeout)
    )
    sender = SmtpEmailSender(host="mailpit", port=1025, from_addr="a@b.com", tls="none")

    with pytest.raises(expected) as caught:
        sender.send(
            EmailMessageData(
                to_email="alice@example.com", subject="Hi", text_body="t", html_body="<p>h</p>"
            )
        )

    assert "secret" not in str(caught.value)
    assert "a@b.com" not in str(caught.value)
