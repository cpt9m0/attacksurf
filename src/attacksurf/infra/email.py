"""SMTP email sender and digest renderer (`EmailSender` adapter, #28)."""

import smtplib
import ssl
from email.message import EmailMessage
from typing import Literal

from jinja2 import Environment, PackageLoader, select_autoescape
from pydantic import SecretStr

from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.notifications import (
    EmailDeliveryError,
    EmailMessageData,
    ScanDigest,
)

_MAX_SUBJECT_LENGTH = 200
_SMTP_TRANSIENT_MIN = 400
_SMTP_TRANSIENT_MAX = 500

_TEMPLATES = Environment(
    loader=PackageLoader("attacksurf.infra", "email_templates"),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _clean_header(value: str, *, label: str) -> str:
    if any(ch in value for ch in ("\r", "\n")):
        raise EmailDeliveryError(f"Invalid {label} header.")
    return value.strip()


def _sanitize_subject(subject: str) -> str:
    single_line = " ".join(subject.replace("\r", " ").replace("\n", " ").split())
    return single_line[:_MAX_SUBJECT_LENGTH]


def render_digest_email(digest: ScanDigest, to_email: str) -> EmailMessageData:
    """Render plain-text and HTML digest bodies for `digest`."""
    new_count = sum(1 for item in digest.findings if item.change == "new")
    regressed_count = sum(1 for item in digest.findings if item.change == "regressed")
    parts: list[str] = []
    if new_count:
        parts.append(f"{new_count} new")
    if regressed_count:
        parts.append(f"{regressed_count} regressed")
    summary_label = ", ".join(parts) if parts else f"{digest.total_matching} findings"
    if digest.truncated:
        summary_label = f"{digest.total_matching} findings"
    subject = _sanitize_subject(f"[attacksurf] {digest.root_domain}: {summary_label}")

    base = digest.app_base_url
    context = {
        "digest": digest,
        "new_count": new_count,
        "regressed_count": regressed_count,
        "scan_url": f"{base}/scans/{digest.scan_id}" if base else None,
        "settings_url": f"{base}/settings" if base else None,
    }
    text_body = _TEMPLATES.get_template("digest.txt").render(**context)
    html_body = _TEMPLATES.get_template("digest.html").render(**context)
    return EmailMessageData(
        to_email=to_email,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )


class SmtpEmailSender:
    """`domain.notifications.EmailSender` over stdlib `smtplib`."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        from_addr: str,
        tls: Literal["starttls", "ssl", "none"] = "starttls",
        user: str | None = None,
        password: SecretStr | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        self._host = host
        self._port = port
        self._from_addr = _clean_header(from_addr, label="From")
        self._tls = tls
        self._user = user
        self._password = password
        self._timeout_seconds = timeout_seconds

    def send(self, message: EmailMessageData) -> None:
        to_addr = _clean_header(message.to_email, label="To")
        subject = _clean_header(message.subject, label="Subject")
        mime = EmailMessage()
        mime["From"] = self._from_addr
        mime["To"] = to_addr
        mime["Subject"] = subject
        mime["Auto-Submitted"] = "auto-generated"
        mime.set_content(message.text_body, subtype="plain", charset="utf-8")
        mime.add_alternative(message.html_body, subtype="html", charset="utf-8")

        try:
            if self._tls == "ssl":
                client: smtplib.SMTP = smtplib.SMTP_SSL(
                    self._host,
                    self._port,
                    timeout=self._timeout_seconds,
                    context=ssl.create_default_context(),
                )
            else:
                client = smtplib.SMTP(self._host, self._port, timeout=self._timeout_seconds)
            with client:
                if self._tls == "starttls":
                    client.ehlo()
                    client.starttls(context=ssl.create_default_context())
                    client.ehlo()
                if self._user and self._password is not None:
                    client.login(self._user, self._password.get_secret_value())
                client.send_message(mime)
        except smtplib.SMTPAuthenticationError as exc:
            raise EmailDeliveryError("SMTP authentication failed.") from exc
        except smtplib.SMTPRecipientsRefused as exc:
            raise EmailDeliveryError("SMTP recipient refused.") from exc
        except smtplib.SMTPSenderRefused as exc:
            raise EmailDeliveryError("SMTP sender refused.") from exc
        except smtplib.SMTPResponseException as exc:
            if _SMTP_TRANSIENT_MIN <= exc.smtp_code < _SMTP_TRANSIENT_MAX:
                raise TransientJobError("Temporary SMTP server error.") from exc
            raise EmailDeliveryError("SMTP server rejected message.") from exc
        except (
            smtplib.SMTPServerDisconnected,
            smtplib.SMTPConnectError,
            smtplib.SMTPHeloError,
        ) as exc:
            raise TransientJobError("SMTP connection failed.") from exc
        except smtplib.SMTPException as exc:
            raise EmailDeliveryError("SMTP delivery failed.") from exc
        except (TimeoutError, OSError) as exc:
            raise TransientJobError("SMTP connection failed.") from exc
