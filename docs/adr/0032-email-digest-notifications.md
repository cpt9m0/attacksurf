# 0032. Email digest notifications

- Status: accepted
- Date: 2026-11-20

## Context
Issue #28 adds email digest notifications so organization members learn about new and regressed findings from completed scans without opening the app. Each digest includes the matching findings above the user's severity threshold and the scan's AI exposure summary headline (ADR 0030) when available.

Two design constraints shape the implementation:

1. **AI runs after `ScanCompleted`.** Under ADR 0029 and ADR 0030, `finalize_scan` commits the scan as `completed`, publishes the best-effort `ScanCompleted` in-process event, and then queues `ai.triage`, which in turn queues `ai.summarize`. Dispatching email directly inside a `ScanCompleted` handler would send before AI triage/summary completes and would rely on the non-durable in-process dispatcher.
2. **Per-scan regression identity and delivery idempotency.** `Finding.status == regressed` persists across subsequent scans until fixed or suppressed, so querying `Finding.status` alone would re-notify on every later scan. Furthermore, Celery retries (`TransientJobError`) after a partial multi-recipient send must not re-send to users who already received the digest.

## Decision
1. **Trigger at the end of the post-scan AI phase.** `services.notifications.queue_scan_notification` queues one idempotent `passive.notify_scan` job (`stage="notify"`, `TrackedTask`) for a completed scan with an active root. It is called at every terminal exit of the AI phase (`ai.summarize` completion/skip/final failure, `ai.triage` budget/config skip, `ai.triage_failed`, and `finalize_scan`'s broker-error fallback). `NOTIFY_STAGE` is excluded from scan progress counts alongside `TRIAGE_STAGES`.
2. **Per-scan regression marker on `finding_observations`.** Migration `0014` adds `FindingObservation.regressed` (`BOOLEAN NOT NULL DEFAULT false`), set to `True` by `services.scan_diff._regress` in the same transaction that transitions `Finding.status` to `regressed`. Digest queries select `Finding.first_seen_scan_id == scan_id OR FindingObservation.regressed` for active findings observed by that scan.
3. **At-most-once delivery per `(org, scan, user)`.** Migration `0014` adds `notification_deliveries` (`UniqueConstraint("org_id", "scan_id", "user_id")`), committed immediately after each recipient's `EmailSender.send()` succeeds, and `notification_preferences` (`UniqueConstraint("org_id", "user_id")`, defaulting to `email_enabled=True, min_severity=high` when absent).
4. **Stdlib SMTP adapter with no external tracking.** `infra.email.SmtpEmailSender` uses Python's `smtplib` and `email.message.EmailMessage` (`starttls`, `ssl`, or `none`), mapping temporary network/4xx failures to `TransientJobError` (retried by Celery) and permanent 5xx/auth/header errors to `EmailDeliveryError` (sanitized message, no credentials or addresses). Templates (`digest.txt` and `digest.html`) are rendered with Jinja autoescaping for HTML and contain zero external images, scripts, or tracking pixels.

## Consequences
- Every completed scan with new or regressed findings above a user's threshold sends at most one digest email per recipient, including the AI summary headline whenever AI ran.
- Scans with no new/regressed findings, archived roots, or unconfigured `SMTP_HOST` skip cleanly without sending.
- Local development previews emails in Mailpit (`compose.yaml`).
