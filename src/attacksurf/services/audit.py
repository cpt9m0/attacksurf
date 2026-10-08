"""Audit trail helper."""

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from attacksurf.infra.db.models import AuditLog


def audit(
    session: Session,
    org_id: UUID,
    action: str,
    *,
    actor_id: UUID | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Record `action` in the caller's transaction (no commit), so it persists with the change.

    `details` is stored as-is: never pass secrets, tokens or passwords.
    """
    entry = AuditLog(
        org_id=org_id,
        action=action,
        actor_user_id=actor_id,
        target_type=target_type,
        target_id=target_id,
        details=details or {},
    )
    session.add(entry)
    return entry
