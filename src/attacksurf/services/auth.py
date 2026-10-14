"""Login, logout and the per-request identity lookup."""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.accounts import (
    InvalidCredentials,
    InvalidSignup,
    PasswordHasher,
    Role,
    normalize_email,
)
from attacksurf.infra.db.models import Membership, Org, User
from attacksurf.services.audit import audit

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class SessionUser:
    """Who is logged in and in which org they act (MVP: their first membership)."""

    user_id: UUID
    email: str
    org_id: UUID
    org_name: str
    role: Role


def authenticate(
    session: Session, hasher: PasswordHasher, email: str, password: str
) -> SessionUser:
    """Check credentials and record the attempt. Raises `InvalidCredentials` on any failure."""
    try:
        email = normalize_email(email)
    except InvalidSignup:
        email = ""
    user = session.scalar(select(User).where(User.email == email)) if email else None
    if user is None:
        # Spend the same argon2 work as a real check so timing doesn't reveal unknown emails.
        hasher.hash(password)
        log.info("login failed", reason="unknown_user")
        raise InvalidCredentials

    membership = _first_membership(session, user.id)
    password_ok = hasher.verify(user.password_hash, password)
    if not (password_ok and user.is_active and membership):
        reason = "bad_password" if not password_ok else "inactive"
        if membership is not None:
            audit(
                session,
                membership.org_id,
                "user.login_failed",
                actor_id=user.id,
                target_type="user",
                target_id=str(user.id),
                details={"reason": reason},
            )
            session.commit()
        log.info("login failed", reason=reason, user_id=str(user.id))
        raise InvalidCredentials

    if hasher.needs_rehash(user.password_hash):
        user.password_hash = hasher.hash(password)
    user.last_login_at = datetime.now(UTC)
    audit(
        session,
        membership.org_id,
        "user.login",
        actor_id=user.id,
        target_type="user",
        target_id=str(user.id),
    )
    session.commit()
    log.info("user logged in", user_id=str(user.id), org_id=str(membership.org_id))
    return _session_user(session, user, membership)


def record_logout(session: Session, user: SessionUser) -> None:
    audit(
        session,
        user.org_id,
        "user.logout",
        actor_id=user.user_id,
        target_type="user",
        target_id=str(user.user_id),
    )
    session.commit()


def load_session_user(session: Session, user_id: UUID) -> SessionUser | None:
    """The user behind a session cookie, or None if they were deactivated or lost their org."""
    user = session.get(User, user_id)
    if user is None or not user.is_active:
        return None
    membership = _first_membership(session, user.id)
    return _session_user(session, user, membership) if membership else None


def has_users(session: Session) -> bool:
    return session.scalar(select(User.id).limit(1)) is not None


def _first_membership(session: Session, user_id: UUID) -> Membership | None:
    # Identity lookup by the user's own id, not a tenant query: it decides which org they act in.
    return session.scalars(
        select(Membership)
        .where(Membership.user_id == user_id)
        .order_by(Membership.created_at, Membership.id)
        .limit(1)
    ).first()


def _session_user(session: Session, user: User, membership: Membership) -> SessionUser:
    org = session.get_one(Org, membership.org_id)
    return SessionUser(
        user_id=user.id,
        email=user.email,
        org_id=org.id,
        org_name=org.name,
        role=membership.role,
    )
