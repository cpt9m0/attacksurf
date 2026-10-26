"""Account use cases."""

from dataclasses import dataclass

import structlog
from sqlalchemy import or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.domain.accounts import (
    EmailAlreadyRegistered,
    PasswordHasher,
    Role,
    SignupClosed,
    normalize_email,
    normalize_org_name,
    slugify,
    validate_password,
)
from attacksurf.infra.db.models import Membership, Org, User
from attacksurf.services.audit import audit

log = structlog.get_logger(__name__)

_EMAIL_UNIQUE_CONSTRAINT = "uq_users_email"
_SLUG_UNIQUE_CONSTRAINT = "uq_orgs_slug"
_SLUG_ATTEMPTS = 3
# Arbitrary app-wide key for pg_advisory_xact_lock (bigint); only bootstrap signup uses it.
_FIRST_USER_LOCK = 0x6174_7375_7266_0001


@dataclass(frozen=True)
class Registration:
    user: User
    org: Org


def register_user(
    session: Session,
    hasher: PasswordHasher,
    email: str,
    password: str,
    org_name: str | None = None,
    *,
    first_user_only: bool = False,
) -> Registration:
    """Create a user, their personal org and owner membership in one transaction, and commit.

    Raises `InvalidSignup` for bad input and `EmailAlreadyRegistered` for a taken email.
    With `first_user_only` (signup disabled), raises `SignupClosed` unless no user exists yet.
    """
    email = normalize_email(email)
    validate_password(password)
    name = normalize_org_name(org_name if org_name is not None else email.split("@")[0])
    if first_user_only:
        # Serialize bootstrap signups: the lock is held until this transaction ends, so a
        # concurrent request waits and then sees the first user. Checking outside it races.
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _FIRST_USER_LOCK})
        if session.scalar(select(User.id).limit(1)) is not None:
            session.rollback()
            raise SignupClosed("Signup is closed.")
    if session.scalar(select(User.id).where(User.email == email)) is not None:
        raise EmailAlreadyRegistered("This email is already registered.")

    password_hash = hasher.hash(password)  # once: argon2 is deliberately slow
    for attempt in range(1, _SLUG_ATTEMPTS + 1):
        try:
            user, org = _create_account(session, email, password_hash, name)
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            constraint = _violated_constraint(exc)
            # A concurrent signup with the same email passed the check above.
            if constraint == _EMAIL_UNIQUE_CONSTRAINT:
                raise EmailAlreadyRegistered("This email is already registered.") from None
            # A concurrent signup took the slug we picked: pick again (it is now visible).
            if constraint == _SLUG_UNIQUE_CONSTRAINT and attempt < _SLUG_ATTEMPTS:
                continue
            raise
        except Exception:
            session.rollback()
            raise
        log.info("user registered", user_id=str(user.id), org_id=str(org.id))
        return Registration(user=user, org=org)
    raise AssertionError("unreachable: the last attempt returns or raises")  # pragma: no cover


def _create_account(
    session: Session, email: str, password_hash: str, org_name: str
) -> tuple[User, Org]:
    user = User(email=email, password_hash=password_hash)
    org = Org(name=org_name, slug=_unique_slug(session, slugify(org_name)))
    session.add_all([user, org])
    session.flush()
    session.add(Membership(org_id=org.id, user_id=user.id, role=Role.OWNER))
    audit(
        session,
        org.id,
        "user.registered",
        actor_id=user.id,
        target_type="user",
        target_id=str(user.id),
    )
    return user, org


def _unique_slug(session: Session, base: str) -> str:
    """`base`, or `base-2`, `base-3`, ... whichever is free. Slugs are [a-z0-9-], safe in LIKE."""
    taken = set(
        session.scalars(select(Org.slug).where(or_(Org.slug == base, Org.slug.like(f"{base}-%"))))
    )
    if base not in taken:
        return base
    n = 2
    while f"{base}-{n}" in taken:
        n += 1
    return f"{base}-{n}"


def _violated_constraint(exc: IntegrityError) -> str | None:
    diag = getattr(exc.orig, "diag", None)
    return getattr(diag, "constraint_name", None)
