"""Account use cases."""

from dataclasses import dataclass

import structlog
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.domain.accounts import (
    EmailAlreadyRegistered,
    PasswordHasher,
    Role,
    normalize_email,
    normalize_org_name,
    slugify,
    validate_password,
)
from attacksurf.infra.db.models import Membership, Org, User
from attacksurf.services.audit import audit

log = structlog.get_logger(__name__)

_EMAIL_UNIQUE_CONSTRAINT = "uq_users_email"


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
) -> Registration:
    """Create a user, their personal org and owner membership in one transaction, and commit.

    Raises `InvalidSignup` for bad input and `EmailAlreadyRegistered` for a taken email.
    """
    email = normalize_email(email)
    validate_password(password)
    name = normalize_org_name(org_name if org_name is not None else email.split("@")[0])
    if session.scalar(select(User.id).where(User.email == email)) is not None:
        raise EmailAlreadyRegistered("This email is already registered.")

    try:
        user = User(email=email, password_hash=hasher.hash(password))
        org = Org(name=name, slug=_unique_slug(session, slugify(name)))
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
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        # A concurrent signup with the same email passed the check above.
        if _violated_constraint(exc) == _EMAIL_UNIQUE_CONSTRAINT:
            raise EmailAlreadyRegistered("This email is already registered.") from None
        raise
    except Exception:
        session.rollback()
        raise

    log.info("user registered", user_id=str(user.id), org_id=str(org.id))
    return Registration(user=user, org=org)


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
