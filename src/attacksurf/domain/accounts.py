"""Accounts and tenancy rules: roles, signup validation, password hashing interface."""

import re
import unicodedata
from enum import StrEnum
from typing import Protocol

MIN_PASSWORD_LENGTH = 12
# Upper bound so a huge "password" can't make hashing a cheap DoS.
MAX_PASSWORD_LENGTH = 1024
MAX_EMAIL_LENGTH = 254
MAX_ORG_NAME_LENGTH = 200
MAX_SLUG_LENGTH = 50

# Deliberately loose: real validation is proving ownership of the address (later issue).
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_NON_SLUG_CHARS = re.compile(r"[^a-z0-9]+")


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


_ROLE_RANK = {Role.MEMBER: 1, Role.ADMIN: 2, Role.OWNER: 3}


def has_role(actual: Role, required: Role) -> bool:
    """True if `actual` grants at least the permissions of `required` (owner > admin > member)."""
    return _ROLE_RANK[actual] >= _ROLE_RANK[required]


class AccountError(Exception):
    """Base for account errors that `web/` maps to user-facing messages."""


class InvalidSignup(AccountError):
    pass


class EmailAlreadyRegistered(AccountError):
    pass


class PasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...

    def verify(self, password_hash: str, password: str) -> bool: ...


def normalize_email(raw: str) -> str:
    email = raw.strip().lower()
    if len(email) > MAX_EMAIL_LENGTH or not _EMAIL.fullmatch(email):
        raise InvalidSignup("Enter a valid email address.")
    return email


def validate_password(password: str) -> None:
    # Messages never echo the password.
    if len(password) < MIN_PASSWORD_LENGTH:
        raise InvalidSignup(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise InvalidSignup(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")


def normalize_org_name(raw: str) -> str:
    name = raw.strip()
    if not name or len(name) > MAX_ORG_NAME_LENGTH:
        raise InvalidSignup(f"Organization name must be 1-{MAX_ORG_NAME_LENGTH} characters.")
    return name


def slugify(name: str) -> str:
    """URL-safe slug: lowercase ASCII letters, digits, single hyphens; "org" if nothing is left."""
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    slug = _NON_SLUG_CHARS.sub("-", ascii_name.lower()).strip("-")
    return slug[:MAX_SLUG_LENGTH].rstrip("-") or "org"
