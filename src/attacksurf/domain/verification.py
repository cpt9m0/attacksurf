"""Ownership proof by DNS TXT record: the token the org publishes, and how it is matched.

A TXT proof is only as private as the zone it lives in, so nothing here is a secret: the
record name and value are shown to the user and copied into their DNS provider. What proves
control is that only the zone's owners can publish it.
"""

import secrets
from datetime import datetime, timedelta
from enum import StrEnum

# One label under the asset: "_attacksurf-verify.example.com", so a CNAME wildcard on the
# apex doesn't hide the proof. The token is matched from the value, so the callout is precise.
TXT_RECORD_NAME = "_attacksurf-verify"
TXT_RECORD_PREFIX = "attacksurf-verification="
# 32 random bytes, URL-safe base64 without padding: 43 characters, well past any real spoofing.
TOKEN_MIN_BYTES = 32
MAX_TOKEN_LENGTH = 128
# A zone can hold several TXT records at the name; only these are ours to inspect.
MAX_TXT_RECORDS = 50
MAX_TXT_BYTES = 4096
# How often a verified record is checked again by the hourly re-verification run. The recheck
# is due well before the proof stops counting, so a healthy domain is refreshed while its
# authorization is still valid: the hourly beat can be up to an hour late, and a lookup that
# fails must not cost access either.
RECHECK_AFTER = timedelta(hours=20)
# How long a verified proof authorizes active checks. `RECHECK_AFTER` + the beat interval +
# room for a failed check leaves the proof valid across at least one missed renewal.
PROOF_VALID_FOR = timedelta(days=1)
# How long a proof keeps counting after a failed (or never run) check, so a flaky lookup or a
# worker outage doesn't revoke every domain at once.
GRACE_AFTER_FAILURE = timedelta(days=7)


class VerificationStatus(StrEnum):
    PENDING = "pending"  # token issued, not seen in DNS yet
    VERIFIED = "verified"  # the record was found
    REVOKED = "revoked"  # it was verified once, then the record disappeared


class OwnershipState(StrEnum):
    """What a proof grants right now, for the gate and the UI.

    `EXPIRED` is derived, never stored: a row still says `verified` after `expires_at` (the
    next check may revive it), but neither the gate nor a badge may count it.
    """

    NONE = "none"  # no token issued
    PENDING = "pending"
    VERIFIED = "verified"
    EXPIRED = "expired"  # stored verified, past `expires_at`
    REVOKED = "revoked"


class VerificationMethod(StrEnum):
    DNS_TXT = "dns_txt"


def ownership_state(
    status: VerificationStatus | None, expires_at: datetime | None, now: datetime
) -> OwnershipState:
    """One definition of "does this proof count", shared by the gate and every badge (ADR 0014).

    Otherwise the UI could show a green Verified while ScopeGuard denies the domain.
    """
    if status is None:
        return OwnershipState.NONE
    if status is VerificationStatus.VERIFIED and (expires_at is None or now >= expires_at):
        return OwnershipState.EXPIRED
    return OwnershipState(status.value)


def new_token() -> str:
    """An unpredictable token; no padding, so it is a valid DNS value on every provider."""
    return secrets.token_urlsafe(TOKEN_MIN_BYTES)


def record_name(asset_value: str) -> str:
    """The FQDN owners publish, without a trailing dot: `_attacksurf-verify.example.com`."""
    return f"{TXT_RECORD_NAME}.{asset_value}"


def record_value(token: str) -> str:
    """The TXT value to publish."""
    return f"{TXT_RECORD_PREFIX}{token}"


def matches(token: str, values: tuple[str, ...]) -> bool:
    """True if one of the TXT values is exactly our record.

    Resolvers hand back the chunks of a long record separately and in any order, so each value
    is compared after removing white space. A record with extra text, or one carrying another
    asset's token, never matches.
    """
    if not token or len(token) > MAX_TOKEN_LENGTH:
        return False
    expected = record_value(token)
    return any(_normalized(value) == expected for value in values[:MAX_TXT_RECORDS])


def _normalized(value: str) -> str:
    return "".join(value.split())
