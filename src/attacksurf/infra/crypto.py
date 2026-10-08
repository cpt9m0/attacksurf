"""Password hashing (argon2id, argon2-cffi's recommended parameters)."""

from argon2 import PasswordHasher as _Argon2
from argon2.exceptions import InvalidHashError, VerificationError


class Argon2PasswordHasher:
    """Implements `attacksurf.domain.accounts.PasswordHasher`."""

    def __init__(self, hasher: _Argon2 | None = None) -> None:
        self._hasher = hasher or _Argon2()

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (VerificationError, InvalidHashError):
            return False
