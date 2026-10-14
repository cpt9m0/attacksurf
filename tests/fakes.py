"""Test doubles for domain interfaces."""


class FakePasswordHasher:
    """Fast, deterministic stand-in for argon2 in service tests."""

    def hash(self, password: str) -> str:
        return f"fake${password[::-1]}"

    def verify(self, password_hash: str, password: str) -> bool:
        return password_hash == self.hash(password)

    def needs_rehash(self, password_hash: str) -> bool:
        return not password_hash.startswith("fake$")
