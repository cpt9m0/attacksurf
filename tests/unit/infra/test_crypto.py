from argon2 import PasswordHasher

from attacksurf.infra.crypto import Argon2PasswordHasher

# Minimal cost: these tests check behavior, not hashing strength.
FAST = Argon2PasswordHasher(PasswordHasher(time_cost=1, memory_cost=8, parallelism=1))


def test_hash_is_argon2id_and_salted() -> None:
    first, second = FAST.hash("correct horse"), FAST.hash("correct horse")

    assert first.startswith("$argon2id$")
    assert first != second


def test_verify_accepts_correct_password() -> None:
    assert FAST.verify(FAST.hash("correct horse"), "correct horse") is True


def test_verify_rejects_wrong_password() -> None:
    assert FAST.verify(FAST.hash("correct horse"), "wrong horse") is False


def test_verify_rejects_malformed_hash() -> None:
    assert FAST.verify("not-a-hash", "correct horse") is False


def test_default_parameters_produce_verifiable_hash() -> None:
    hasher = Argon2PasswordHasher()

    assert hasher.verify(hasher.hash("correct horse battery"), "correct horse battery")
