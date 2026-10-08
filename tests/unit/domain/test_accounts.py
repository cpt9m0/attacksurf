import pytest

from attacksurf.domain.accounts import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    InvalidSignup,
    Role,
    has_role,
    normalize_email,
    normalize_org_name,
    slugify,
    validate_password,
)


@pytest.mark.parametrize(
    ("actual", "required", "allowed"),
    [
        (Role.OWNER, Role.OWNER, True),
        (Role.OWNER, Role.ADMIN, True),
        (Role.OWNER, Role.MEMBER, True),
        (Role.ADMIN, Role.OWNER, False),
        (Role.ADMIN, Role.ADMIN, True),
        (Role.ADMIN, Role.MEMBER, True),
        (Role.MEMBER, Role.OWNER, False),
        (Role.MEMBER, Role.ADMIN, False),
        (Role.MEMBER, Role.MEMBER, True),
    ],
)
def test_has_role_respects_hierarchy(actual: Role, required: Role, allowed: bool) -> None:
    assert has_role(actual, required) is allowed


def test_normalize_email_trims_and_lowercases() -> None:
    assert normalize_email("  Alice@Example.COM ") == "alice@example.com"


@pytest.mark.parametrize(
    "email", ["", "alice", "alice@", "@example.com", "alice@example", "a b@example.com"]
)
def test_normalize_email_rejects_malformed(email: str) -> None:
    with pytest.raises(InvalidSignup):
        normalize_email(email)


def test_normalize_email_rejects_overlong() -> None:
    with pytest.raises(InvalidSignup):
        normalize_email("a" * 250 + "@example.com")


def test_validate_password_accepts_bounds() -> None:
    validate_password("x" * MIN_PASSWORD_LENGTH)
    validate_password("x" * MAX_PASSWORD_LENGTH)


@pytest.mark.parametrize("length", [0, MIN_PASSWORD_LENGTH - 1, MAX_PASSWORD_LENGTH + 1])
def test_validate_password_rejects_out_of_bounds(length: int) -> None:
    with pytest.raises(InvalidSignup):
        validate_password("x" * length)


def test_validate_password_error_does_not_echo_password() -> None:
    with pytest.raises(InvalidSignup) as exc:
        validate_password("hunter2")

    assert "hunter2" not in str(exc.value)


def test_normalize_org_name_trims() -> None:
    assert normalize_org_name("  Acme Inc ") == "Acme Inc"


@pytest.mark.parametrize("name", ["", "   ", "x" * 201])
def test_normalize_org_name_rejects_empty_or_overlong(name: str) -> None:
    with pytest.raises(InvalidSignup):
        normalize_org_name(name)


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        ("Acme Inc.", "acme-inc"),
        ("  --Hello__World--  ", "hello-world"),
        ("Café Zürich", "cafe-zurich"),
        ("日本", "org"),
        ("!!!", "org"),
    ],
)
def test_slugify(name: str, slug: str) -> None:
    assert slugify(name) == slug


def test_slugify_truncates_without_trailing_hyphen() -> None:
    slug = slugify("a" * 49 + " b")

    assert slug == "a" * 49
