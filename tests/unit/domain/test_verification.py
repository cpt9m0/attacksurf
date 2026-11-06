"""TXT ownership proofs: token shape, the record to publish, and chunk-tolerant matching."""

import string

from attacksurf.domain.verification import (
    MAX_TOKEN_LENGTH,
    TOKEN_MIN_BYTES,
    TXT_RECORD_PREFIX,
    matches,
    new_token,
    record_name,
    record_value,
)

# A plainly fake sample: gitleaks reads high-entropy literals as secrets.
TOKEN = "sample-verification-token-0123456789-abcdef"


def test_new_token_carries_at_least_32_bytes_of_entropy() -> None:
    token = new_token()

    assert len(token) >= TOKEN_MIN_BYTES  # base64 of 32 bytes is longer, never shorter
    assert len(token.encode()) >= TOKEN_MIN_BYTES * 4 // 3
    assert set(token) <= set(string.ascii_letters + string.digits + "-_")  # no "=" padding


def test_new_tokens_do_not_repeat() -> None:
    assert len({new_token() for _ in range(100)}) == 100


def test_record_name_sits_one_label_under_the_asset() -> None:
    assert record_name("example.com") == "_attacksurf-verify.example.com"


def test_record_value_carries_the_documented_prefix() -> None:
    assert record_value(TOKEN) == f"{TXT_RECORD_PREFIX}{TOKEN}"


def test_the_exact_record_matches() -> None:
    assert matches(TOKEN, ("v=spf1 -all", record_value(TOKEN)))


def test_a_record_split_into_chunks_still_matches() -> None:
    # A long TXT record arrives as several chunks; some providers' UIs also wrap or space the
    # value. Only white space is ignored, never other characters.
    head, tail = TOKEN[:20], TOKEN[20:]
    chunks = (f"attacksurf-verification={head}", tail)

    assert matches(TOKEN, ("".join(chunks),))
    assert matches(TOKEN, (" ".join(chunks),))


def test_another_asset_token_does_not_match() -> None:
    assert not matches(TOKEN, (record_value("another-token"),))


def test_a_prefix_only_record_does_not_match() -> None:
    assert not matches(TOKEN, ("attacksurf-verification=",))


def test_extra_text_around_the_record_does_not_match() -> None:
    assert not matches(TOKEN, (f"prefix {record_value(TOKEN)}",))


def test_no_records_never_match() -> None:
    assert not matches(TOKEN, ())


def test_an_overlong_token_never_matches() -> None:
    assert not matches("a" * (MAX_TOKEN_LENGTH + 1), ("a" * (MAX_TOKEN_LENGTH + 1),))
