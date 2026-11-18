"""Envelope encryption (ADR 0028): key wrapping and the streaming AEAD frame format."""

import io
import secrets

import pytest

from attacksurf.infra import crypto
from attacksurf.infra.crypto import (
    CHUNK_BYTES,
    DecryptionError,
    EnvelopeCipher,
    decrypt_stream,
    encrypt_stream,
)

APP_KEY = b"k" * 32
DEK = b"d" * 32
HEADER = 12
FRAME = CHUNK_BYTES + 16


def _encrypt(plaintext: bytes, dek: bytes = DEK) -> bytes:
    return b"".join(encrypt_stream(dek, io.BytesIO(plaintext)))


def _decrypt(blob: bytes, dek: bytes = DEK) -> bytes:
    return b"".join(decrypt_stream(dek, io.BytesIO(blob)))


class _Trickle(io.BytesIO):
    """A stream that returns fewer bytes than asked, like a socket."""

    def read(self, size: int | None = -1) -> bytes:
        return super().read(min(size or 7, 7))


def test_wrap_round_trips_a_key_in_a_61_byte_envelope() -> None:
    cipher = EnvelopeCipher(APP_KEY, purpose=b"artifact")

    envelope = cipher.wrap(DEK, aad=b"row-1")

    assert len(envelope) == 61
    assert DEK not in envelope
    assert cipher.unwrap(envelope, aad=b"row-1") == DEK


@pytest.mark.parametrize("app_key", [b"", b"abc", b"k" * 31, b"k" * 33])
def test_cipher_refuses_an_app_key_that_is_not_32_bytes(app_key: bytes) -> None:
    with pytest.raises(ValueError, match="32 bytes") as error:
        EnvelopeCipher(app_key, purpose=b"artifact")

    assert "abc" not in str(error.value)


@pytest.mark.parametrize("key", [b"", b"x", b"d" * 33])
def test_wrap_refuses_a_key_that_is_not_32_bytes(key: bytes) -> None:
    cipher = EnvelopeCipher(APP_KEY, purpose=b"artifact")

    with pytest.raises(ValueError, match="32 bytes"):
        cipher.wrap(key, aad=b"row-1")


def test_wrap_uses_a_fresh_nonce_each_time() -> None:
    cipher = EnvelopeCipher(APP_KEY, purpose=b"artifact")

    assert cipher.wrap(DEK, aad=b"a") != cipher.wrap(DEK, aad=b"a")


@pytest.mark.parametrize(
    "other",
    [
        EnvelopeCipher(b"x" * 32, purpose=b"artifact"),  # another app key
        EnvelopeCipher(APP_KEY, purpose=b"org-api-key"),  # same key, another purpose
    ],
)
def test_unwrap_fails_under_another_key_or_purpose(other: EnvelopeCipher) -> None:
    envelope = EnvelopeCipher(APP_KEY, purpose=b"artifact").wrap(DEK, aad=b"a")

    with pytest.raises(DecryptionError):
        other.unwrap(envelope, aad=b"a")


def test_unwrap_fails_with_other_associated_data() -> None:
    cipher = EnvelopeCipher(APP_KEY, purpose=b"artifact")

    with pytest.raises(DecryptionError):
        cipher.unwrap(cipher.wrap(DEK, aad=b"org-a"), aad=b"org-b")


@pytest.mark.parametrize("mutate", [lambda e: b"\x02" + e[1:], lambda e: e[:-1], lambda e: b""])
def test_unwrap_rejects_malformed_envelopes(mutate) -> None:  # type: ignore[no-untyped-def]
    cipher = EnvelopeCipher(APP_KEY, purpose=b"artifact")
    envelope = cipher.wrap(DEK, aad=b"a")

    with pytest.raises(DecryptionError):
        cipher.unwrap(mutate(envelope), aad=b"a")


def test_decryption_error_message_is_fixed() -> None:
    cipher = EnvelopeCipher(APP_KEY, purpose=b"artifact")

    with pytest.raises(DecryptionError) as error:
        cipher.unwrap(b"\x01" + b"n" * 60, aad=b"a")

    assert str(error.value) == "Decryption failed."


@pytest.mark.parametrize(
    "size", [0, 1, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1, 3 * CHUNK_BYTES]
)
def test_stream_round_trips_every_boundary_size(size: int) -> None:
    plaintext = secrets.token_bytes(size)

    assert _decrypt(_encrypt(plaintext)) == plaintext


def test_stream_blob_has_a_magic_header_and_no_plaintext() -> None:
    blob = _encrypt(b"attack surface " * 100)

    assert blob[:5] == b"ASAF\x01"
    assert b"attack surface" not in blob
    assert len(blob) == HEADER + 1500 + 16


def test_empty_input_is_one_authenticated_frame() -> None:
    assert len(_encrypt(b"")) == HEADER + 16


def test_same_plaintext_encrypts_differently_each_time() -> None:
    assert _encrypt(b"same") != _encrypt(b"same")


def test_stream_frames_do_not_depend_on_how_the_source_chunks_reads() -> None:
    plaintext = secrets.token_bytes(1000)

    blob = b"".join(encrypt_stream(DEK, _Trickle(plaintext)))

    assert len(blob) == HEADER + 1000 + 16
    assert b"".join(decrypt_stream(DEK, _Trickle(blob))) == plaintext


def test_stream_never_buffers_more_than_two_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(crypto, "CHUNK_BYTES", 8)
    reads: list[int] = []

    class Recording(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            reads.append(size or 0)
            return super().read(size)

    blob = b"".join(crypto.encrypt_stream(DEK, Recording(b"x" * 64)))

    assert max(reads) == 8
    assert b"".join(crypto.decrypt_stream(DEK, io.BytesIO(blob))) == b"x" * 64


def test_flipped_byte_is_rejected_anywhere_in_the_blob() -> None:
    blob = _encrypt(secrets.token_bytes(CHUNK_BYTES + 100))

    for position in (0, 4, 6, HEADER, HEADER + 10, HEADER + FRAME + 5, len(blob) - 1):
        tampered = bytearray(blob)
        tampered[position] ^= 0x01
        with pytest.raises(DecryptionError):
            _decrypt(bytes(tampered))


@pytest.mark.parametrize("keep", [0, 5, HEADER, HEADER + 10, HEADER + FRAME, HEADER + FRAME + 3])
def test_truncated_blob_is_rejected(keep: int) -> None:
    # HEADER + FRAME cuts exactly at a frame boundary: only the final flag catches that.
    blob = _encrypt(secrets.token_bytes(2 * CHUNK_BYTES))

    with pytest.raises(DecryptionError):
        _decrypt(blob[:keep])


def test_swapped_frames_are_rejected() -> None:
    blob = _encrypt(secrets.token_bytes(3 * CHUNK_BYTES))
    first, second = blob[HEADER : HEADER + FRAME], blob[HEADER + FRAME : HEADER + 2 * FRAME]

    with pytest.raises(DecryptionError):
        _decrypt(blob[:HEADER] + second + first + blob[HEADER + 2 * FRAME :])


def test_duplicated_frame_is_rejected() -> None:
    blob = _encrypt(secrets.token_bytes(2 * CHUNK_BYTES))
    first = blob[HEADER : HEADER + FRAME]

    with pytest.raises(DecryptionError):
        _decrypt(blob[:HEADER] + first + blob[HEADER:])


@pytest.mark.parametrize("size", [10, CHUNK_BYTES])
def test_trailing_garbage_is_rejected(size: int) -> None:
    blob = _encrypt(secrets.token_bytes(size))

    with pytest.raises(DecryptionError):
        _decrypt(blob + b"\x00")


def test_frames_from_another_blob_are_rejected() -> None:
    # Same key, different header: a frame can't be spliced into another artifact's blob.
    one, two = _encrypt(b"a" * 100), _encrypt(b"b" * 100)

    with pytest.raises(DecryptionError):
        _decrypt(one[:HEADER] + two[HEADER:])


def test_wrong_data_key_is_rejected() -> None:
    with pytest.raises(DecryptionError):
        _decrypt(_encrypt(b"payload"), dek=b"e" * 32)
