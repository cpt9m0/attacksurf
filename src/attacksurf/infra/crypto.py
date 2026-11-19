"""Password hashing (argon2id) and envelope encryption for data at rest (ADR 0028)."""

import secrets
from collections.abc import Iterator, Sequence
from typing import Protocol

from argon2 import PasswordHasher as _Argon2
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_BYTES = 32
CHUNK_BYTES = 64 * 1024  # plaintext per frame: what a stream holds in memory at a time
_KEK_INFO = b"attacksurf/kek/v1/"
_ENVELOPE_VERSION = b"\x01"
_BLOB_MAGIC = b"ASAF\x01"  # format name + version; authenticated with every frame
_PREFIX_BYTES = 7  # random per blob; with the 4-byte counter and final flag: a 12-byte nonce
_NONCE_BYTES = 12
_TAG_BYTES = 16
_WRAPPED_KEY_BYTES = 1 + _NONCE_BYTES + KEY_BYTES + _TAG_BYTES


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

    def needs_rehash(self, password_hash: str) -> bool:
        """True when the hash used older parameters; rehash after a successful login."""
        return self._hasher.check_needs_rehash(password_hash)


class DecryptionError(Exception):
    """A key or ciphertext failed authentication. Never says which part or why."""

    def __init__(self) -> None:
        super().__init__("Decryption failed.")


class ByteSource(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


class EnvelopeCipher:
    """Wraps per-record data keys under a key derived from `APP_ENCRYPTION_KEY` (ADR 0028).

    `purpose` separates the wrapping keys of different features, so an envelope written for
    one can't be unwrapped by another.
    """

    def __init__(self, app_key: bytes, *, purpose: bytes) -> None:
        # Checked here too, not only in Settings: HKDF would derive a key from any input.
        if len(app_key) != KEY_BYTES:
            raise ValueError("The app key must be 32 bytes.")
        kdf = HKDF(algorithm=SHA256(), length=KEY_BYTES, salt=None, info=_KEK_INFO + purpose)
        self._kek = AESGCM(kdf.derive(app_key))

    def wrap(self, key: bytes, *, aad: bytes) -> bytes:
        if len(key) != KEY_BYTES:
            raise ValueError("The key to wrap must be 32 bytes.")
        nonce = secrets.token_bytes(_NONCE_BYTES)
        return _ENVELOPE_VERSION + nonce + self._kek.encrypt(nonce, key, aad)

    def unwrap(self, envelope: bytes, *, aad: bytes) -> bytes:
        nonce, wrapped = envelope[1 : 1 + _NONCE_BYTES], envelope[1 + _NONCE_BYTES :]
        if envelope[:1] != _ENVELOPE_VERSION or len(nonce) != _NONCE_BYTES:
            raise DecryptionError
        try:
            return self._kek.decrypt(nonce, wrapped, aad)
        except InvalidTag:
            raise DecryptionError from None


class SecretCipher:
    """Encrypts small secrets (e.g. org API keys) under `APP_ENCRYPTION_KEY` with key rotation.

    Wraps a per-secret 256-bit DEK with `EnvelopeCipher` (HKDF purpose separation + AAD binding)
    and seals the secret with AES-256-GCM under that DEK. Encryption uses `primary_key`;
    decryption accepts `primary_key` or any key in `old_keys` for zero-downtime key rotation.
    """

    def __init__(
        self,
        primary_key: bytes,
        *,
        old_keys: Sequence[bytes] = (),
        purpose: bytes = b"org_api_key",
    ) -> None:
        self._primary = EnvelopeCipher(primary_key, purpose=purpose)
        self._ciphers = (
            self._primary,
            *(EnvelopeCipher(key, purpose=purpose) for key in old_keys),
        )

    def encrypt_secret(self, plaintext: str, *, aad: bytes) -> bytes:
        try:
            raw = plaintext.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("Secret contains invalid characters.") from None
        dek = secrets.token_bytes(KEY_BYTES)
        wrapped_dek = self._primary.wrap(dek, aad=aad)
        nonce = secrets.token_bytes(_NONCE_BYTES)
        ciphertext = AESGCM(dek).encrypt(nonce, raw, aad)
        return _ENVELOPE_VERSION + wrapped_dek + nonce + ciphertext

    def decrypt_secret(self, ciphertext: bytes, *, aad: bytes) -> str:
        min_len = 1 + _WRAPPED_KEY_BYTES + _NONCE_BYTES + _TAG_BYTES
        if len(ciphertext) < min_len or ciphertext[:1] != _ENVELOPE_VERSION:
            raise DecryptionError
        wrapped_end = 1 + _WRAPPED_KEY_BYTES
        nonce_end = wrapped_end + _NONCE_BYTES
        wrapped_dek = ciphertext[1:wrapped_end]
        nonce = ciphertext[wrapped_end:nonce_end]
        sealed = ciphertext[nonce_end:]
        dek = self._unwrap_any(wrapped_dek, aad=aad)
        try:
            raw = AESGCM(dek).decrypt(nonce, sealed, aad)
            return raw.decode("utf-8")
        except (InvalidTag, UnicodeDecodeError):
            raise DecryptionError from None

    def _unwrap_any(self, wrapped_dek: bytes, *, aad: bytes) -> bytes:
        for cipher in self._ciphers:
            try:
                return cipher.unwrap(wrapped_dek, aad=aad)
            except DecryptionError:
                continue
        raise DecryptionError


def _read_full(source: ByteSource, size: int) -> bytes:
    """Read exactly `size` bytes unless the stream ends: sockets return short reads."""
    parts: list[bytes] = []
    while size > 0 and (part := source.read(size)):
        parts.append(part)
        size -= len(part)
    return b"".join(parts)


def _frame_nonce(prefix: bytes, counter: int, *, final: bool) -> bytes:
    # The counter fixes each frame's position and the flag marks the last one, so frames
    # can't be reordered, repeated or cut off without failing authentication.
    return prefix + counter.to_bytes(4, "big") + (b"\x01" if final else b"\x00")


def encrypt_stream(dek: bytes, source: ByteSource) -> Iterator[bytes]:
    """Header, then one AES-256-GCM frame per `CHUNK_BYTES` of `source`. `dek`: single use."""
    header = _BLOB_MAGIC + secrets.token_bytes(_PREFIX_BYTES)
    aead = AESGCM(dek)
    yield header
    chunk, counter = _read_full(source, CHUNK_BYTES), 0
    while True:
        # One chunk is held back, so the last frame is known when it is sealed.
        following = _read_full(source, CHUNK_BYTES)
        nonce = _frame_nonce(header[len(_BLOB_MAGIC) :], counter, final=not following)
        yield aead.encrypt(nonce, chunk, header)
        if not following:
            return
        chunk, counter = following, counter + 1


def decrypt_stream(dek: bytes, source: ByteSource) -> Iterator[bytes]:
    """Plaintext chunks of an `encrypt_stream` blob. Raises `DecryptionError` on any change.

    Chunks are yielded as they authenticate; a truncated blob is only detected at its end, so
    a consumer must discard what it read when this raises.
    """
    header = _read_full(source, len(_BLOB_MAGIC) + _PREFIX_BYTES)
    if len(header) != len(_BLOB_MAGIC) + _PREFIX_BYTES or not header.startswith(_BLOB_MAGIC):
        raise DecryptionError
    aead = AESGCM(dek)
    frame, counter = _read_full(source, CHUNK_BYTES + _TAG_BYTES), 0
    while True:
        following = _read_full(source, CHUNK_BYTES + _TAG_BYTES)
        nonce = _frame_nonce(header[len(_BLOB_MAGIC) :], counter, final=not following)
        try:
            yield aead.decrypt(nonce, frame, header)
        except InvalidTag:
            raise DecryptionError from None
        if not following:
            return
        frame, counter = following, counter + 1
