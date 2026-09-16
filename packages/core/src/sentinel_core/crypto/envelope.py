"""Envelope encryption for customer credentials (docs/01-architecture.md §6.3).

Every persona's login credential is encrypted with a per-organization data
key; the data key itself is wrapped by a master key (in production, an
actual KMS — AWS Secrets Manager / Infisical; here, a Fernet key from
config so local dev and CI don't need cloud infra). Plaintext credentials
exist only transiently, in memory, inside a scanner worker — never at rest,
never in a log line, never in an LLM prompt (rule enforced structurally in
sentinel_ai's client, not just here).

This is deliberately swappable: ``KmsMasterKeyProvider`` is the seam where a
real KMS call replaces the local Fernet master key without touching any
caller of ``EnvelopeCrypto``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from cryptography.fernet import Fernet, MultiFernet


class MasterKeyProvider(ABC):
    @abstractmethod
    def wrap(self, data_key: bytes) -> bytes: ...

    @abstractmethod
    def unwrap(self, wrapped: bytes) -> bytes: ...


class LocalMasterKeyProvider(MasterKeyProvider):
    """Dev/CI/self-hosted: master key(s) come from config (KMS_MASTER_KEY).

    Accepts multiple keys (comma-separated) so a key rotation is: add the
    new key first in the list, re-wrap active data keys, then remove the old
    one — the same rotation story MultiFernet gives for data encryption.
    """

    def __init__(self, master_keys: list[bytes]) -> None:
        if not master_keys:
            raise ValueError("At least one master key is required.")
        self._fernet = MultiFernet([Fernet(k) for k in master_keys])

    def wrap(self, data_key: bytes) -> bytes:
        return self._fernet.encrypt(data_key)

    def unwrap(self, wrapped: bytes) -> bytes:
        return self._fernet.decrypt(wrapped)


class EnvelopeCrypto:
    def __init__(self, master_key_provider: MasterKeyProvider) -> None:
        self._provider = master_key_provider

    def generate_data_key(self) -> bytes:
        """A fresh per-organization data key. Callers persist only the
        *wrapped* form (see wrap_data_key) — never the raw key."""
        return Fernet.generate_key()

    def wrap_data_key(self, data_key: bytes) -> bytes:
        return self._provider.wrap(data_key)

    def unwrap_data_key(self, wrapped_data_key: bytes) -> bytes:
        return self._provider.unwrap(wrapped_data_key)

    def encrypt(self, data_key: bytes, plaintext: bytes) -> bytes:
        return Fernet(data_key).encrypt(plaintext)

    def decrypt(self, data_key: bytes, ciphertext: bytes) -> bytes:
        return Fernet(data_key).decrypt(ciphertext)
