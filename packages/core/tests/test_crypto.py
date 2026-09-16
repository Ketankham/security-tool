from cryptography.fernet import Fernet
from sentinel_core.crypto import EnvelopeCrypto, LocalMasterKeyProvider


def make_crypto():
    master_key = Fernet.generate_key()
    return EnvelopeCrypto(LocalMasterKeyProvider([master_key]))


def test_data_key_roundtrip_wrap_unwrap():
    crypto = make_crypto()
    data_key = crypto.generate_data_key()
    wrapped = crypto.wrap_data_key(data_key)
    assert wrapped != data_key
    assert crypto.unwrap_data_key(wrapped) == data_key


def test_encrypt_decrypt_roundtrip():
    crypto = make_crypto()
    data_key = crypto.generate_data_key()
    plaintext = b"correct-horse-battery-staple"
    ciphertext = crypto.encrypt(data_key, plaintext)
    assert ciphertext != plaintext
    assert crypto.decrypt(data_key, ciphertext) == plaintext


def test_different_orgs_get_independent_data_keys():
    crypto = make_crypto()
    key_org_a = crypto.generate_data_key()
    key_org_b = crypto.generate_data_key()
    assert key_org_a != key_org_b

    secret = b"org-a-password"
    ciphertext = crypto.encrypt(key_org_a, secret)
    # org B's key cannot decrypt org A's secret
    import pytest
    from cryptography.fernet import InvalidToken

    with pytest.raises(InvalidToken):
        crypto.decrypt(key_org_b, ciphertext)


def test_master_key_rotation_via_multifernet():
    old_key = Fernet.generate_key()
    new_key = Fernet.generate_key()

    crypto_old = EnvelopeCrypto(LocalMasterKeyProvider([old_key]))
    data_key = crypto_old.generate_data_key()
    wrapped_with_old = crypto_old.wrap_data_key(data_key)

    # Rotation: new key first, old key still accepted for decrypt.
    crypto_rotating = EnvelopeCrypto(LocalMasterKeyProvider([new_key, old_key]))
    assert crypto_rotating.unwrap_data_key(wrapped_with_old) == data_key

    # Re-wrap with the rotating provider now uses the new key primarily.
    rewrapped = crypto_rotating.wrap_data_key(data_key)
    crypto_new_only = EnvelopeCrypto(LocalMasterKeyProvider([new_key]))
    assert crypto_new_only.unwrap_data_key(rewrapped) == data_key
