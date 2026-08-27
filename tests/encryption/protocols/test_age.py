"""Tests for the age encryption protocol."""

from pathlib import Path

from pyrage import decrypt
from pyrage import encrypt
from pyrage import x25519
from pyrage.x25519 import Identity

from secrepo.encryption.protocols.age import AgeEncryptionBackend
from secrepo.encryption.protocols.age import generate_identity


def test_age_encrypt_decrypt() -> None:
    """Encrypt and decrypt data using age."""
    identity = x25519.Identity.generate()
    recipient = identity.to_public()

    plaintext = b"secret data"

    encrypted = encrypt(
        plaintext,
        [recipient],
    )

    decrypted = decrypt(
        encrypted,
        [identity],
    )

    assert decrypted == plaintext


def test_age_backend_encrypt_decrypt(tmp_path: Path) -> None:
    """Encrypt and decrypt a file using the age backend."""
    identity = Identity.generate()
    recipient = identity.to_public()

    backend = AgeEncryptionBackend(
        recipients=[recipient],
        identities=[identity],
    )

    plaintext_path = tmp_path / "secret.txt"
    encrypted_path = tmp_path / "secret.txt.enc"
    decrypted_path = tmp_path / "secret.decrypted.txt"

    plaintext = b"secret data"

    plaintext_path.write_bytes(plaintext)

    backend.encrypt(
        plaintext_path,
        encrypted_path,
    )

    assert encrypted_path.exists()
    assert encrypted_path.read_bytes() != plaintext

    backend.decrypt(
        encrypted_path,
        decrypted_path,
    )

    assert decrypted_path.exists()
    assert decrypted_path.read_bytes() == plaintext


def test_generate_identity() -> None:
    """Generate an identity that can encrypt and decrypt data."""
    identity = generate_identity()
    recipient = identity.to_public()

    plaintext = b"secret data"

    encrypted = encrypt(
        plaintext,
        [recipient],
    )

    decrypted = decrypt(
        encrypted,
        [identity],
    )

    assert decrypted == plaintext
