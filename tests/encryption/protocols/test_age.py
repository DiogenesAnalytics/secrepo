"""Tests for the age encryption protocol."""

from pathlib import Path

import pytest
from pyrage import decrypt
from pyrage import encrypt
from pyrage import x25519
from pyrage.x25519 import Identity
from pytest import MonkeyPatch

from secrepo.encryption.backend import BackendOption
from secrepo.encryption.protocols.age import AgeEncryptionBackend
from secrepo.encryption.protocols.age import default_identity_path
from secrepo.encryption.protocols.age import generate_identity
from secrepo.encryption.protocols.age import load_identity
from secrepo.encryption.protocols.age import resolve_identity_path
from secrepo.encryption.protocols.age import save_identity


@pytest.mark.enc
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


@pytest.mark.enc
def test_age_backend_encrypt_decrypt(tmp_path: Path) -> None:
    """Encrypt and decrypt a file using the age backend."""
    identity = Identity.generate()
    identity_path = tmp_path / "identity"

    save_identity(
        identity,
        identity_path,
    )

    recipient = str(identity.to_public())

    backend = AgeEncryptionBackend(
        recipients=[recipient],
        identity=identity_path,
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


@pytest.mark.enc
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


@pytest.mark.enc
def test_save_and_load_identity(tmp_path: Path) -> None:
    """Save and load an age identity."""
    identity = Identity.generate()
    path = tmp_path / "identity"

    save_identity(
        identity,
        path,
    )

    loaded = load_identity(path)

    plaintext = b"secret data"

    encrypted = encrypt(
        plaintext,
        [identity.to_public()],
    )

    decrypted = decrypt(
        encrypted,
        [loaded],
    )

    assert decrypted == plaintext


@pytest.mark.enc
def test_default_identity_path(monkeypatch: MonkeyPatch) -> None:
    """Return the default age identity path."""
    monkeypatch.setenv(
        "XDG_DATA_HOME",
        "/tmp/data",
    )

    assert default_identity_path() == Path(
        "/tmp/data/secrepo/age/identity",
    )


@pytest.mark.enc
def test_default_identity_path_without_xdg_data_home(monkeypatch: MonkeyPatch) -> None:
    """Use the standard home data directory without XDG_DATA_HOME."""
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(
        Path,
        "home",
        lambda: Path("/home/test"),
    )

    assert default_identity_path() == Path(
        "/home/test/.local/share/secrepo/age/identity",
    )


@pytest.mark.enc
def test_resolve_identity_path() -> None:
    """Prefer an explicitly supplied identity path."""
    path = Path("/custom/identity")

    assert resolve_identity_path(path) == path


@pytest.mark.enc
def test_resolve_identity_path_uses_default() -> None:
    """Use the default identity path when none is supplied."""
    assert resolve_identity_path() == default_identity_path()


@pytest.mark.enc
def test_config_options() -> None:
    """Expose age encryption configuration options."""
    assert AgeEncryptionBackend.config_options == (
        BackendOption(
            name="recipients",
            type="string",
            multiple=True,
            help="Age recipient(s) used for encryption.",
        ),
        BackendOption(
            name="identity",
            type="path",
            help="Path to the age identity file.",
        ),
    )
