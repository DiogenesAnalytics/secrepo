"""Tests for SecureRepo repository management."""

from pathlib import Path

import pytest
from pytest import MonkeyPatch

from secrepo.config import CONFIG_FILENAME
from secrepo.config import CONFIG_VERSION
from secrepo.config import DEFAULT_ENCRYPTION_PROTOCOL
from secrepo.config import SECREPO_DIRNAME
from secrepo.config import EncryptionConfig
from secrepo.config import SecureRepoConfig
from secrepo.config import save_config
from secrepo.encryption.protocols.age import generate_identity
from secrepo.encryption.protocols.age import initialize_identity
from secrepo.encryption.protocols.age import load_identity
from secrepo.encryption.protocols.age import save_identity
from secrepo.repository import FileState
from secrepo.repository import SecureRepo
from secrepo.repository import discover_repository
from secrepo.repository import hash_file
from secrepo.repository import init_repository


class FakeEncryption:
    """Fake encryption backend for testing."""

    def encrypt(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        """Copy plaintext to the encrypted destination."""
        destination.write_bytes(source.read_bytes())

    def decrypt(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        """Copy encrypted data to the plaintext destination."""
        destination.write_bytes(source.read_bytes())


class FailingEncryption:
    """Encryption backend that always fails."""

    def encrypt(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        """Fail during encryption."""
        destination.write_bytes(b"partial")
        raise RuntimeError("Encryption failed.")

    def decrypt(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        """Not implemented."""
        raise NotImplementedError


@pytest.mark.repo
def test_init(tmp_path: Path) -> None:
    """Initialize a SecureRepo in a directory."""
    repo = init_repository(tmp_path)

    assert repo.root == tmp_path
    assert repo.config.version == CONFIG_VERSION
    assert repo.config.protected == ()
    assert (tmp_path / SECREPO_DIRNAME / CONFIG_FILENAME).exists()
    assert repo.config.encryption.protocol == DEFAULT_ENCRYPTION_PROTOCOL


@pytest.mark.repo
def test_init_creates_secrepo_directory(tmp_path: Path) -> None:
    """Initialize the SecureRepo metadata directory."""
    init_repository(tmp_path)

    secrepo_dir = tmp_path / SECREPO_DIRNAME

    assert secrepo_dir.is_dir()
    assert (secrepo_dir / CONFIG_FILENAME).is_file()


@pytest.mark.repo
def test_init_rejects_existing_configuration(tmp_path: Path) -> None:
    """Reject initialization when SecureRepo already exists."""
    init_repository(tmp_path)

    with pytest.raises(FileExistsError):
        init_repository(tmp_path)


@pytest.mark.repo
def test_discover(tmp_path: Path) -> None:
    """Discover a SecureRepo from within the repository."""
    init_repository(tmp_path)

    nested = tmp_path / "notebooks" / "analysis"
    nested.mkdir(parents=True)

    repo = discover_repository(nested)

    assert repo.root == tmp_path


@pytest.mark.repo
def test_discover_fails_outside_repository(
    tmp_path: Path,
) -> None:
    """Raise FileNotFoundError when no SecureRepo exists."""
    with pytest.raises(FileNotFoundError):
        discover_repository(tmp_path)


@pytest.mark.repo
def test_hash_file(tmp_path: Path) -> None:
    """Hash the contents of a file."""
    path = tmp_path / "test.txt"
    path.write_text("hello", encoding="utf-8")

    assert (
        hash_file(path)
        == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )


@pytest.mark.repo
def test_hash_file_changes_with_contents(tmp_path: Path) -> None:
    """Produce different hashes for different file contents."""
    path = tmp_path / "test.txt"

    path.write_text("hello", encoding="utf-8")
    first_hash = hash_file(path)

    path.write_text("goodbye", encoding="utf-8")
    second_hash = hash_file(path)

    assert first_hash != second_hash


@pytest.mark.repo
def test_protected_paths(tmp_path: Path) -> None:
    """Resolve protected paths relative to the repository root."""
    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol=DEFAULT_ENCRYPTION_PROTOCOL,
        ),
        protected=(
            "data/customers.csv",
            "notebooks/analysis.ipynb",
        ),
    )

    repo = SecureRepo(
        root=tmp_path,
        config=config,
    )

    assert repo.protected_paths() == (
        tmp_path / "data/customers.csv",
        tmp_path / "notebooks/analysis.ipynb",
    )


@pytest.mark.repo
def test_encrypted_path(tmp_path: Path) -> None:
    """Derive the encrypted path from a plaintext path."""
    path = tmp_path / "data" / "customers.csv"

    assert SecureRepo.encrypted_path(path) == (tmp_path / "data" / "customers.csv.enc")


@pytest.mark.repo
def test_file_state_missing(tmp_path: Path) -> None:
    """Report MISSING when neither representation exists."""
    repo = init_repository(tmp_path)

    assert repo.file_state(Path("secret.txt")) is FileState.MISSING


@pytest.mark.repo
def test_file_state_locked(tmp_path: Path) -> None:
    """Report LOCKED when only the encrypted file exists."""
    repo = init_repository(tmp_path)

    encrypted = tmp_path / "secret.txt.enc"
    encrypted.write_bytes(b"encrypted")

    assert repo.file_state(Path("secret.txt")) is FileState.LOCKED


@pytest.mark.repo
def test_file_state_unlocked(tmp_path: Path) -> None:
    """Report UNLOCKED when the plaintext exists."""
    repo = init_repository(tmp_path)

    plaintext = tmp_path / "secret.txt"
    plaintext.write_text("secret", encoding="utf-8")

    assert repo.file_state(Path("secret.txt")) is FileState.UNLOCKED


@pytest.mark.repo
def test_file_state_unlocked_when_both_exist(tmp_path: Path) -> None:
    """Report UNLOCKED when both plaintext and encrypted files exist."""
    repo = init_repository(tmp_path)

    plaintext = tmp_path / "secret.txt"
    encrypted = tmp_path / "secret.txt.enc"

    plaintext.write_text("secret", encoding="utf-8")
    encrypted.write_bytes(b"encrypted")

    assert repo.file_state(Path("secret.txt")) is FileState.UNLOCKED


@pytest.mark.repo
def test_status(tmp_path: Path) -> None:
    """Report the state of all protected files."""
    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol=DEFAULT_ENCRYPTION_PROTOCOL,
        ),
        protected=(
            "locked.txt",
            "unlocked.txt",
            "missing.txt",
        ),
    )

    repo = SecureRepo(
        root=tmp_path,
        config=config,
    )

    (tmp_path / "locked.txt.enc").write_bytes(b"encrypted")
    (tmp_path / "unlocked.txt").write_text(
        "secret",
        encoding="utf-8",
    )

    assert repo.status() == {
        Path("locked.txt"): FileState.LOCKED,
        Path("unlocked.txt"): FileState.UNLOCKED,
        Path("missing.txt"): FileState.MISSING,
    }


@pytest.mark.repo
def test_protect(tmp_path: Path) -> None:
    """Protect an existing file."""
    repo = init_repository(tmp_path)

    path = tmp_path / "data" / "secret.csv"
    path.parent.mkdir()
    path.write_text("secret", encoding="utf-8")

    repo.protect(path)
    repo = discover_repository(tmp_path)

    assert repo.config.protected == ("data/secret.csv",)


@pytest.mark.repo
def test_protect_saves_configuration(tmp_path: Path) -> None:
    """Persist a protected path to the configuration."""
    repo = init_repository(tmp_path)

    path = tmp_path / "secret.csv"
    path.write_text("secret", encoding="utf-8")

    repo.protect(path)

    discovered = discover_repository(tmp_path)

    assert discovered.config.protected == ("secret.csv",)


@pytest.mark.repo
def test_protect_does_not_duplicate_path(tmp_path: Path) -> None:
    """Do not add a protected path more than once."""
    repo = init_repository(tmp_path)

    path = tmp_path / "secret.csv"
    path.write_text("secret", encoding="utf-8")

    repo.protect(path)
    repo.protect(path)
    repo = discover_repository(tmp_path)

    assert repo.config.protected == ("secret.csv",)


@pytest.mark.repo
def test_protect_rejects_missing_file(tmp_path: Path) -> None:
    """Reject a protected file that does not exist."""
    repo = init_repository(tmp_path)

    with pytest.raises(FileNotFoundError):
        repo.protect(tmp_path / "missing.csv")


@pytest.mark.repo
def test_protect_rejects_path_outside_repository(
    tmp_path: Path,
) -> None:
    """Reject a path outside the repository."""
    repo = init_repository(tmp_path)

    outside = tmp_path.parent / "outside.csv"
    outside.write_text("secret", encoding="utf-8")

    with pytest.raises(ValueError):
        repo.protect(outside)


@pytest.mark.repo
def test_lock_creates_encrypted_file(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Lock a protected file."""
    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol=DEFAULT_ENCRYPTION_PROTOCOL,
        ),
        protected=("secret.txt",),
    )

    repo = SecureRepo(
        root=tmp_path,
        config=config,
    )

    plaintext = tmp_path / "secret.txt"
    plaintext.write_text("secret", encoding="utf-8")

    monkeypatch.setattr(
        "secrepo.repository.create_backend",
        lambda config: FakeEncryption(),
    )

    repo.lock(plaintext)

    encrypted = tmp_path / "secret.txt.enc"

    assert encrypted.exists()
    assert plaintext.exists()
    assert plaintext.read_text(encoding="utf-8") == "secret"


@pytest.mark.repo
def test_lock_rejects_unprotected_file(tmp_path: Path) -> None:
    """Do not lock an unprotected file."""
    repo = init_repository(tmp_path)

    plaintext = tmp_path / "secret.txt"
    plaintext.write_text("secret", encoding="utf-8")

    with pytest.raises(ValueError, match="not protected"):
        repo.lock(plaintext)


@pytest.mark.repo
def test_lock_rejects_missing_file(tmp_path: Path) -> None:
    """Do not lock a file that does not exist."""
    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol=DEFAULT_ENCRYPTION_PROTOCOL,
        ),
        protected=("secret.txt",),
    )

    repo = SecureRepo(
        root=tmp_path,
        config=config,
    )

    with pytest.raises(FileNotFoundError):
        repo.lock(tmp_path / "secret.txt")


@pytest.mark.repo
def test_lock_preserves_plaintext_when_encryption_fails(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Preserve plaintext if encryption fails."""
    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol=DEFAULT_ENCRYPTION_PROTOCOL,
        ),
        protected=("secret.txt",),
    )

    repo = SecureRepo(
        root=tmp_path,
        config=config,
    )

    plaintext = tmp_path / "secret.txt"
    plaintext.write_text("secret", encoding="utf-8")

    monkeypatch.setattr(
        "secrepo.repository.create_backend",
        lambda config: FailingEncryption(),
    )

    with pytest.raises(RuntimeError, match="Encryption failed"):
        repo.lock(plaintext)

    assert plaintext.exists()
    assert plaintext.read_text(encoding="utf-8") == "secret"
    assert not (tmp_path / "secret.txt.enc").exists()
    assert not (tmp_path / "secret.txt.enc.tmp").exists()


@pytest.mark.repo
def test_lock_preserves_existing_encrypted_file_on_failure(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Preserve the existing encrypted file if locking fails."""
    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol=DEFAULT_ENCRYPTION_PROTOCOL,
        ),
        protected=("secret.txt",),
    )

    repo = SecureRepo(
        root=tmp_path,
        config=config,
    )

    plaintext = tmp_path / "secret.txt"
    encrypted = tmp_path / "secret.txt.enc"

    plaintext.write_text("new secret", encoding="utf-8")
    encrypted.write_bytes(b"old encrypted data")

    monkeypatch.setattr(
        "secrepo.repository.create_backend",
        lambda config: FailingEncryption(),
    )

    with pytest.raises(RuntimeError, match="Encryption failed"):
        repo.lock(plaintext)

    assert encrypted.read_bytes() == b"old encrypted data"
    assert plaintext.read_text(encoding="utf-8") == "new secret"


@pytest.mark.repo
def test_init_with_encryption_protocol(tmp_path: Path) -> None:
    """Initialize a SecureRepo with a specified encryption protocol."""
    repo = init_repository(
        tmp_path,
        encryption_protocol="age",
    )

    assert repo.config.encryption.protocol == "age"


@pytest.mark.repo
def test_lock_with_configured_age_backend(
    tmp_path: Path,
) -> None:
    """Test locking a protected file with a configured age backend."""
    repo = init_repository(tmp_path)

    identity = generate_identity()
    identity_path = tmp_path / "identity"
    save_identity(identity, identity_path)

    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol="age",
            options={
                "recipients": (str(identity.to_public()),),
                "identity": identity_path,
            },
        ),
        protected=(),
    )

    save_config(
        config,
        tmp_path / SECREPO_DIRNAME / CONFIG_FILENAME,
    )

    secret_path = tmp_path / "secret.txt"
    original_content = "This is sensitive data.\n"
    secret_path.write_text(original_content, encoding="utf-8")

    repo = discover_repository(tmp_path)
    repo.protect(secret_path)
    repo = discover_repository(tmp_path)

    repo.lock(secret_path)

    encrypted_path = repo.encrypted_path(secret_path)

    assert secret_path.is_file()
    assert secret_path.read_text(encoding="utf-8") == original_content
    assert encrypted_path.is_file()
    assert encrypted_path.read_bytes() != original_content.encode("utf-8")

    decrypted_path = tmp_path / "decrypted.txt"

    repo.encryption_backend.decrypt(
        encrypted_path,
        decrypted_path,
    )

    assert decrypted_path.read_text(encoding="utf-8") == original_content


@pytest.mark.repo
def test_unlock_with_configured_age_backend(
    tmp_path: Path,
) -> None:
    """Test unlocking a protected file with a configured age backend."""
    repo = init_repository(tmp_path)

    identity = generate_identity()
    identity_path = tmp_path / "identity"
    save_identity(identity, identity_path)

    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol="age",
            options={
                "recipients": (str(identity.to_public()),),
                "identity": identity_path,
            },
        ),
        protected=(),
    )

    save_config(
        config,
        tmp_path / SECREPO_DIRNAME / CONFIG_FILENAME,
    )

    secret_path = tmp_path / "secret.txt"
    original_content = "This is sensitive data.\n"
    secret_path.write_text(original_content, encoding="utf-8")

    repo = discover_repository(tmp_path)
    repo.protect(secret_path)
    repo = discover_repository(tmp_path)

    repo.lock(secret_path)

    secret_path.unlink()

    repo = discover_repository(tmp_path)
    repo.unlock(secret_path)

    assert secret_path.is_file()
    assert secret_path.read_text(encoding="utf-8") == original_content
    assert repo.encrypted_path(secret_path).is_file()


def test_initialize_encryption(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Initialize age encryption and save the configuration."""
    repo = init_repository(tmp_path)

    identity_path = tmp_path / "identity"
    monkeypatch.setattr(
        "secrepo.repository.default_identity_path",
        lambda: identity_path,
    )

    repo.initialize_encryption()

    assert identity_path.is_file()

    config = discover_repository(tmp_path).config

    assert config.encryption.protocol == "age"
    assert config.encryption.options["recipients"] == [
        str(load_identity(identity_path).to_public())
    ]
    assert config.encryption.options["identity"] == str(identity_path)


def test_initialize_encryption_does_not_overwrite_identity(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Refuse to overwrite an existing age identity."""
    repo = init_repository(tmp_path)

    identity_path = tmp_path / "identity"
    monkeypatch.setattr(
        "secrepo.repository.default_identity_path",
        lambda: identity_path,
    )

    initialize_identity(identity_path)
    original_identity = identity_path.read_text(encoding="utf-8")

    with pytest.raises(FileExistsError):
        repo.initialize_encryption()

    assert identity_path.read_text(encoding="utf-8") == original_identity


def test_initialize_encryption_preserves_protected_paths(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Preserve existing protected paths when configuring encryption."""
    repo = init_repository(tmp_path)

    secret_path = tmp_path / "secret.txt"
    secret_path.write_text("secret", encoding="utf-8")
    repo.protect(secret_path)

    identity_path = tmp_path / "identity"
    monkeypatch.setattr(
        "secrepo.repository.default_identity_path",
        lambda: identity_path,
    )

    repo = discover_repository(tmp_path)
    repo.initialize_encryption()

    config = discover_repository(tmp_path).config

    assert config.protected == ("secret.txt",)
    assert config.encryption.protocol == "age"
