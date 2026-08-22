"""Tests for SecureRepo repository management."""

from pathlib import Path

import pytest

from secrepo.config import CONFIG_FILENAME
from secrepo.config import CONFIG_VERSION
from secrepo.config import SECREPO_DIRNAME
from secrepo.config import SecureRepoConfig
from secrepo.repository import FileState
from secrepo.repository import SecureRepo
from secrepo.repository import discover_repository
from secrepo.repository import hash_file
from secrepo.repository import init_repository


def test_init(tmp_path: Path) -> None:
    """Initialize a SecureRepo in a directory."""
    repo = init_repository(tmp_path)

    assert repo.root == tmp_path
    assert repo.config.version == CONFIG_VERSION
    assert repo.config.protected == ()
    assert (tmp_path / SECREPO_DIRNAME / CONFIG_FILENAME).exists()


def test_init_creates_secrepo_directory(tmp_path: Path) -> None:
    """Initialize the SecureRepo metadata directory."""
    init_repository(tmp_path)

    secrepo_dir = tmp_path / SECREPO_DIRNAME

    assert secrepo_dir.is_dir()
    assert (secrepo_dir / CONFIG_FILENAME).is_file()


def test_init_rejects_existing_configuration(tmp_path: Path) -> None:
    """Reject initialization when SecureRepo already exists."""
    init_repository(tmp_path)

    with pytest.raises(FileExistsError):
        init_repository(tmp_path)


def test_discover(tmp_path: Path) -> None:
    """Discover a SecureRepo from within the repository."""
    init_repository(tmp_path)

    nested = tmp_path / "notebooks" / "analysis"
    nested.mkdir(parents=True)

    repo = discover_repository(nested)

    assert repo.root == tmp_path


def test_discover_fails_outside_repository(
    tmp_path: Path,
) -> None:
    """Raise FileNotFoundError when no SecureRepo exists."""
    with pytest.raises(FileNotFoundError):
        discover_repository(tmp_path)


def test_hash_file(tmp_path: Path) -> None:
    """Hash the contents of a file."""
    path = tmp_path / "test.txt"
    path.write_text("hello", encoding="utf-8")

    assert (
        hash_file(path)
        == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )


def test_hash_file_changes_with_contents(tmp_path: Path) -> None:
    """Produce different hashes for different file contents."""
    path = tmp_path / "test.txt"

    path.write_text("hello", encoding="utf-8")
    first_hash = hash_file(path)

    path.write_text("goodbye", encoding="utf-8")
    second_hash = hash_file(path)

    assert first_hash != second_hash


def test_protected_paths(tmp_path: Path) -> None:
    """Resolve protected paths relative to the repository root."""
    config = SecureRepoConfig(
        version=CONFIG_VERSION,
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


def test_encrypted_path(tmp_path: Path) -> None:
    """Derive the encrypted path from a plaintext path."""
    path = tmp_path / "data" / "customers.csv"

    assert SecureRepo.encrypted_path(path) == (tmp_path / "data" / "customers.csv.enc")


def test_file_state_missing(tmp_path: Path) -> None:
    """Report MISSING when neither representation exists."""
    repo = init_repository(tmp_path)

    assert repo.file_state(Path("secret.txt")) is FileState.MISSING


def test_file_state_locked(tmp_path: Path) -> None:
    """Report LOCKED when only the encrypted file exists."""
    repo = init_repository(tmp_path)

    encrypted = tmp_path / "secret.txt.enc"
    encrypted.write_bytes(b"encrypted")

    assert repo.file_state(Path("secret.txt")) is FileState.LOCKED


def test_file_state_unlocked(tmp_path: Path) -> None:
    """Report UNLOCKED when the plaintext exists."""
    repo = init_repository(tmp_path)

    plaintext = tmp_path / "secret.txt"
    plaintext.write_text("secret", encoding="utf-8")

    assert repo.file_state(Path("secret.txt")) is FileState.UNLOCKED


def test_file_state_unlocked_when_both_exist(tmp_path: Path) -> None:
    """Report UNLOCKED when both plaintext and encrypted files exist."""
    repo = init_repository(tmp_path)

    plaintext = tmp_path / "secret.txt"
    encrypted = tmp_path / "secret.txt.enc"

    plaintext.write_text("secret", encoding="utf-8")
    encrypted.write_bytes(b"encrypted")

    assert repo.file_state(Path("secret.txt")) is FileState.UNLOCKED


def test_status(tmp_path: Path) -> None:
    """Report the state of all protected files."""
    config = SecureRepoConfig(
        version=CONFIG_VERSION,
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
