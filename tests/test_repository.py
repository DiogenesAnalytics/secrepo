"""Tests for SecureRepo repository management."""

from pathlib import Path

import pytest

from secrepo.config import CONFIG_FILENAME
from secrepo.config import CONFIG_VERSION
from secrepo.repository import discover_repository
from secrepo.repository import init_repository


def test_init(tmp_path: Path) -> None:
    """Initialize a SecureRepo in a directory."""
    repo = init_repository(tmp_path)

    assert repo.root == tmp_path
    assert repo.config.version == CONFIG_VERSION
    assert repo.config.protected == ()
    assert (tmp_path / CONFIG_FILENAME).exists()


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
