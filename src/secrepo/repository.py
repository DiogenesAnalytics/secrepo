"""Git repository management for SecureRepo."""

import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from .config import CONFIG_FILENAME
from .config import CONFIG_VERSION
from .config import SecureRepoConfig
from .config import load_config
from .config import save_config


class FileState(Enum):
    """Current state of a protected file."""

    LOCKED = "locked"
    UNLOCKED = "unlocked"
    MISSING = "missing"


@dataclass(frozen=True)
class SecureRepo:
    """A Git repository managed by SecureRepo.

    Parameters
    ----------
    root:
        Root directory of the repository.
    config:
        SecureRepo configuration associated with the repository.
    """

    root: Path
    config: SecureRepoConfig

    def protected_paths(self) -> tuple[Path, ...]:
        """Return protected paths relative to the repository root."""
        return tuple(self.root / path for path in self.config.protected)

    @staticmethod
    def encrypted_path(path: Path) -> Path:
        """Return the encrypted path corresponding to a plaintext path."""
        return path.with_name(f"{path.name}.enc")

    def file_state(self, path: Path) -> FileState:
        """Determine the current state of a protected file.

        Parameters
        ----------
        path:
            Path to the protected file, relative to the repository root.

        Returns
        -------
        FileState
            Current state of the protected file.
        """
        plaintext = self.root / path
        encrypted = self.encrypted_path(plaintext)

        plaintext_exists = plaintext.exists()
        encrypted_exists = encrypted.exists()

        if not plaintext_exists and not encrypted_exists:
            return FileState.MISSING

        if not plaintext_exists:
            return FileState.LOCKED

        return FileState.UNLOCKED

    def status(self) -> dict[Path, FileState]:
        """Return the current state of all protected files."""
        return {
            Path(path): self.file_state(Path(path)) for path in self.config.protected
        }


def hash_file(path: Path) -> str:
    """Return the SHA-256 hash of a file.

    Parameters
    ----------
    path:
        Path to the file to hash.

    Returns
    -------
    str
        Hexadecimal SHA-256 digest.
    """
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)

    return digest.hexdigest()


def discover_repository(path: Optional[Path] = None) -> SecureRepo:
    """Discover a SecureRepo from a directory.

    Parameters
    ----------
    path:
        Directory from which to begin searching. If omitted, the
        current working directory is used.

    Returns
    -------
    SecureRepo
        The discovered repository.

    Raises
    ------
    FileNotFoundError
        If no SecureRepo configuration can be found.
    """
    current = (path or Path.cwd()).resolve()

    for directory in (current, *current.parents):
        config_path = directory / CONFIG_FILENAME

        if config_path.exists():
            return SecureRepo(
                root=directory,
                config=load_config(config_path),
            )

    raise FileNotFoundError(
        f"Could not find {CONFIG_FILENAME} in {current} " "or any parent directory."
    )


def init_repository(path: Optional[Path] = None) -> SecureRepo:
    """Initialize a SecureRepo in a directory.

    Parameters
    ----------
    path:
        Directory in which to initialize the repository. If omitted,
        the current working directory is used.

    Returns
    -------
    SecureRepo
        The initialized repository.

    Raises
    ------
    FileExistsError
        If a SecureRepo configuration already exists.
    """
    root = (path or Path.cwd()).resolve()
    config_path = root / CONFIG_FILENAME

    if config_path.exists():
        raise FileExistsError(f"{CONFIG_FILENAME} already exists in {root}.")

    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        protected=(),
    )

    save_config(config, config_path)

    return SecureRepo(
        root=root,
        config=config,
    )
