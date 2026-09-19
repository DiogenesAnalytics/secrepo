"""Git repository management for SecureRepo."""

import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from .config import CONFIG_FILENAME
from .config import CONFIG_VERSION
from .config import DEFAULT_ENCRYPTION_PROTOCOL
from .config import SECREPO_DIRNAME
from .config import EncryptionConfig
from .config import SecureRepoConfig
from .config import add_protected
from .config import load_config
from .config import save_config
from .config import update_encryption_options
from .config import validate_encryption_protocol
from .encryption import EncryptionBackend
from .encryption import create_backend
from .encryption.protocols.age import default_identity_path
from .encryption.protocols.age import initialize_identity


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

    @property
    def encryption_backend(self) -> EncryptionBackend:
        """Return the encryption backend configured for this repository."""
        return create_backend(self.config.encryption)

    def initialize_encryption(self) -> None:
        """Initialize encryption for the repository.

        Raises
        ------
        FileExistsError
            If the age identity already exists.
        """
        identity_path = default_identity_path()
        identity = initialize_identity(identity_path)

        config = update_encryption_options(
            self.config,
            {
                "recipients": [str(identity.to_public())],
                "identity": identity_path,
            },
        )

        save_config(
            config,
            self.root / SECREPO_DIRNAME / CONFIG_FILENAME,
        )

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

    def protect(self, path: Path) -> None:
        """Protect a file in the repository.

        Parameters
        ----------
        path:
            Path to the file, relative to the repository root.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        ValueError
            If the path is outside the repository.
        """
        path = path.resolve()

        try:
            relative_path = path.relative_to(self.root)
        except ValueError as error:
            raise ValueError(f"Path is outside the repository: {path}") from error

        if not path.is_file():
            raise FileNotFoundError(f"File does not exist: {path}")

        config = add_protected(
            self.config,
            relative_path.as_posix(),
        )

        save_config(
            config,
            self.root / SECREPO_DIRNAME / CONFIG_FILENAME,
        )

    def lock(
        self,
        path: Path,
    ) -> None:
        """Encrypt a protected file.

        The plaintext file is never removed.

        Parameters
        ----------
        path:
            Path to the protected plaintext file.

        Raises
        ------
        FileNotFoundError
            If the plaintext file does not exist.
        ValueError
            If the file is not protected or is outside the repository.
        """
        path = path.resolve()

        try:
            relative_path = path.relative_to(self.root)
        except ValueError as error:
            raise ValueError(f"Path is outside the repository: {path}") from error

        relative_path_string = relative_path.as_posix()

        if relative_path_string not in self.config.protected:
            raise ValueError(f"File is not protected: {relative_path_string}")

        if not path.is_file():
            raise FileNotFoundError(f"File does not exist: {path}")

        encrypted_path = self.encrypted_path(path)
        temporary_path = encrypted_path.with_suffix(encrypted_path.suffix + ".tmp")

        try:
            self.encryption_backend.encrypt(
                path,
                temporary_path,
            )

            if not temporary_path.is_file():
                raise RuntimeError("Encryption backend did not create an output file.")

            temporary_path.replace(encrypted_path)

        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise

    def unlock(
        self,
        path: Path,
    ) -> None:
        """Decrypt a protected file.

        The encrypted file is never removed.

        Parameters
        ----------
        path:
            Path to the protected plaintext file.

        Raises
        ------
        FileNotFoundError
            If the encrypted file does not exist.
        ValueError
            If the file is not protected or is outside the repository.
        """
        path = path.resolve()

        try:
            relative_path = path.relative_to(self.root)
        except ValueError as error:
            raise ValueError(f"Path is outside the repository: {path}") from error

        relative_path_string = relative_path.as_posix()

        if relative_path_string not in self.config.protected:
            raise ValueError(f"File is not protected: {relative_path_string}")

        encrypted_path = self.encrypted_path(path)

        if not encrypted_path.is_file():
            raise FileNotFoundError(f"Encrypted file does not exist: {encrypted_path}")

        temporary_path = path.with_suffix(path.suffix + ".tmp")

        try:
            self.encryption_backend.decrypt(
                encrypted_path,
                temporary_path,
            )

            if not temporary_path.is_file():
                raise RuntimeError("Decryption backend did not create an output file.")

            temporary_path.replace(path)

        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise


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
        config_path = directory / SECREPO_DIRNAME / CONFIG_FILENAME

        if config_path.exists():
            return SecureRepo(
                root=directory,
                config=load_config(config_path),
            )

    raise FileNotFoundError(
        f"Could not find {SECREPO_DIRNAME}/{CONFIG_FILENAME} "
        f"in {current} or any parent directory."
    )


def init_repository(
    path: Optional[Path] = None,
    encryption_protocol: str = DEFAULT_ENCRYPTION_PROTOCOL,
) -> SecureRepo:
    """Initialize a SecureRepo in a directory.

    Parameters
    ----------
    path:
        Directory in which to initialize the repository. If omitted,
        the current working directory is used.
    encryption_protocol:
        Encryption protocol to use for protected files. If omitted,
        the default encryption protocol is used.

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
    secrepo_dir = root / SECREPO_DIRNAME
    config_path = secrepo_dir / CONFIG_FILENAME

    if config_path.exists():
        raise FileExistsError(
            f"{SECREPO_DIRNAME}/{CONFIG_FILENAME} already exists in {root}."
        )

    validate_encryption_protocol(encryption_protocol)

    secrepo_dir.mkdir(exist_ok=True)

    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol=encryption_protocol,
        ),
        protected=(),
    )

    save_config(config, config_path)

    return SecureRepo(
        root=root,
        config=config,
    )
