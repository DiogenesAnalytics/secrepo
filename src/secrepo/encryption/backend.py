"""Encryption interfaces and backend management for SecureRepo."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Dict
from typing import Protocol
from typing import Tuple
from typing import Type

from ..config import EncryptionConfig


class BackendConfigurationError(ValueError):
    """Raised when an encryption backend is improperly configured."""


@dataclass(frozen=True)
class BackendOption:
    """Describe an encryption backend configuration option.

    Parameters
    ----------
    name:
        Configuration option name.
    type:
        Configuration option type.
    required:
        Whether the option is required.
    multiple:
        Whether multiple values may be supplied.
    help:
        Description of the option for the user.
    """

    name: str
    type: str
    required: bool = True
    multiple: bool = False
    help: str = ""


class EncryptionBackend(Protocol):
    """Interface for a SecureRepo encryption backend.

    Attributes
    ----------
    config_options:
        Configuration options supported by the backend.
    """

    config_options: Tuple[BackendOption, ...]

    @classmethod
    def validate_options(
        cls,
        **options: Any,
    ) -> None:
        """Validate encryption backend configuration options."""
        ...

    def encrypt(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        """Encrypt a file."""
        ...

    def decrypt(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        """Decrypt a file."""
        ...


BACKENDS: Dict[str, Type[EncryptionBackend]] = {}


def register_backends(
    backends: Dict[str, Type[EncryptionBackend]],
) -> None:
    """Register encryption backends."""
    BACKENDS.update(backends)


def create_backend(
    config: EncryptionConfig,
) -> EncryptionBackend:
    """Create an encryption backend from its configuration."""
    backend = BACKENDS.get(config.protocol)

    if backend is None:
        raise ValueError(f"Unsupported encryption protocol: {config.protocol}.")

    backend.validate_options(**config.options)

    return backend(**config.options)
