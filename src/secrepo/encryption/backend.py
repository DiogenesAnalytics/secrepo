"""Encryption interfaces and backend management for SecureRepo."""

from pathlib import Path
from typing import Dict
from typing import Protocol
from typing import Type

from ..config import EncryptionConfig


class EncryptionBackend(Protocol):
    """Interface for a SecureRepo encryption backend."""

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

    return backend(**config.options)
