"""Encryption interfaces for SecureRepo."""

from pathlib import Path
from typing import Protocol


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
