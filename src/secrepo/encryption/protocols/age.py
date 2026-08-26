"""Age encryption protocol implementation."""

from pathlib import Path
from typing import Iterable

from pyrage import decrypt
from pyrage import encrypt
from pyrage.x25519 import Identity
from pyrage.x25519 import Recipient

from ..backend import EncryptionBackend


class AgeEncryptionBackend(EncryptionBackend):
    """Encryption backend using the age encryption protocol.

    Parameters
    ----------
    recipients:
        Age recipients that can decrypt encrypted files.
    identities:
        Age identities used to decrypt encrypted files.
    """

    def __init__(
        self,
        recipients: Iterable[Recipient],
        identities: Iterable[Identity],
    ) -> None:
        """Initialize an age encryption backend."""
        self._recipients = tuple(recipients)
        self._identities = tuple(identities)

    def encrypt(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        """Encrypt a file using age."""
        encrypted = encrypt(
            source.read_bytes(),
            self._recipients,
        )
        destination.write_bytes(encrypted)

    def decrypt(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        """Decrypt an age-encrypted file."""
        decrypted = decrypt(
            source.read_bytes(),
            self._identities,
        )
        destination.write_bytes(decrypted)
