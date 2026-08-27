"""Age encryption protocol implementation."""

import os
from pathlib import Path
from typing import Iterable
from typing import Optional

from pyrage import decrypt
from pyrage import encrypt
from pyrage.x25519 import Identity
from pyrage.x25519 import Recipient

from ..backend import EncryptionBackend

IDENTITY_FILENAME = "identity"
SECREPO_DATA_DIRNAME = "secrepo"
AGE_DATA_DIRNAME = "age"


def default_identity_path() -> Path:
    """Return the default path for the user's age identity."""
    data_home = os.environ.get("XDG_DATA_HOME")

    if data_home:
        data_dir = Path(data_home)
    else:
        data_dir = Path.home() / ".local" / "share"

    return data_dir / SECREPO_DATA_DIRNAME / AGE_DATA_DIRNAME / IDENTITY_FILENAME


def resolve_identity_path(path: Optional[Path] = None) -> Path:
    """Resolve an explicit or default age identity path."""
    if path is not None:
        return path

    return default_identity_path()


def generate_identity() -> Identity:
    """Generate a new age X25519 identity."""
    return Identity.generate()


def save_identity(
    identity: Identity,
    path: Path,
) -> None:
    """Save an age identity to a file."""
    path.write_text(
        str(identity),
        encoding="utf-8",
    )


def load_identity(path: Path) -> Identity:
    """Load an age identity from a file."""
    return Identity.from_str(
        path.read_text(encoding="utf-8").strip(),
    )


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
