"""Age encryption protocol implementation."""

import os
from pathlib import Path
from typing import Any
from typing import Iterable
from typing import Optional

from pyrage import RecipientError
from pyrage import decrypt
from pyrage import encrypt
from pyrage.x25519 import Identity
from pyrage.x25519 import Recipient

from ..backend import BackendConfigurationError
from ..backend import BackendOption
from ..backend import EncryptionBackend

IDENTITY_FILENAME = "identity"
SECREPO_DATA_DIRNAME = "secrepo"
AGE_DATA_DIRNAME = "age"


def default_identity_path() -> Path:
    """Return the default path for the user's age identity.

    Returns
    -------
    Path
        Default path for the user's age identity.
    """
    data_home = os.environ.get("XDG_DATA_HOME")

    if data_home:
        data_dir = Path(data_home)
    else:
        data_dir = Path.home() / ".local" / "share"

    return data_dir / SECREPO_DATA_DIRNAME / AGE_DATA_DIRNAME / IDENTITY_FILENAME


def resolve_identity_path(path: Optional[Path] = None) -> Path:
    """Resolve an explicit or default age identity path.

    Parameters
    ----------
    path:
        Explicit path to the age identity, or None to use the default.

    Returns
    -------
    Path
        Resolved path to the age identity.
    """
    if path is not None:
        return path

    return default_identity_path()


def generate_identity() -> Identity:
    """Generate a new age X25519 identity.

    Returns
    -------
    Identity
        Newly generated age X25519 identity.
    """
    return Identity.generate()


def save_identity(
    identity: Identity,
    path: Path,
) -> None:
    """Save an age identity to a file.

    Parameters
    ----------
    identity:
        Age identity to save.
    path:
        Path where the identity will be saved.

    Raises
    ------
    OSError
        If the identity cannot be written to the specified path.
    """
    path.write_text(
        str(identity),
        encoding="utf-8",
    )


def initialize_identity(
    path: Path,
) -> Identity:
    """Generate and save an age identity.

    Parameters
    ----------
    path:
        Path where the identity will be saved.

    Returns
    -------
    Identity
        The newly generated age identity.

    Raises
    ------
    FileExistsError
        If the identity already exists.
    """
    if path.exists():
        raise FileExistsError(f"Age identity already exists: {path}")

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    identity = generate_identity()
    save_identity(identity, path)

    return identity


def load_identity(path: Path) -> Identity:
    """Load an age identity from a file.

    Parameters
    ----------
    path:
        Path to the age identity file.

    Returns
    -------
    Identity
        Loaded age identity.

    Raises
    ------
    OSError
        If the identity cannot be read from the specified path.
    ValueError
        If the identity contents are invalid.
    """
    return Identity.from_str(
        path.read_text(encoding="utf-8").strip(),
    )


class AgeEncryptionBackend(EncryptionBackend):
    """Encryption backend using the age encryption protocol.

    Parameters
    ----------
    recipients:
        Age recipients that can decrypt encrypted files.
    identity:
        Path to the age identity used to decrypt encrypted files.
    """

    config_options = (
        BackendOption(
            name="recipients",
            type="string",
            multiple=True,
            help="Age recipient(s) used for encryption.",
        ),
        BackendOption(
            name="identity",
            type="path",
            help="Path to the age identity file.",
        ),
    )

    def __init__(
        self,
        recipients: Iterable[str],
        identity: Path,
    ) -> None:
        """Initialize an age encryption backend.

        Parameters
        ----------
        recipients:
            Age recipients that can decrypt encrypted files.
        identity:
            Path to the age identity used to decrypt encrypted files.

        Raises
        ------
        BackendConfigurationError
            If the encryption options are invalid.
        """
        self.validate_options(
            recipients=recipients,
            identity=identity,
        )

        identity = self._resolve_identity(identity)

        self._recipients = tuple(
            Recipient.from_str(recipient) for recipient in recipients
        )
        self._identities = (load_identity(identity),)

    @classmethod
    def validate_options(
        cls,
        **options: Any,
    ) -> None:
        """Validate age encryption options.

        Parameters
        ----------
        options:
            Encryption options to validate.

        Raises
        ------
        BackendConfigurationError
            If the encryption options are invalid.
        """
        cls._validate_recipients(options.get("recipients"))
        cls._validate_identity(options.get("identity"))

    @staticmethod
    def _resolve_identity(
        identity: Any,
    ) -> Path:
        """Resolve the age identity path.

        Parameters
        ----------
        identity:
            Identity path to resolve.

        Returns
        -------
        Path
            Resolved identity path.

        Raises
        ------
        BackendConfigurationError
            If the identity is not a path or string.
        """
        if isinstance(identity, str):
            identity = Path(identity)

        if not isinstance(identity, Path):
            raise BackendConfigurationError("'identity' must be a path.")

        return identity

    @staticmethod
    def _validate_recipients(
        recipients: Any,
    ) -> None:
        """Validate age recipients.

        Parameters
        ----------
        recipients:
            Age recipients to validate.

        Raises
        ------
        BackendConfigurationError
            If the recipients are missing, incorrectly typed, or invalid.
        """
        if recipients is None:
            raise BackendConfigurationError(
                "Age encryption is not configured: recipients are missing."
            )

        if not isinstance(recipients, (list, tuple)):
            raise BackendConfigurationError("'recipients' must be a list.")

        if not recipients:
            raise BackendConfigurationError(
                "Age encryption is not configured: recipients are missing."
            )

        if not all(isinstance(recipient, str) for recipient in recipients):
            raise BackendConfigurationError("All recipients must be strings.")

        for recipient in recipients:
            try:
                Recipient.from_str(recipient)
            except RecipientError as error:
                raise BackendConfigurationError(
                    f"Invalid age recipient: {recipient}."
                ) from error

    @classmethod
    def _validate_identity(
        cls,
        identity: Any,
    ) -> None:
        """Validate the age identity.

        Parameters
        ----------
        identity:
            Age identity path to validate.

        Raises
        ------
        BackendConfigurationError
            If the identity is missing, does not exist, or is invalid.
        """
        if identity is None:
            raise BackendConfigurationError(
                "Age encryption is not configured: identity is missing."
            )

        identity = cls._resolve_identity(identity)

        if not identity.is_file():
            raise BackendConfigurationError(f"Age identity does not exist: {identity}")

        try:
            load_identity(identity)
        except ValueError as error:
            raise BackendConfigurationError(
                f"Invalid age identity: {identity}"
            ) from error

    def encrypt(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        """Encrypt a file using age.

        Parameters
        ----------
        source:
            Path to the plaintext file.
        destination:
            Path where the encrypted file will be written.

        Raises
        ------
        OSError
            If the source cannot be read or the destination cannot be written.
        """
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
        """Decrypt an age-encrypted file.

        Parameters
        ----------
        source:
            Path to the encrypted file.
        destination:
            Path where the decrypted file will be written.

        Raises
        ------
        OSError
            If the source cannot be read or the destination cannot be written.
        ValueError
            If the encrypted data cannot be decrypted with the configured identity.
        """
        decrypted = decrypt(
            source.read_bytes(),
            self._identities,
        )
        destination.write_bytes(decrypted)
