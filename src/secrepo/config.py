"""Configuration management for SecureRepo projects."""

from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

import yaml

SECREPO_DIRNAME = ".secrepo"
CONFIG_FILENAME = "protected.yaml"
CONFIG_VERSION = 1

DEFAULT_ENCRYPTION_PROTOCOL = "age"
SUPPORTED_ENCRYPTION_PROTOCOLS = ("age",)


@dataclass(frozen=True)
class EncryptionConfig:
    """Encryption configuration for a SecureRepo repository.

    Parameters
    ----------
    protocol:
        Encryption protocol used for protected files.
    """

    protocol: str


@dataclass(frozen=True)
class SecureRepoConfig:
    """Configuration for a SecureRepo repository.

    Parameters
    ----------
    version:
        Configuration file format version.
    encryption:
        Encryption configuration.
    protected:
        Paths or glob patterns identifying protected files.
    """

    version: int
    encryption: EncryptionConfig
    protected: Tuple[str, ...]


def validate_encryption_protocol(protocol: str) -> None:
    """Validate an encryption protocol.

    Parameters
    ----------
    protocol:
        Encryption protocol name.

    Raises
    ------
    ValueError
        If the encryption protocol is not supported.
    """
    if protocol not in SUPPORTED_ENCRYPTION_PROTOCOLS:
        raise ValueError(f"Unsupported encryption protocol: {protocol}.")


def load_config(path: Path) -> SecureRepoConfig:
    """Load a SecureRepo configuration from a YAML file.

    Parameters
    ----------
    path:
        Path to the SecureRepo configuration file.

    Returns
    -------
    SecureRepoConfig
        Parsed configuration.

    Raises
    ------
    FileNotFoundError
        If the configuration file does not exist.
    ValueError
        If the configuration is invalid.
    """
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise ValueError("SecureRepo configuration must be a mapping.")

    version = data.get("version")
    encryption = data.get("encryption", {})
    protected = data.get("protected", [])

    if not isinstance(version, int):
        raise ValueError("'version' must be an integer.")

    if version != CONFIG_VERSION:
        raise ValueError(f"Unsupported configuration version: {version}.")

    if not isinstance(encryption, dict):
        raise ValueError("'encryption' must be a mapping.")

    protocol = encryption.get(
        "protocol",
        DEFAULT_ENCRYPTION_PROTOCOL,
    )

    if not isinstance(protocol, str):
        raise ValueError("'encryption.protocol' must be a string.")

    validate_encryption_protocol(protocol)

    if not isinstance(protected, list):
        raise ValueError("'protected' must be a list.")

    if not all(isinstance(path, str) for path in protected):
        raise ValueError("All protected paths must be strings.")

    return SecureRepoConfig(
        version=version,
        encryption=EncryptionConfig(
            protocol=protocol,
        ),
        protected=tuple(protected),
    )


def save_config(config: SecureRepoConfig, path: Path) -> None:
    """Save a SecureRepo configuration to a YAML file.

    Parameters
    ----------
    config:
        Configuration to save.

    path:
        Destination path for the ``secrepo.yaml`` file.
    """
    data = {
        "version": config.version,
        "encryption": {
            "protocol": config.encryption.protocol,
        },
        "protected": list(config.protected),
    }

    with path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(
            data,
            file,
            sort_keys=False,
        )


def add_protected(
    config: SecureRepoConfig,
    path: str,
) -> SecureRepoConfig:
    """Return a configuration with a protected path added.

    Parameters
    ----------
    config:
        Existing SecureRepo configuration.
    path:
        Repository-relative path to protect.

    Returns
    -------
    SecureRepoConfig
        Configuration containing the protected path.
    """
    if path in config.protected:
        return config

    return SecureRepoConfig(
        version=config.version,
        encryption=config.encryption,
        protected=(*config.protected, path),
    )
