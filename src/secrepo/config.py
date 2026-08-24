"""Configuration management for SecureRepo projects."""

from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

import yaml

SECREPO_DIRNAME = ".secrepo"
CONFIG_FILENAME = "protected.yaml"
CONFIG_VERSION = 1


@dataclass(frozen=True)
class SecureRepoConfig:
    """Configuration for a SecureRepo repository.

    Parameters
    ----------
    version:
        Configuration file format version.
    protected:
        Paths or glob patterns identifying protected files.
    """

    version: int
    protected: Tuple[str, ...]


def load_config(path: Path) -> SecureRepoConfig:
    """Load a SecureRepo configuration from a YAML file.

    Parameters
    ----------
    path:
        Path to the ``secrepo.yaml`` configuration file.

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
    protected = data.get("protected", [])

    if not isinstance(version, int):
        raise ValueError("'version' must be an integer.")

    if version != CONFIG_VERSION:
        raise ValueError(f"Unsupported configuration version: {version}.")

    if not isinstance(protected, list):
        raise ValueError("'protected' must be a list.")

    if not all(isinstance(path, str) for path in protected):
        raise ValueError("All protected paths must be strings.")

    return SecureRepoConfig(
        version=version,
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
        protected=(*config.protected, path),
    )
