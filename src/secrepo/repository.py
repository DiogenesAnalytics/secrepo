"""Git repository management for SecureRepo."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import CONFIG_FILENAME
from .config import CONFIG_VERSION
from .config import SecureRepoConfig
from .config import load_config
from .config import save_config


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
