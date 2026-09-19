"""Command-line interface for SecureRepo."""

from pathlib import Path
from typing import Any
from typing import List
from typing import Optional

import click

from .config import CONFIG_FILENAME
from .config import DEFAULT_ENCRYPTION_PROTOCOL
from .config import SECREPO_DIRNAME
from .config import save_config
from .config import update_encryption_options
from .encryption.backend import BACKENDS
from .encryption.backend import BackendConfigurationError
from .repository import discover_repository
from .repository import init_repository


@click.group()
def main() -> None:
    """Secure management of sensitive files in Git repositories."""


@main.command()
@click.argument(
    "path",
    type=click.Path(
        path_type=Path,
        file_okay=False,
        dir_okay=True,
    ),
    default=".",
)
@click.option(
    "--encryption",
    "encryption_protocol",
    default=DEFAULT_ENCRYPTION_PROTOCOL,
    show_default=True,
)
def init(
    path: Path,
    encryption_protocol: str,
) -> None:
    """Initialize a SecureRepo."""
    try:
        init_repository(
            path,
            encryption_protocol=encryption_protocol,
        )
    except (FileExistsError, ValueError) as error:
        raise click.ClickException(str(error)) from error

    click.echo(f"Initialized SecureRepo in {path.resolve()}")


@main.command()
def status() -> None:
    """Show the status of protected files."""
    try:
        repo = discover_repository()
    except FileNotFoundError as error:
        raise click.ClickException(str(error)) from error

    for path, state in repo.status().items():
        click.echo(f"{path}: {state.value}")


@main.command()
@click.argument(
    "path",
    type=click.Path(
        path_type=Path,
        file_okay=True,
        dir_okay=False,
    ),
)
def protect(path: Path) -> None:
    """Protect a file."""
    try:
        repo = discover_repository(path)
        repo.protect(path)
    except (FileNotFoundError, ValueError) as error:
        raise click.ClickException(str(error)) from error

    click.echo(f"Protected {path}")


@main.command()
@click.argument(
    "path",
    type=click.Path(
        path_type=Path,
        file_okay=True,
        dir_okay=False,
    ),
)
def lock(path: Path) -> None:
    """Lock a protected file."""
    try:
        repo = discover_repository(path)
        repo.lock(path)
    except BackendConfigurationError as error:
        raise click.ClickException(
            f"{error} Run 'secrepo config encryption' first."
        ) from error
    except (FileNotFoundError, ValueError) as error:
        raise click.ClickException(str(error)) from error

    click.echo(f"Locked {path}")


@main.command()
@click.argument(
    "path",
    type=click.Path(
        path_type=Path,
        file_okay=True,
        dir_okay=False,
    ),
)
def unlock(path: Path) -> None:
    """Unlock a protected file."""
    try:
        repo = discover_repository(path)
        repo.unlock(path)
    except BackendConfigurationError as error:
        raise click.ClickException(
            f"{error} Run 'secrepo config encryption' first."
        ) from error
    except (FileNotFoundError, ValueError) as error:
        raise click.ClickException(str(error)) from error

    click.echo(f"Unlocked {path}")


def configure_encryption(**options: Any) -> None:
    """Configure encryption."""
    try:
        repo = discover_repository()

        backend = BACKENDS.get(repo.config.encryption.protocol)

        if backend is None:
            raise ValueError(
                "Unsupported encryption protocol: "
                f"{repo.config.encryption.protocol}."
            )

        backend.validate_options(**options)

        config = update_encryption_options(
            repo.config,
            options,
        )

        save_config(
            config,
            repo.root / SECREPO_DIRNAME / CONFIG_FILENAME,
        )
    except (FileNotFoundError, ValueError) as error:
        raise click.ClickException(str(error)) from error

    click.echo("Encryption configuration updated.")


def create_encryption_command() -> click.Command:
    """Create the encryption configuration command."""
    try:
        repo = discover_repository()
    except FileNotFoundError as error:
        raise click.ClickException(str(error)) from error

    backend = BACKENDS.get(repo.config.encryption.protocol)

    if backend is None:
        raise click.ClickException(
            "Unsupported encryption protocol: " f"{repo.config.encryption.protocol}."
        )

    params: List[click.Parameter] = [
        click.Option(
            param_decls=[f"--{option.name}"],
            type=get_click_option_type(option.type),
            required=option.required,
            multiple=option.multiple,
            help=option.help,
        )
        for option in backend.config_options
    ]

    return click.Command(
        name="encryption",
        callback=configure_encryption,
        params=params,
        help=f"Configure {repo.config.encryption.protocol} encryption.",
    )


class ConfigGroup(click.Group):
    """Click group for SecureRepo configuration commands."""

    def get_command(
        self,
        ctx: click.Context,
        cmd_name: str,
    ) -> Optional[click.Command]:
        """Resolve configuration commands dynamically."""
        if cmd_name == "encryption":
            return create_encryption_command()

        return super().get_command(ctx, cmd_name)

    def list_commands(
        self,
        ctx: click.Context,
    ) -> List[str]:
        """Return available configuration commands."""
        commands = super().list_commands(ctx)

        if "encryption" not in commands:
            commands.append("encryption")

        return sorted(commands)


def get_click_option_type(
    option_type: str,
) -> click.ParamType[Any]:
    """Return the Click parameter type for a backend option type."""
    option_types = {
        "string": click.STRING,
        "path": click.Path(path_type=Path),
    }

    try:
        return option_types[option_type]
    except KeyError as error:
        raise ValueError(f"Unsupported backend option type: {option_type}.") from error


@click.group(cls=ConfigGroup)
def config() -> None:
    """Configure SecureRepo."""


main.add_command(config)


@main.group()
def encryption() -> None:
    """Manage encryption."""


@encryption.command(name="init")
def encryption_init() -> None:
    """Initialize age encryption for the repository."""
    try:
        repo = discover_repository()
        repo.initialize_encryption()
    except FileExistsError as error:
        raise click.ClickException(
            f"{error} Encryption has already been initialized."
        ) from error
    except FileNotFoundError as error:
        raise click.ClickException(str(error)) from error

    click.echo("Encryption initialized.")


if __name__ == "__main__":
    main()
