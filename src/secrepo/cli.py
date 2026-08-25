"""Command-line interface for SecureRepo."""

from pathlib import Path

import click

from .config import DEFAULT_ENCRYPTION_PROTOCOL
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
    except FileExistsError as error:
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


if __name__ == "__main__":
    main()
