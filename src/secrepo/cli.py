"""Command-line interface for SecureRepo."""

import click


@click.group()
def main() -> None:
    """Secure management of sensitive files in Git repositories."""


if __name__ == "__main__":
    main()
