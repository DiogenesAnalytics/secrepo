"""Tests for SecureRepo cli."""

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from secrepo.cli import main
from secrepo.config import DEFAULT_ENCRYPTION_PROTOCOL


@pytest.mark.cli
def test_cli_init(tmp_path: Path) -> None:
    """Initialize a SecureRepo from the CLI."""
    runner = CliRunner()

    result = runner.invoke(main, ["init", str(tmp_path)])

    assert result.exit_code == 0
    assert (tmp_path / ".secrepo" / "protected.yaml").exists()


@pytest.mark.cli
def test_cli_protect(tmp_path: Path) -> None:
    """Protect a file from the CLI."""
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["init"])

        assert result.exit_code == 0

        path = Path("secret.txt")
        path.write_text("secret", encoding="utf-8")

        result = runner.invoke(
            main,
            ["protect", str(path)],
            catch_exceptions=False,
        )

        assert result.exit_code == 0
        assert "Protected" in result.output


@pytest.mark.cli
def test_cli_status(tmp_path: Path) -> None:
    """Show protected file status from the CLI."""
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["init"])

        assert result.exit_code == 0

        path = Path("secret.txt")
        path.write_text("secret", encoding="utf-8")

        result = runner.invoke(
            main,
            ["protect", str(path)],
            catch_exceptions=False,
        )

        assert result.exit_code == 0

        result = runner.invoke(
            main,
            ["status"],
            catch_exceptions=False,
        )

        assert result.exit_code == 0
        assert "secret.txt: unlocked" in result.output


@pytest.mark.cli
def test_cli_init_uses_default_encryption_protocol(tmp_path: Path) -> None:
    """Initialize with the default encryption protocol."""
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["init"])

        assert result.exit_code == 0

        config_path = Path(".secrepo/protected.yaml")
        assert config_path.exists()

        data = yaml.safe_load(
            config_path.read_text(encoding="utf-8"),
        )

        assert data["encryption"]["protocol"] == DEFAULT_ENCRYPTION_PROTOCOL


@pytest.mark.cli
def test_cli_init_accepts_encryption_protocol(tmp_path: Path) -> None:
    """Initialize with an explicitly selected encryption protocol."""
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(
            main,
            ["init", "--encryption", "age"],
        )

        assert result.exit_code == 0

        config_path = Path(".secrepo/protected.yaml")
        data = yaml.safe_load(
            config_path.read_text(encoding="utf-8"),
        )

        assert data["encryption"]["protocol"] == "age"


@pytest.mark.cli
def test_cli_init_rejects_unsupported_encryption_protocol(
    tmp_path: Path,
) -> None:
    """Reject an unsupported encryption protocol."""
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(
            main,
            [
                "init",
                "--encryption",
                "unknown",
            ],
        )

        assert result.exit_code != 0
        assert "Unsupported encryption protocol" in result.output
