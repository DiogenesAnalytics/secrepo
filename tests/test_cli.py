"""Tests for SecureRepo cli."""

from pathlib import Path

from click.testing import CliRunner

from secrepo.cli import main


def test_cli_init(tmp_path: Path) -> None:
    """Initialize a SecureRepo from the CLI."""
    runner = CliRunner()

    result = runner.invoke(main, ["init", str(tmp_path)])

    assert result.exit_code == 0
    assert (tmp_path / ".secrepo" / "protected.yaml").exists()


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
