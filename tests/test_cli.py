"""Tests for SecureRepo cli."""

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner
from pytest import MonkeyPatch

from secrepo.cli import main
from secrepo.config import CONFIG_FILENAME
from secrepo.config import CONFIG_VERSION
from secrepo.config import DEFAULT_ENCRYPTION_PROTOCOL
from secrepo.config import SECREPO_DIRNAME
from secrepo.config import EncryptionConfig
from secrepo.config import SecureRepoConfig
from secrepo.config import save_config
from secrepo.encryption.protocols.age import generate_identity
from secrepo.encryption.protocols.age import initialize_identity
from secrepo.encryption.protocols.age import save_identity
from secrepo.repository import discover_repository
from secrepo.repository import init_repository


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


def test_encryption_rejects_invalid_options(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Test that invalid encryption options are not persisted."""
    runner = CliRunner()

    monkeypatch.chdir(tmp_path)

    init_repository(tmp_path)

    config_path = tmp_path / SECREPO_DIRNAME / CONFIG_FILENAME
    original_config = config_path.read_text(encoding="utf-8")

    result = runner.invoke(
        main,
        [
            "config",
            "encryption",
            "--recipients",
            "age1invalid",
            "--identity",
            str(tmp_path / "missing-identity"),
        ],
        catch_exceptions=False,
    )

    assert result.exit_code != 0
    assert "Invalid age recipient" in result.output
    assert config_path.read_text(encoding="utf-8") == original_config


@pytest.mark.cli
def test_lock(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Test the lock command."""
    monkeypatch.chdir(tmp_path)

    init_repository(tmp_path)

    identity = generate_identity()
    identity_path = tmp_path / "identity"
    save_identity(identity, identity_path)

    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol="age",
            options={
                "recipients": (str(identity.to_public()),),
                "identity": identity_path,
            },
        ),
        protected=(),
    )

    save_config(
        config,
        tmp_path / SECREPO_DIRNAME / CONFIG_FILENAME,
    )

    secret_path = tmp_path / "secret.txt"
    secret_path.write_text(
        "This is sensitive data.\n",
        encoding="utf-8",
    )

    repo = discover_repository(tmp_path)
    repo.protect(secret_path)

    runner = CliRunner()

    result = runner.invoke(
        main,
        ["lock", str(secret_path)],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    assert f"Locked {secret_path}" in result.output
    assert repo.encrypted_path(secret_path).is_file()


@pytest.mark.cli
def test_unlock(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Test the unlock command."""
    monkeypatch.chdir(tmp_path)

    init_repository(tmp_path)

    identity = generate_identity()
    identity_path = tmp_path / "identity"
    save_identity(identity, identity_path)

    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol="age",
            options={
                "recipients": (str(identity.to_public()),),
                "identity": identity_path,
            },
        ),
        protected=(),
    )

    save_config(
        config,
        tmp_path / SECREPO_DIRNAME / CONFIG_FILENAME,
    )

    secret_path = tmp_path / "secret.txt"
    original_content = "This is sensitive data.\n"
    secret_path.write_text(
        original_content,
        encoding="utf-8",
    )

    repo = discover_repository(tmp_path)
    repo.protect(secret_path)
    repo = discover_repository(tmp_path)

    repo.lock(secret_path)
    secret_path.unlink()

    runner = CliRunner()

    result = runner.invoke(
        main,
        ["unlock", str(secret_path)],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    assert f"Unlocked {secret_path}" in result.output
    assert secret_path.is_file()
    assert secret_path.read_text(encoding="utf-8") == original_content
    assert repo.encrypted_path(secret_path).is_file()


@pytest.mark.cli
def test_lock_without_encryption_configuration(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Test that lock reports missing encryption configuration."""
    monkeypatch.chdir(tmp_path)

    init_repository(tmp_path)

    secret_path = tmp_path / "secret.txt"
    secret_path.write_text(
        "This is sensitive data.\n",
        encoding="utf-8",
    )

    repo = discover_repository(tmp_path)
    repo.protect(secret_path)

    runner = CliRunner()

    result = runner.invoke(
        main,
        ["lock", str(secret_path)],
        catch_exceptions=False,
    )

    assert result.exit_code != 0
    assert "Age encryption is not configured: recipients are missing." in result.output


@pytest.mark.cli
def test_encryption_init(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Initialize encryption for a repository."""
    init_repository(tmp_path)
    monkeypatch.chdir(tmp_path)

    identity_path = tmp_path / "identity"

    monkeypatch.setattr(
        "secrepo.repository.default_identity_path",
        lambda: identity_path,
    )

    runner = CliRunner()

    result = runner.invoke(
        main,
        ["encryption", "init"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    assert result.output == "Encryption initialized.\n"

    repo = discover_repository(tmp_path)

    assert repo.config.encryption.protocol == "age"
    assert repo.config.encryption.options["recipients"]
    assert repo.config.encryption.options["identity"] == str(identity_path)


@pytest.mark.cli
def test_encryption_init_existing_identity(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Report an error when the age identity already exists."""
    init_repository(tmp_path)
    monkeypatch.chdir(tmp_path)

    identity_path = tmp_path / "identity"

    monkeypatch.setattr(
        "secrepo.repository.default_identity_path",
        lambda: identity_path,
    )

    initialize_identity(identity_path)

    runner = CliRunner()

    result = runner.invoke(
        main,
        ["encryption", "init"],
    )

    assert result.exit_code != 0
    assert (
        f"Error: Age identity already exists: {identity_path}"
        " Encryption has already been initialized.\n" == result.output
    )
