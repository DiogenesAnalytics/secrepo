"""Tests for SecureRepo configuration management."""

from pathlib import Path
from textwrap import dedent

import pytest
import yaml

from secrepo.config import CONFIG_VERSION
from secrepo.config import DEFAULT_ENCRYPTION_PROTOCOL
from secrepo.config import EncryptionConfig
from secrepo.config import SecureRepoConfig
from secrepo.config import load_config
from secrepo.config import save_config


@pytest.mark.config
def test_load_config(tmp_path: Path) -> None:
    """Load a valid configuration from a YAML file."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: 1
            protected:
              - data/private/**
              - notebooks/analysis.ipynb
            """),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config == SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol=DEFAULT_ENCRYPTION_PROTOCOL,
        ),
        protected=(
            "data/private/**",
            "notebooks/analysis.ipynb",
        ),
    )


@pytest.mark.config
def test_load_config_with_no_protected_files(tmp_path: Path) -> None:
    """Load a configuration with no protected files."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: 1
            protected: []
            """),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config == SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol=DEFAULT_ENCRYPTION_PROTOCOL,
        ),
        protected=(),
    )


@pytest.mark.config
def test_save_config(tmp_path: Path) -> None:
    """Save a configuration to a YAML file."""
    config_path = tmp_path / "secrepo.yaml"

    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol=DEFAULT_ENCRYPTION_PROTOCOL,
        ),
        protected=(
            "data/private/**",
            "notebooks/analysis.ipynb",
        ),
    )

    save_config(config, config_path)

    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    assert data == {
        "version": CONFIG_VERSION,
        "encryption": {
            "protocol": DEFAULT_ENCRYPTION_PROTOCOL,
            "options": {},
        },
        "protected": [
            "data/private/**",
            "notebooks/analysis.ipynb",
        ],
    }


@pytest.mark.config
def test_load_config_file_not_found(tmp_path: Path) -> None:
    """Raise FileNotFoundError when the configuration does not exist."""
    config_path = tmp_path / "missing.yaml"

    with pytest.raises(FileNotFoundError):
        load_config(config_path)


@pytest.mark.config
def test_load_config_requires_mapping(tmp_path: Path) -> None:
    """Reject a configuration whose root value is not a mapping."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        "- one\n- two\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="must be a mapping",
    ):
        load_config(config_path)


@pytest.mark.config
def test_load_config_requires_integer_version(tmp_path: Path) -> None:
    """Reject a configuration with a non-integer version."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: "1"
            protected: []
            """),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="'version' must be an integer",
    ):
        load_config(config_path)


@pytest.mark.config
def test_load_config_rejects_unsupported_version(
    tmp_path: Path,
) -> None:
    """Reject a configuration version that SecureRepo does not support."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: 999
            protected: []
            """),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Unsupported configuration version",
    ):
        load_config(config_path)


@pytest.mark.config
def test_load_config_requires_protected_list(
    tmp_path: Path,
) -> None:
    """Reject a configuration whose protected value is not a list."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: 1
            protected: data/private
            """),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="'protected' must be a list",
    ):
        load_config(config_path)


@pytest.mark.config
def test_load_config_requires_string_paths(
    tmp_path: Path,
) -> None:
    """Reject protected paths that are not strings."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: 1
            protected:
              - data/private/**
              - 123
            """),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="must be strings",
    ):
        load_config(config_path)


@pytest.mark.config
def test_save_and_load_round_trip(tmp_path: Path) -> None:
    """A saved configuration can be loaded without changing its value."""
    config_path = tmp_path / "secrepo.yaml"

    original = SecureRepoConfig(
        version=CONFIG_VERSION,
        encryption=EncryptionConfig(
            protocol=DEFAULT_ENCRYPTION_PROTOCOL,
            options={
                "recipients": [
                    "age1example",
                ],
            },
        ),
        protected=(
            "data/private/**",
            "notebooks/analysis.ipynb",
            "results/**",
        ),
    )

    save_config(original, config_path)
    loaded = load_config(config_path)

    assert loaded == original


@pytest.mark.config
def test_load_config_with_encryption_protocol(tmp_path: Path) -> None:
    """Load a configuration with an explicit encryption protocol."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: 1
            encryption:
              protocol: age
            protected: []
            """),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.encryption == EncryptionConfig(
        protocol="age",
    )


@pytest.mark.config
def test_load_config_with_encryption_options(tmp_path: Path) -> None:
    """Load a configuration with encryption protocol options."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: 1
            encryption:
              protocol: age
              options:
                recipients:
                  - age1example
            protected: []
            """),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.encryption == EncryptionConfig(
        protocol="age",
        options={
            "recipients": [
                "age1example",
            ],
        },
    )


@pytest.mark.config
def test_load_config_rejects_unsupported_encryption_protocol(
    tmp_path: Path,
) -> None:
    """Reject an unsupported encryption protocol."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: 1
            encryption:
              protocol: unknown
            protected: []
            """),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Unsupported encryption protocol",
    ):
        load_config(config_path)


@pytest.mark.config
def test_load_config_requires_encryption_mapping(
    tmp_path: Path,
) -> None:
    """Reject an encryption value that is not a mapping."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: 1
            encryption: age
            protected: []
            """),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="'encryption' must be a mapping",
    ):
        load_config(config_path)


@pytest.mark.config
def test_load_config_requires_encryption_options_mapping(
    tmp_path: Path,
) -> None:
    """Reject encryption options that are not a mapping."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: 1
            encryption:
              protocol: age
              options: invalid
            protected: []
            """),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="'encryption.options' must be a mapping",
    ):
        load_config(config_path)


@pytest.mark.config
def test_load_config_requires_encryption_protocol_string(
    tmp_path: Path,
) -> None:
    """Reject a non-string encryption protocol."""
    config_path = tmp_path / "secrepo.yaml"

    config_path.write_text(
        dedent("""\
            version: 1
            encryption:
              protocol: 123
            protected: []
            """),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="'encryption.protocol' must be a string",
    ):
        load_config(config_path)
