"""Tests for SecureRepo configuration management."""

from pathlib import Path
from textwrap import dedent

import pytest
import yaml

from secrepo.config import CONFIG_VERSION
from secrepo.config import SecureRepoConfig
from secrepo.config import load_config
from secrepo.config import save_config


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
        protected=(
            "data/private/**",
            "notebooks/analysis.ipynb",
        ),
    )


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
        protected=(),
    )


def test_save_config(tmp_path: Path) -> None:
    """Save a configuration to a YAML file."""
    config_path = tmp_path / "secrepo.yaml"

    config = SecureRepoConfig(
        version=CONFIG_VERSION,
        protected=(
            "data/private/**",
            "notebooks/analysis.ipynb",
        ),
    )

    save_config(config, config_path)

    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    assert data == {
        "version": CONFIG_VERSION,
        "protected": [
            "data/private/**",
            "notebooks/analysis.ipynb",
        ],
    }


def test_load_config_file_not_found(tmp_path: Path) -> None:
    """Raise FileNotFoundError when the configuration does not exist."""
    config_path = tmp_path / "missing.yaml"

    with pytest.raises(FileNotFoundError):
        load_config(config_path)


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


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    """A saved configuration can be loaded without changing its value."""
    config_path = tmp_path / "secrepo.yaml"

    original = SecureRepoConfig(
        version=CONFIG_VERSION,
        protected=(
            "data/private/**",
            "notebooks/analysis.ipynb",
            "results/**",
        ),
    )

    save_config(original, config_path)
    loaded = load_config(config_path)

    assert loaded == original
