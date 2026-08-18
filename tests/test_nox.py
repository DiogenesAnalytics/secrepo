"""Tests for nox utilities."""

from packaging import version
from pytest import MonkeyPatch

from noxfile import generate_python_versions
from noxfile import get_python_versions_from_toml
from noxfile import parse_requires_python


def test_parse_requires_python() -> None:
    """Test that the function correctly extracts min/max versions."""
    # get
    parsed = parse_requires_python(">=3.7, <3.11")

    assert parsed[">="] == version.parse("3.7")
    assert parsed["<"] == version.parse("3.11")
    assert parsed[">"] is None
    assert parsed["<="] is None

    parsed = parse_requires_python(">3.8, <=3.12")

    assert parsed[">"] == version.parse("3.8")
    assert parsed["<="] == version.parse("3.12")
    assert parsed[">="] is None
    assert parsed["<"] is None


def test_generate_python_versions() -> None:
    """Test that the function correctly generates a list of minor versions."""
    assert generate_python_versions(version.parse("3.6"), version.parse("3.10")) == [
        "3.6",
        "3.7",
        "3.8",
        "3.9",
    ]
    assert generate_python_versions(version.parse("3.9"), version.parse("3.13")) == [
        "3.9",
        "3.10",
        "3.11",
        "3.12",
    ]


def test_get_python_versions_from_toml(monkeypatch: MonkeyPatch) -> None:
    """Mock the TOML loading and test the full pipeline."""
    # use monkeypatch to replace nox.project.load_toml with our mock function
    monkeypatch.setattr(
        "nox.project.load_toml",
        lambda _: {"project": {"requires-python": ">=3.9, <3.13"}},
    )

    versions = get_python_versions_from_toml()
    assert versions == ["3.9", "3.10", "3.11", "3.12"]
