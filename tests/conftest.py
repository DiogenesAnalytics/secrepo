"""Pytest fixtures for SecureRepo tests."""

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """For configuring pytest with custom markers."""
    config.addinivalue_line(
        "markers", "config: custom marker for secrepo.config module tests."
    )
    config.addinivalue_line(
        "markers", "repo: custom marker for secrepo.repository module tests."
    )
