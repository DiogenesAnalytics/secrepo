"""Tests for encryption backend management."""

from pathlib import Path
from typing import Any
from typing import Dict
from typing import Tuple
from typing import Type

import pytest
from pytest import MonkeyPatch

from secrepo.config import EncryptionConfig
from secrepo.encryption.backend import BackendOption
from secrepo.encryption.backend import EncryptionBackend
from secrepo.encryption.backend import create_backend
from secrepo.encryption.backend import register_backends


class FakeBackend:
    """Fake encryption backend for testing."""

    config_options: Tuple[BackendOption, ...] = ()

    def __init__(
        self,
        key: str,
        retries: int,
    ) -> None:
        """Initialize the fake backend."""
        self.key = key
        self.retries = retries

    @classmethod
    def validate_options(
        cls,
        **options: Any,
    ) -> None:
        """Validate fake backend options."""

    def encrypt(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        """Encrypt a file."""
        raise NotImplementedError

    def decrypt(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        """Decrypt a file."""
        raise NotImplementedError


@pytest.mark.enc
def test_register_backend(
    monkeypatch: MonkeyPatch,
) -> None:
    """Register an encryption backend."""
    backends: Dict[str, Type[EncryptionBackend]] = {}

    monkeypatch.setattr(
        "secrepo.encryption.backend.BACKENDS",
        backends,
    )

    register_backends({"test": FakeBackend})

    assert backends["test"] is FakeBackend


@pytest.mark.enc
def test_create_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Create the backend configured by the encryption protocol."""
    monkeypatch.setattr(
        "secrepo.encryption.backend.BACKENDS",
        {"test": FakeBackend},
    )

    config = EncryptionConfig(
        protocol="test",
        options={
            "key": "secret",
            "retries": 3,
        },
    )

    backend = create_backend(config)

    assert isinstance(backend, FakeBackend)
    assert backend.key == "secret"
    assert backend.retries == 3


@pytest.mark.enc
def test_create_backend_without_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Create a backend with no encryption options."""
    monkeypatch.setattr(
        "secrepo.encryption.backend.BACKENDS",
        {"test": FakeBackend},
    )

    config = EncryptionConfig(
        protocol="test",
    )

    with pytest.raises(
        TypeError,
        match="missing.*required positional argument",
    ):
        create_backend(config)


@pytest.mark.enc
def test_create_backend_rejects_unsupported_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject an encryption protocol with no registered backend."""
    monkeypatch.setattr(
        "secrepo.encryption.backend.BACKENDS",
        {},
    )

    config = EncryptionConfig(
        protocol="unknown",
    )

    with pytest.raises(
        ValueError,
        match="Unsupported encryption protocol: unknown",
    ):
        create_backend(config)
