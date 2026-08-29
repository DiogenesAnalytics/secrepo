"""Encryption support for SecureRepo."""

from . import protocols
from .backend import EncryptionBackend
from .backend import create_backend
from .backend import register_backends

register_backends(
    {
        "age": protocols.AgeEncryptionBackend,
    }
)

__all__ = [
    "EncryptionBackend",
    "create_backend",
]
