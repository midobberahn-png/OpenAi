"""Verschlüsselung ruhender Geheimnisse (ADR-008)."""

from .envelope import (
    DEK_BYTES,
    NONCE_BYTES,
    SealedSecret,
    SecretTampered,
    oeffnen,
    versiegeln,
)

__all__ = [
    "DEK_BYTES",
    "NONCE_BYTES",
    "SealedSecret",
    "SecretTampered",
    "oeffnen",
    "versiegeln",
]
