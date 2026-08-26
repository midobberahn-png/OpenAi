"""Authentifizierung — Sitzungen mit Herkunft, Frist und Widerruf.

Bis hierher war ``session_id`` ein Wert, den der Aufrufer mitbrachte. Mit
diesem Paket wird daraus eine Zusicherung: Die Sitzungsbindung einer
Bestätigung prüft ab jetzt, dass die Sitzung existiert, dem Nutzer gehört und
noch gilt.

Passkeys und WebAuthn liegen bewusst **nicht** hier, sondern in ``apps/api``:
Die Bibliothek dafür ist ein Fremdsystem, und der Kern kennt keine
Fremdsysteme (ADR-009).
"""

from .passkeys import (
    CHALLENGE_BYTES,
    AuthenticationFailed,
    CloneSuspicion,
    PasskeyService,
    sign_count_is_plausible,
)
from .sessions import (
    SESSION_TOKEN_BYTES,
    SessionCheck,
    SessionManager,
    SessionRejection,
    token_fingerprint,
)

__all__ = [
    "CHALLENGE_BYTES",
    "SESSION_TOKEN_BYTES",
    "AuthenticationFailed",
    "CloneSuspicion",
    "PasskeyService",
    "SessionCheck",
    "SessionManager",
    "SessionRejection",
    "sign_count_is_plausible",
    "token_fingerprint",
]
