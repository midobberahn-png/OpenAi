"""Authentifizierung — Sitzungen mit Herkunft, Frist und Widerruf.

Bis hierher war ``session_id`` ein Wert, den der Aufrufer mitbrachte. Mit
diesem Paket wird daraus eine Zusicherung: Die Sitzungsbindung einer
Bestätigung prüft ab jetzt, dass die Sitzung existiert, dem Nutzer gehört und
noch gilt.

Passkeys und WebAuthn liegen bewusst **nicht** hier, sondern in ``apps/api``:
Die Bibliothek dafür ist ein Fremdsystem, und der Kern kennt keine
Fremdsysteme (ADR-009).
"""

from .sessions import SESSION_TOKEN_BYTES, SessionManager, token_fingerprint

__all__ = ["SESSION_TOKEN_BYTES", "SessionManager", "token_fingerprint"]
