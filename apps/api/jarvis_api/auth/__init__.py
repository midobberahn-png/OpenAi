"""Auth-Adapter — die Fremdsysteme hinter der Anmeldung.

Der Ablauf steht in ``jarvis_core.auth``; hier liegt nur, was eine Bibliothek
braucht: die WebAuthn-Verifikation. Die Trennung ist ADR-009 und zugleich der
Grund, warum sich Einmaligkeit, Zweckbindung und Klon-Erkennung ohne
Authenticator prüfen lassen.
"""

from .webauthn_verifier import WebAuthnVerifier

__all__ = ["WebAuthnVerifier"]
