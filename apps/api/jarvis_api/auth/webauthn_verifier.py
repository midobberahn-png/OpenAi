"""WebAuthn-Verifikation — der Adapter um ``py_webauthn``.

Die einzige Stelle im Projekt, die eine WebAuthn-Bibliothek kennt. Der Kern
ruft sie über ``AttestationVerifier`` auf und weiß nichts von ihr (ADR-009).

Was hier geprüft wird, ist die Kryptografie: Signatur, Origin, RP-ID,
Nutzerpräsenz. Was **nicht** hier geprüft wird — Einmaligkeit der Challenge,
Zweckbindung, Klon-Erkennung — steht im Kern, weil eine Bibliothek den
Zustand des Systems nicht kennt.

Zur Origin-Prüfung: ``expected_origin`` ist die Verankerung, die Passkeys
phishing-resistent macht. Eine Signatur, die für ``https://jarvis.local``
ausgestellt wurde, ist auf einer nachgebauten Seite wertlos. Deshalb ist die
Herkunft hier Konfiguration und kein Wert aus dem Request — ein aus dem
Request übernommener Origin wäre die Aufhebung genau dieser Eigenschaft.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webauthn import verify_authentication_response, verify_registration_response

__all__ = ["VerifiedAssertionResult", "VerifiedAttestationResult", "WebAuthnVerifier"]


@dataclass(frozen=True)
class VerifiedAttestationResult:
    credential_id: bytes
    public_key: bytes
    sign_count: int


@dataclass(frozen=True)
class VerifiedAssertionResult:
    new_sign_count: int


class WebAuthnVerifier:
    """Prüft Registrierungs- und Anmeldeantworten gegen die Spezifikation."""

    def __init__(
        self,
        *,
        rp_id: str,
        expected_origins: list[str],
        require_user_verification: bool = True,
    ) -> None:
        self._rp_id = rp_id
        self._origins = expected_origins
        self._require_uv = require_user_verification
        """Nutzerverifikation (PIN, Biometrie) ist Pflicht, nicht Wunsch: Ohne
        sie genügt der Besitz des Geräts, und der Passkey wäre nur noch ein
        zweiter Faktor ohne ersten."""

    def verify_registration(
        self, credential: dict[str, Any] | str, *, challenge: bytes
    ) -> VerifiedAttestationResult:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=self._rp_id,
            expected_origin=self._origins,
            require_user_verification=self._require_uv,
        )
        return VerifiedAttestationResult(
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
        )

    def verify_authentication(
        self,
        credential: dict[str, Any] | str,
        *,
        challenge: bytes,
        public_key: bytes,
        sign_count: int,
    ) -> VerifiedAssertionResult:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=self._rp_id,
            expected_origin=self._origins,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=self._require_uv,
        )
        return VerifiedAssertionResult(new_sign_count=verified.new_sign_count)
