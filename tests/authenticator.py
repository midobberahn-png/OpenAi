"""Ein Software-Authenticator für die Tests.

Ohne ihn wären die interessantesten WebAuthn-Fälle nicht prüfbar, sondern nur
behauptet: falscher Origin, falsche RP-ID, gefälschte Signatur, wiederholte
Assertion. Ein Mock des Verifizierers würde lediglich zeigen, dass der Mock
tut, was man ihm sagt — und genau die Prüfungen, um die es geht, liegen in der
Bibliothek dahinter.

Deshalb hier ein echter Authenticator: ES256-Schlüsselpaar, selbst gebautes
``clientDataJSON`` und ``authenticatorData``, echte Signatur. Was er erzeugt,
ist von der Antwort eines Hardwareschlüssels nicht zu unterscheiden — mit dem
Unterschied, dass wir jedes Feld absichtlich falsch setzen können.

Bewusst *nicht* im Anwendungscode: Ein Authenticator ist ein Angreiferwerkzeug
so gut wie ein Testwerkzeug. Er gehört in die Testsuite und nirgendwo sonst.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import bytes_to_base64url

__all__ = ["SoftwareAuthenticator"]


FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_ATTESTED_DATA = 0x40
AAGUID = b"\x00" * 16


@dataclass
class SoftwareAuthenticator:
    """Ein einzelner Passkey.

    ``sign_count`` verhält sich wie bei einem Hardwareschlüssel: Er steigt bei
    jeder Nutzung. Für die Klon-Erkennung lässt er sich von außen setzen — das
    ist der Fall, den ein echter Angreifer mit einem kopierten Schlüssel
    erzeugt.
    """

    rp_id: str = "localhost"
    origin: str = "http://localhost:5173"
    credential_id: bytes = field(default_factory=lambda: os.urandom(32))
    sign_count: int = 0
    user_verified: bool = True

    def __post_init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())

    # -- Registrierung ----------------------------------------------------
    def register(
        self, challenge: bytes, *, origin: str | None = None, rp_id: str | None = None
    ) -> dict[str, Any]:
        """Erzeugt eine Registrierungsantwort.

        ``origin`` und ``rp_id`` sind überschreibbar, weil genau darin die
        Angriffe bestehen: Ein Authenticator auf einer nachgebauten Seite
        signiert für *deren* Herkunft, und die Prüfung muss das bemerken.
        """
        client_data = self._client_data("webauthn.create", challenge, origin)
        auth_data = self._authenticator_data(
            rp_id or self.rp_id, attested=True, sign_count=self.sign_count
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(attestation),
            },
            "clientExtensionResults": {},
        }

    # -- Anmeldung --------------------------------------------------------
    def authenticate(
        self,
        challenge: bytes,
        *,
        origin: str | None = None,
        rp_id: str | None = None,
        sign_count: int | None = None,
        break_signature: bool = False,
    ) -> dict[str, Any]:
        """Erzeugt eine Anmeldeantwort.

        ``sign_count`` überschreibt den mitgeführten Zähler — damit lässt sich
        der geklonte Schlüssel nachstellen, der einen alten Stand meldet.
        ``break_signature`` erzeugt eine formal gültige, kryptografisch falsche
        Antwort.
        """
        if sign_count is None:
            self.sign_count += 1
            counter = self.sign_count
        else:
            counter = sign_count

        client_data = self._client_data("webauthn.get", challenge, origin)
        auth_data = self._authenticator_data(
            rp_id or self.rp_id, attested=False, sign_count=counter
        )
        signature = self._sign(auth_data + hashlib.sha256(client_data).digest())
        if break_signature:
            # Eine gültige Signatur über *andere* Daten: Die Struktur stimmt,
            # die Bindung an diese Zeremonie nicht.
            signature = self._sign(b"etwas ganz anderes")

        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }

    # -- Bausteine --------------------------------------------------------
    def _client_data(self, ceremony: str, challenge: bytes, origin: str | None) -> bytes:
        return json.dumps(
            {
                "type": ceremony,
                "challenge": bytes_to_base64url(challenge),
                "origin": origin or self.origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()

    def _authenticator_data(self, rp_id: str, *, attested: bool, sign_count: int) -> bytes:
        flags = FLAG_USER_PRESENT
        if self.user_verified:
            flags |= FLAG_USER_VERIFIED
        if attested:
            flags |= FLAG_ATTESTED_DATA

        data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags])
        data += struct.pack(">I", sign_count)
        if attested:
            data += (
                AAGUID
                + struct.pack(">H", len(self.credential_id))
                + self.credential_id
                + self._cose_key()
            )
        return data

    def _cose_key(self) -> bytes:
        """Der öffentliche Schlüssel im COSE-Format (ES256)."""
        numbers = self._key.public_key().public_numbers()
        return bytes(
            cbor2.dumps(
                {
                    1: 2,  # kty: EC2
                    3: -7,  # alg: ES256
                    -1: 1,  # crv: P-256
                    -2: numbers.x.to_bytes(32, "big"),
                    -3: numbers.y.to_bytes(32, "big"),
                }
            )
        )

    def _sign(self, payload: bytes) -> bytes:
        return bytes(self._key.sign(payload, ec.ECDSA(hashes.SHA256())))
