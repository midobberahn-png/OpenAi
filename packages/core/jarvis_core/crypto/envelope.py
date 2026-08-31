"""Envelope Encryption — ein Datenschlüssel je Datensatz (ADR-008).

Der Ablauf in einem Satz: Für jeden Datensatz entsteht ein frischer
Datenschlüssel (DEK), der Klartext wird damit verschlüsselt, und der DEK
wandert **verpackt** neben den Geheimtext. Der Schlüssel, der ihn verpackt
(KEK), liegt woanders — bei einem ``KeyProvider``, der ihn nie herausgibt.

**Was das bringt und was nicht.** Ein Datenbank-Dump ohne den KEK ist wertlos;
das ist der ganze Zweck. Wer dagegen den laufenden Prozess kompromittiert,
bekommt, was der Prozess bekommt — dagegen hilft nur, dass der KEK die Instanz
nie verlässt (ADR-008 V1.1), und das entscheidet der Adapter, nicht diese
Datei.

**Ein DEK je Datensatz, kein gemeinsamer.** Nicht aus Vorsicht, sondern weil es
die Nonce-Frage beantwortet: AES-GCM verliert seine Zusage vollständig, wenn
dieselbe Nonce zweimal mit demselben Schlüssel verwendet wird. Mit einem
frischen Schlüssel je Datensatz kann das nicht passieren — die Eigenschaft
entsteht aus der Bauart und nicht aus Disziplin beim Zählen.

**Und der Geheimtext ist an seinen Platz gebunden.** Diese Entscheidung trifft
ADR-008 nicht; sie kommt aus derselben Überlegung, die dem Audit-Log seinen
Trigger gegeben hat. Wer die Datenbank direkt erreicht, kann eine Zeile nicht
entschlüsseln — aber er könnte sie **verschieben**: den Geheimtext eines
fremden Kontos in die eigene Zeile kopieren und ihn vom System entschlüsseln
lassen. Deshalb geht die Kennung des Datensatzes als *zusätzliche
authentifizierte Daten* (AAD) in die Verschlüsselung ein. Ein verschobener
Geheimtext öffnet sich dann nicht, und zwar ohne dass jemand daran denken
müsste.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict

from jarvis_core.ports.keys import KeyProvider

__all__ = [
    "DEK_BYTES",
    "NONCE_BYTES",
    "SealedSecret",
    "SecretTampered",
    "oeffnen",
    "versiegeln",
]

DEK_BYTES = 32
"""256 Bit — AES-256-GCM, wie in ADR-008 festgelegt."""

NONCE_BYTES = 12
"""96 Bit, die empfohlene Länge für GCM.

Länger ist nicht besser: Abweichende Längen werden intern erst gehasht, und die
Empfehlung ist der Fall, für den die Konstruktion analysiert wurde."""


class SecretTampered(Exception):
    """Der Geheimtext ließ sich nicht öffnen.

    **Ein einziger Fehlerfall nach außen, und das ist Absicht.** Ob der
    Geheimtext verändert, die Nonce vertauscht oder der Datensatz an eine
    fremde Stelle kopiert wurde — GCM beantwortet all das mit demselben
    ``InvalidTag``, und eine feinere Auskunft wäre ein Orakel für den, der es
    versucht. Was der Betreiber braucht, steht im Protokoll der aufrufenden
    Schicht, nicht in der Ausnahme.
    """


class SealedSecret(BaseModel):
    """Ein versiegeltes Geheimnis — genau die vier Spalten der Tabelle.

    ``oauth_credentials`` führt sie seit dem ersten Schema (``ciphertext``,
    ``nonce``, ``wrapped_dek``, ``kek_id``) und hatte bis hierher keinen Code
    dazu. Dieses Modell ist die Brücke; es enthält **keinen** Klartext, auch
    nicht vorübergehend.
    """

    model_config = ConfigDict(frozen=True)

    ciphertext: bytes
    nonce: bytes
    wrapped_dek: bytes
    kek_id: str
    """Welcher KEK diesen Datensatz versiegelt hat — die Grundlage der
    Rotation. Ohne ihn wüsste beim Öffnen niemand, welcher Schlüssel gefragt
    ist, und eine Rotation hieße, alle Zeilen neu zu verschlüsseln."""


async def versiegeln(klartext: bytes, *, bindung: bytes, schluessel: KeyProvider) -> SealedSecret:
    """Verschlüsselt einen Klartext und verpackt seinen Datenschlüssel.

    ``bindung`` ist die Kennung des Datensatzes (etwa die Konto-ID als Bytes).
    Sie wird **nicht** gespeichert und **nicht** verschlüsselt — sie geht als
    AAD in die Verschlüsselung ein und muss beim Öffnen wieder dieselbe sein.
    Damit öffnet sich ein Geheimtext nur dort, wo er hingehört.
    """
    dek = os.urandom(DEK_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(nonce, klartext, bindung)
    wrapped = await schluessel.wrap(dek)
    return SealedSecret(
        ciphertext=ciphertext,
        nonce=nonce,
        wrapped_dek=wrapped,
        # **Nach** dem Verpacken gelesen und nicht davor: Wer zwischen beidem
        # rotiert, soll die Kennung bekommen, unter der tatsächlich verpackt
        # wurde. Ein Datensatz mit falscher Kennung ließe sich nie mehr öffnen.
        kek_id=schluessel.kek_id,
    )


async def oeffnen(siegel: SealedSecret, *, bindung: bytes, schluessel: KeyProvider) -> bytes:
    """Öffnet ein versiegeltes Geheimnis — oder wirft.

    Der Datenschlüssel wird mit **dem** KEK entpackt, der im Datensatz steht,
    nicht mit dem aktuellen. Genau das macht eine Rotation billig.
    """
    dek = await schluessel.unwrap(siegel.wrapped_dek, kek_id=siegel.kek_id)
    try:
        return AESGCM(dek).decrypt(siegel.nonce, siegel.ciphertext, bindung)
    except InvalidTag as ungueltig:
        raise SecretTampered("Der Geheimtext ließ sich nicht öffnen.") from ungueltig
