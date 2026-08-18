"""Hash-verkettetes Audit-Log.

Siehe docs/07-security-permissions.md §8.

Die Kette macht nachträgliche Manipulation *erkennbar* — sie verhindert sie
nicht. Verhindert wird sie durch den Trigger auf Datenbankebene
(Migration 07215b957d0f). Beides zusammen ist der Punkt: Wer die Anwendung
kompromittiert, kann keine Spuren beseitigen; wer die Datenbank direkt
manipuliert, hinterlässt einen Kettenbruch.

Zwei Entscheidungen, die hier festgelegt und nicht änderbar sind, ohne die
Migration mitzuändern:

1. **``user_id`` geht NICHT in den Hash.** Die DSGVO-Löschung pseudonymisiert
   Audit-Einträge (``user_id → NULL``). Wäre die Kennung Teil des Hashes,
   würde jede Nutzerlöschung die Kette zerreißen und damit die
   Unveränderlichkeitszusicherung entwerten. Der Trigger lässt genau diese
   eine Änderung zu, weil sie den Hash nicht berührt.
2. **Anfügen ist serialisiert.** Zwei gleichzeitige Schreiber würden denselben
   ``prev_hash`` lesen und die Kette gabeln. Deshalb ein Advisory Lock je
   Transaktion — nicht optional, sondern Voraussetzung der Verkettung.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AUDIT_ADVISORY_LOCK_KEY",
    "GENESIS_HASH",
    "AuditEntry",
    "AuditSink",
    "ChainBreak",
    "canonical_payload",
    "compute_entry_hash",
    "verify_chain",
]


GENESIS_HASH = b"\x00" * 32
"""Vorgänger des ersten Eintrags. Ausdrücklich gesetzt statt ``None``, damit
die Hash-Berechnung für den ersten Eintrag denselben Weg nimmt wie für alle
weiteren — Sonderfälle in Sicherheitscode sind Fehlerquellen."""

AUDIT_ADVISORY_LOCK_KEY = 0x4A41525649531001
"""Fester Schlüssel für ``pg_advisory_xact_lock``. Serialisiert das Anfügen."""


class AuditEntry(BaseModel):
    """Ein Audit-Eintrag vor dem Schreiben.

    ``user_id`` ist absichtlich **nicht** Teil der gehashten Nutzlast (siehe
    Modulkopf), steht aber im Modell, weil es persistiert wird.
    """

    model_config = ConfigDict(frozen=True)

    occurred_at: datetime
    """Wird in Python gesetzt, nicht von der Datenbank.

    Ein ``server_default=now()`` wäre hier falsch: Der Hash entsteht vor dem
    INSERT: Der gehashte und der gespeicherte Zeitstempel müssen identisch sein.
    """

    actor: str = Field(min_length=1, max_length=80)
    """'user' | 'jarvis' | 'scheduler' | 'plugin:<name>'"""

    action: str = Field(min_length=1, max_length=80)
    resource: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    trace_id: str | None = None
    user_id: UUID | None = None


def canonical_payload(entry: AuditEntry) -> bytes:
    """Kanonische Byte-Darstellung der gehashten Felder.

    Kanonisch heißt: sortierte Schlüssel, keine Leerzeichen, UTF-8, Zeitstempel
    in ISO-8601 mit Zeitzone. Ohne diese Festlegung liefern zwei
    Serialisierungen desselben Eintrags verschiedene Hashes — und eine
    Kettenprüfung, die zufällig scheitert, wird ignoriert.
    """
    payload = {
        "occurred_at": entry.occurred_at.isoformat(),
        "actor": entry.actor,
        "action": entry.action,
        "resource": entry.resource,
        "details": entry.details,
        "trace_id": entry.trace_id,
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def compute_entry_hash(entry: AuditEntry, prev_hash: bytes | None) -> bytes:
    """``SHA-256(prev_hash || kanonische Nutzlast)``."""
    previous = prev_hash if prev_hash is not None else GENESIS_HASH
    if len(previous) != 32:
        raise ValueError(f"prev_hash muss 32 Byte lang sein, ist {len(previous)}")
    return hashlib.sha256(previous + canonical_payload(entry)).digest()


class ChainBreak(BaseModel):
    """Ein erkannter Bruch in der Kette."""

    model_config = ConfigDict(frozen=True)

    row_id: int
    reason: str
    expected: str
    found: str

    def __str__(self) -> str:
        return f"Eintrag {self.row_id}: {self.reason} (erwartet {self.expected}, gefunden {self.found})"


class StoredAuditRow(BaseModel):
    """Wie ein Eintrag aus der Datenbank zurückkommt."""

    model_config = ConfigDict(frozen=True)

    id: int
    occurred_at: datetime
    actor: str
    action: str
    resource: str | None
    details: dict[str, Any]
    trace_id: str | None
    prev_hash: bytes | None
    entry_hash: bytes

    def as_entry(self) -> AuditEntry:
        return AuditEntry(
            occurred_at=self.occurred_at,
            actor=self.actor,
            action=self.action,
            resource=self.resource,
            details=self.details,
            trace_id=self.trace_id,
        )


def verify_chain(rows: list[StoredAuditRow]) -> list[ChainBreak]:
    """Prüft eine nach ``id`` aufsteigend sortierte Kette.

    Leere Liste bedeutet: unversehrt. Es werden *alle* Brüche gemeldet, nicht
    nur der erste — bei einer nachträglichen Manipulation ist die Anzahl
    betroffener Einträge die interessante Information.
    """
    breaks: list[ChainBreak] = []
    expected_prev = GENESIS_HASH

    for row in rows:
        stored_prev = row.prev_hash if row.prev_hash is not None else GENESIS_HASH
        if stored_prev != expected_prev:
            breaks.append(
                ChainBreak(
                    row_id=row.id,
                    reason="Verweis auf Vorgänger stimmt nicht",
                    expected=expected_prev.hex()[:16],
                    found=stored_prev.hex()[:16],
                )
            )

        recomputed = compute_entry_hash(row.as_entry(), stored_prev)
        if recomputed != row.entry_hash:
            breaks.append(
                ChainBreak(
                    row_id=row.id,
                    reason="Inhalt wurde nach dem Schreiben verändert",
                    expected=recomputed.hex()[:16],
                    found=row.entry_hash.hex()[:16],
                )
            )

        # Für die Fortsetzung wird der *gespeicherte* Hash verwendet, nicht der
        # neu berechnete: Sonst würde ein einzelner manipulierter Eintrag alle
        # folgenden ebenfalls als gebrochen melden und der eigentliche Ort der
        # Manipulation ginge im Rauschen unter.
        expected_prev = row.entry_hash

    return breaks


class AuditSink(Protocol):
    """Port für das Schreiben von Audit-Einträgen.

    Implementierungen müssen das Anfügen serialisieren (Advisory Lock) und
    ``prev_hash`` innerhalb derselben Transaktion lesen, in der geschrieben
    wird.
    """

    async def append(self, entry: AuditEntry) -> bytes:
        """Schreibt den Eintrag und gibt seinen ``entry_hash`` zurück."""
        ...

    async def verify(self, *, limit: int | None = None) -> list[ChainBreak]:
        """Prüft die Kette."""
        ...
