"""Das Aktivitätsprotokoll lesen und die Kette prüfen.

Eine hash-verkettete Spur, die niemand prüfen kann, ist eine Behauptung. Der
Bruch wird nicht dadurch sichtbar, dass er existiert, sondern dadurch, dass
jemand nachrechnet — und das muss ohne Datenbankzugang gehen, sonst tut es
niemand.

**Was hier ausdrücklich nicht steht: ein Schreibweg.** Einträge entstehen dort,
wo etwas geschieht (``ToolExecutor``, die Bestätigungsroute, die
Berechtigungsroute). Ein Endpunkt, über den sich ein Eintrag anlegen ließe,
wäre die Möglichkeit, eine Spur zu erfinden — und damit das Gegenteil dessen,
wofür die Kette gebaut ist.

**Und keine Löschung.** Die Tabelle ist per Trigger append-only; die einzige
zugelassene Änderung ist die Pseudonymisierung (``user_id → NULL``) für eine
DSGVO-Löschung, und die berührt den Hash nicht. Ein Endpunkt dafür gehört zum
Löschkonzept und nicht hierher.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel

from jarvis_api.deps import Audit, AuditReader, CurrentSession

__all__ = ["router"]

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditRow(BaseModel):
    """Ein Eintrag, wie ihn ein Mensch liest."""

    id: int
    occurred_at: datetime
    actor: str
    action: str
    resource: str | None
    details: dict[str, Any]
    entry_hash: str
    """Gekürzt auf 16 Zeichen: Er dient dem Wiederfinden einer Zeile, nicht der
    Nachrechnung — die läuft serverseitig über die vollen 32 Byte."""


class ChainStatus(BaseModel):
    """Das Ergebnis der Kettenprüfung."""

    intact: bool
    checked: int
    breaks: list[str]
    """Als Sätze und nicht als Struktur: Wer diese Antwort liest, will wissen,
    *was* nicht stimmt. Die Struktur steht im Kern (``ChainBreak``), und wer
    sie braucht, liest dort."""


@router.get("/verify", response_model=ChainStatus)
async def verify_chain_endpoint(
    session: CurrentSession,
    audit: Audit,
    limit: int | None = Query(default=None, ge=1, le=100_000),
) -> ChainStatus:
    """Rechnet die Kette nach.

    **Ohne ``limit`` wird alles geprüft**, und nur das beantwortet die Frage
    „ist irgendetwas verändert worden?". Ein Ausschnitt beantwortet „ist seit
    Eintrag N etwas verändert worden?" — eine andere und schwächere Frage, die
    hier trotzdem angeboten wird, weil ein wachsendes Protokoll sonst irgendwann
    nur noch nachts prüfbar wäre.

    **Warum die Antwort nicht nach Nutzern getrennt ist.** Die Kette ist eine
    Eigenschaft des Systems, nicht einer Person: Ein fremder Eintrag dazwischen
    gehört zur Kette und wird mitgerechnet. Dieses System hat einen Nutzer; wenn
    es mehrere bekommt, gehört diese Auskunft an eine Rolle und nicht an jede
    Sitzung.
    """
    brueche = await audit.verify(limit=limit)
    return ChainStatus(
        intact=not brueche,
        checked=await audit.count(limit=limit),
        breaks=[str(bruch) for bruch in brueche],
    )


@router.get("", response_model=list[AuditRow])
async def list_audit(
    session: CurrentSession,
    reader: AuditReader,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[AuditRow]:
    """Die jüngsten Einträge, neueste zuerst — das Aktivitätsprotokoll.

    Zeigt **eigene** Einträge. Anders als die Kettenprüfung, die das ganze
    System betrifft: Hier geht es um Auskunft an einen Menschen darüber, was in
    seinem Namen geschehen ist.
    """
    return [
        AuditRow(
            id=zeile.id,
            occurred_at=zeile.occurred_at,
            actor=zeile.actor,
            action=zeile.action,
            resource=zeile.resource,
            details=zeile.details,
            entry_hash=zeile.entry_hash.hex()[:16],
        )
        for zeile in await reader.for_user(session.user_id, limit=limit)
    ]
