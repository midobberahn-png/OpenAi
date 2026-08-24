"""Berechtigungen ansehen, erteilen, zurückziehen.

**Der Befund, aus dem diese Datei entstand:** Es gab keinen Weg, eine
Berechtigung zu erteilen. Der Speicher konnte lesen, eine Route existierte
nicht — jede Berechtigung dieses Systems entstand per ``INSERT`` von Hand, auch
in jedem Test. Damit war das Permission Center (docs/10-ui.md §6) nicht nur
ungebaut, sondern unbaubar: Eine Oberfläche kann nicht anbieten, was die API
nicht kann.

Das ist mehr als eine fehlende Bequemlichkeit. Der gesamte Sicherheitssockel
steht auf der Aussage „der Nutzer hat das erteilt". Solange niemand erteilen
kann, ist diese Aussage über jede Berechtigung eine Behauptung über eine
Datenbankzeile, die irgendwer geschrieben hat.

**Die gefährliche Richtung ist das Erteilen.**

Zurückziehen kann nichts öffnen. Erteilen öffnet alles, was daran hängt: Ein
Scope auf ``allow`` nimmt jede künftige Bestätigung aus dem Weg — genau den
Dialog, den ein Mensch liest, bevor etwas nach außen wirkt. Deshalb gilt hier
dieselbe Regel wie überall, nur mit mehr Gewicht:

* Die Identität kommt aus der Sitzung, nie aus dem Request.
* Der Scope muss im Katalog stehen. Ein erfundener wäre eine Berechtigung für
  nichts — oder schlimmer: eine, die ein künftiges Werkzeug still vorfindet.
* Die Einschränkungen werden gegen die **scope-eigene** Klasse geprüft
  (``constraints_for``). Eine ``files.read``-Berechtigung kann keine
  Empfängerliste tragen, und eine Pfadgrenze fällt nicht durch, weil sie
  falsch geschrieben ist.
* Was gesetzt wird, gilt **vollständig**. Wer eine Berechtigung ändert, setzt
  sie neu — inklusive der Einschränkungen, die er nicht mitschickt.

**Und was hier ausdrücklich nicht steht: ein Werkzeug.** Es gibt in diesem
System kein ``permissions.grant``, und das ist keine Auslassung. Ein Werkzeug,
das Berechtigungen schreibt, wäre der kürzeste Weg von „ein Modell hat
Fremdinhalt gelesen" zu „das Modell darf jetzt mehr" — die Rechteerteilung
gehört an die Kante, an der ein Mensch sitzt. Ein Strukturtest hält das fest.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, ValidationError

from jarvis_api.deps import CurrentSession, Permissions
from jarvis_contracts import PermissionGrant, PermissionMode, RiskLevel, constraints_for
from jarvis_core.clock import utc_now

__all__ = ["router"]

router = APIRouter(prefix="/permissions", tags=["permissions"])

_log = structlog.get_logger(__name__)
"""Jede Änderung wird protokolliert, und zwar mit *beiden* Modi.

„Auf ``allow`` gesetzt" ist eine andere Auskunft als „von ``deny`` auf
``allow`` gehoben". Die Audit-Kette (``jarvis_core.audit``) wäre der richtige
Ort dafür; sie ist im Betrieb bislang nirgends verdrahtet, und bis dahin ist
ein strukturiertes Protokoll besser als nichts. Der Nachtrag steht im Dossier."""


class ScopeView(BaseModel):
    """Ein Scope mit dem, was der Nutzer dazu entschieden hat — oder nicht."""

    name: str
    description: str
    risk_level: RiskLevel
    default_mode: PermissionMode
    """Die **Empfehlung** des Katalogs, nicht die Erteilung. Eine Oberfläche,
    die beides gleich darstellt, zeigt Rechte an, die niemand vergeben hat."""

    granted: GrantView | None = None
    """``None`` heißt: nicht erteilt. Nicht: verboten, und nicht: erlaubt."""


class GrantView(BaseModel):
    mode: PermissionMode
    constraints: dict[str, Any]
    granted_at: datetime
    expires_at: datetime | None = None
    expired: bool
    """Abgelaufen, aber noch vorhanden — ausgerechnet dieser Zustand ist der
    verwirrendste, wenn ihn niemand benennt."""


class SetGrantRequest(BaseModel):
    """Was ein Nutzer über einen Scope entscheidet.

    Kein ``scope``-Feld: Der Scope steht im Pfad. Zwei Angaben desselben
    Gegenstands sind eine Gelegenheit, sie auseinanderlaufen zu lassen.
    """

    mode: PermissionMode
    constraints: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None


ScopeView.model_rebuild()


@router.get("", response_model=list[ScopeView])
async def list_permissions(session: CurrentSession, permissions: Permissions) -> list[ScopeView]:
    """Der ganze Katalog, mit dem Stand des angemeldeten Nutzers.

    **Der Katalog und nicht nur das Erteilte.** „Darf JARVIS Mails senden?"
    beantwortet gerade der Scope, zu dem nichts erteilt ist; eine Liste, die
    ihn nicht führt, kann die Frage nicht stellen.
    """
    jetzt = utc_now()
    erteilt = {g.scope: g for g in await permissions.grants_for(session.user_id)}

    return [
        ScopeView(
            name=eintrag.name,
            description=eintrag.description,
            risk_level=eintrag.risk_level,
            default_mode=eintrag.default_mode,
            granted=_als_sicht(erteilt[eintrag.name], jetzt) if eintrag.name in erteilt else None,
        )
        for eintrag in await permissions.catalog()
    ]


@router.put("/{scope}", response_model=GrantView)
async def set_permission(
    scope: str,
    payload: SetGrantRequest,
    session: CurrentSession,
    permissions: Permissions,
) -> GrantView:
    """Erteilt, ändert oder verweigert einen Scope — vollständig.

    Ein ``PUT`` und kein ``PATCH``, und das ist bedeutungstragend: Was hier
    steht, gilt danach. Ein Zusammenführen mit dem alten Stand wäre die Art von
    Bequemlichkeit, bei der eine Pfadgrenze aus der Vorwoche eine neue
    Erteilung still erweitert.
    """
    katalog = {e.name for e in await permissions.catalog()}
    if scope not in katalog:
        # Kein Geheimnis: Der Katalog beschreibt das System und nicht den
        # Nutzer. Wer einen erfundenen Scope nennt, soll das erfahren, statt
        # eine Berechtigung für nichts zu bekommen — die ein künftiges Werkzeug
        # still vorfände.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unbekannter Scope: {scope!r}.",
        )

    try:
        einschraenkungen = constraints_for(scope, payload.constraints)
    except ValidationError as unpassend:
        # Die scope-eigene Klasse verbietet zusätzliche Felder. Eine
        # ``files.read``-Berechtigung mit Empfängerliste ist damit nicht
        # darstellbar — und eine Pfadgrenze, die falsch geschrieben ist, fällt
        # hier auf und nicht erst dann, wenn sie nicht mehr greift.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Einschränkungen passen nicht zu {scope!r}: {unpassend.error_count()} Fehler.",
        ) from unpassend

    vorher = next(
        (g for g in await permissions.grants_for(session.user_id) if g.scope == scope), None
    )
    grant = PermissionGrant(
        scope=scope,
        mode=payload.mode,
        constraints=einschraenkungen,
        granted_at=utc_now(),
        expires_at=payload.expires_at,
    )
    await permissions.upsert_grant(session.user_id, grant)

    _log.info(
        "berechtigung.gesetzt",
        scope=scope,
        user_id=str(session.user_id),
        vorher=str(vorher.mode) if vorher else None,
        nachher=str(grant.mode),
        # Die Richtung ist die interessante Angabe: Erteilen öffnet, Zurücknehmen
        # nicht. Wer ein Protokoll durchsieht, sucht die Erweiterungen.
        erweitert=_erweitert(vorher, grant),
        expires_at=grant.expires_at.isoformat() if grant.expires_at else None,
    )
    return _als_sicht(grant, utc_now())


@router.delete("/{scope}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_permission(scope: str, session: CurrentSession, permissions: Permissions) -> None:
    """Zieht eine Berechtigung zurück.

    ``204`` auch dann, wenn es nichts zurückzuziehen gab: Danach gilt in beiden
    Fällen dasselbe — der Nutzer hat dieses Recht nicht erteilt. Ein ``404``
    wäre eine Auskunft darüber, was jemand erteilt hat, und die gehört nicht in
    einen Statuscode.

    **Sofort wirksam.** Die Policy Engine liest bei jedem Aufruf neu; ein Lauf,
    der gerade zwischen zwei Schritten steht, findet das Recht beim nächsten
    nicht mehr vor.
    """
    entfernt = await permissions.revoke_grant(session.user_id, scope)
    _log.info(
        "berechtigung.zurueckgezogen",
        scope=scope,
        user_id=str(session.user_id),
        vorhanden=entfernt,
    )


def _als_sicht(grant: PermissionGrant, jetzt: datetime) -> GrantView:
    return GrantView(
        mode=grant.mode,
        constraints=grant.constraints.model_dump(mode="json", exclude_none=True),
        granted_at=grant.granted_at,
        expires_at=grant.expires_at,
        expired=not grant.is_valid_at(jetzt),
    )


def _erweitert(vorher: PermissionGrant | None, nachher: PermissionGrant) -> bool:
    """Öffnet diese Änderung mehr, als vorher offen war?

    Die Rangfolge ist ``deny < confirm < allow``; „nicht erteilt" liegt darunter,
    weil ohne Erteilung nichts läuft. Eine Verschärfung ist unbedenklich, eine
    Lockerung ist der Vorgang, den man im Protokoll sucht.
    """
    rang = {PermissionMode.DENY: 0, PermissionMode.CONFIRM: 1, PermissionMode.ALLOW: 2}
    return rang[nachher.mode] > (rang[vorher.mode] if vorher else -1)
