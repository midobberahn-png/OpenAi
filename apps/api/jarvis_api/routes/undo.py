"""Rücknahme eines ausgeführten Aufrufs.

``ToolResult.undo_token`` war ein Vertragsfeld, das niemand setzte und kein
Endpunkt entgegennahm — und deshalb stand ``calendar.create`` auf
``supports_undo=False``. Der Wert speist ``ActionPreview.reversible``, also den
Satz „das kannst du rückgängig machen“, den ein Mensch **vor** seiner
Bestätigung liest; ein Versprechen ohne Weg senkt die Aufmerksamkeit genau
dort, wo die Bestätigung ihren Zweck hat. Dies ist der Weg.

**Was diese Datei entscheidet: nichts.** Sie löst die Kennung auf, gibt die
Identität aus der Sitzung weiter und übersetzt den Ausgang. Ob zurückgenommen
werden darf, entscheidet ``UndoGateway`` — Zugehörigkeit, Frist, Anspruch —,
und was zurückgenommen wird, steht in der Zeile, die es beansprucht hat.

**Der Aufrufer nennt nur die Kennung des Aufrufs.** Kein Token, kein
Werkzeugname, keine Terminkennung. Alles, was die Rücknahme braucht, kommt aus
der Datenbank; alles, was sie einschränkt, ebenfalls. Ein Token im Request wäre
eine Fähigkeit, die sich raten oder abfangen lässt — und sie zeigte auf ein
Löschen.

**Ein Statuscode für vier Lagen.** Nicht dein Aufruf, nicht ausgeführt, schon
zurückgenommen, Frist abgelaufen: Alle vier ergeben ``409`` mit demselben Satz.
Die Unterscheidung nach außen zu tragen hieße, einem Fremden zu bestätigen,
dass es einen Aufruf mit dieser Kennung gibt — dieselbe Überlegung wie bei
``404`` für fremde Bestätigungen.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from jarvis_api.deps import Audit, CurrentSession, Invocations, Tools
from jarvis_core.audit.chain import AuditEntry
from jarvis_core.orchestrator import utc_now
from jarvis_core.policy.undo import UndoDenied, UndoGateway
from jarvis_core.tools.registry import ForgedAuthorization, UnknownTool

__all__ = ["router"]

router = APIRouter(prefix="/invocations", tags=["undo"])


class UndoResult(BaseModel):
    """Was aus der Rücknahme geworden ist.

    ``undone`` sagt, ob der Weg beschritten wurde; ``display`` sagt, was dabei
    herauskam. Die beiden fallen auseinander, wenn das Werkzeug scheitert:
    Der Anspruch ist dann verbraucht — ein zweiter Versuch trifft die Zeile
    nicht mehr —, und der Termin steht möglicherweise noch. Das steht hier so,
    weil ein Feld, das beides zusammenfasst, die unangenehme Hälfte verschweigt.
    """

    undone: bool
    display: str
    tool_name: str


@router.post("/{invocation_id}/undo", response_model=UndoResult)
async def undo_invocation(
    invocation_id: UUID,
    session: CurrentSession,
    invocations: Invocations,
    tools: Tools,
    audit: Audit,
) -> UndoResult:
    """Nimmt einen eigenen, ausgeführten Aufruf innerhalb der Frist zurück."""
    try:
        grant = await UndoGateway(invocations).authorize(
            invocation_id,
            # Aus der Sitzung und nicht aus dem Request — die einzige Stelle,
            # an der eine Identität entsteht (``identity-derives-from-session``).
            user_id=session.user_id,
            now=utc_now(),
        )
    except UndoDenied as abgelehnt:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(abgelehnt)
        ) from abgelehnt

    try:
        ergebnis = await tools.undo(grant, user_id=session.user_id)
    except UnknownTool as unbekannt:
        # Der Aufruf ist als zurücknehmbar protokolliert, dieser Prozess kennt
        # die Rücknahme aber nicht — ein Konfigurationsfehler. Der Anspruch ist
        # dabei bereits verbraucht; das ist der Preis dafür, ihn vor der
        # Wirkung zu setzen, und die richtige Richtung: lieber eine Rücknahme
        # zu wenig als zwei.
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(unbekannt)
        ) from unbekannt
    except ForgedAuthorization as gefaelscht:  # pragma: no cover - Gate baut den Grant selbst
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(gefaelscht)
        ) from gefaelscht

    # **Eine Rücknahme ist eine Wirkung und gehört in die Spur.** Aufgefallen
    # beim Schreiben des Browsertests: Der Executor protokolliert jede
    # Ausführung, dieser Weg lief daran vorbei — die Kette hätte einen
    # gelöschten Termin nicht bezeugt.
    #
    # ``ok`` steht im Eintrag, weil der Anspruch vor dem Handler verbraucht
    # wird: „zurückgenommen" und „es wurde versucht" sind hier zwei
    # verschiedene Aussagen, und die Spur soll die richtige tragen.
    await audit.append(
        AuditEntry(
            occurred_at=utc_now(),
            actor="user",
            action="tool.undone" if ergebnis.ok else "tool.undo_failed",
            resource=grant.tool_name,
            details={
                "invocation_id": str(grant.invocation_id),
                "display": ergebnis.display or (ergebnis.error or ""),
            },
            user_id=session.user_id,
        )
    )

    return UndoResult(
        undone=ergebnis.ok,
        display=ergebnis.display or (ergebnis.error or ""),
        tool_name=grant.tool_name,
    )
