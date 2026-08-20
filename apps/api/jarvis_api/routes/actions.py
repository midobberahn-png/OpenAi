"""Bestätigungs-Endpunkte.

Bis hierher gab es **keinen Weg, eine Bestätigung zu erteilen**. Der gesamte
Mechanismus stand — Nonce, Payload-Hash, Sitzungsbindung, Kanalbindung,
Ausführungsanspruch —, nur konnte niemand auf „Ja" klicken. Jede Aktion mit
Außenwirkung hängt daran.

**Was hier entschieden wird und was nicht.** Diese Datei entscheidet über
*Sichtbarkeit*: Wem eine Bestätigung nicht gehört, für den existiert sie
nicht (404). Über *Gültigkeit* entscheidet weiterhin ausschließlich
``ApprovalGateway.respond()`` — Nonce, Ablauf, Kanal, Sitzungsbindung und der
atomare Verbrauch liegen dort und werden hier nicht wiederholt. Das ist keine
doppelte Prüfung, sondern eine geschichtete: Die Grenze verhindert Auskunft,
der Kern verhindert Wirkung. Wären beide dieselbe Prüfung, gäbe es zwei
Wahrheiten über Bestätigungen, und die zweite prüfte niemand.

**Der Kanal kommt nicht aus dem Request.** ``PendingAction.allows_channel()``
ist eine Sicherheitsprüfung: Eine Aktion, die per Sprache nicht bestätigt
werden darf, darf es auch dann nicht, wenn der Aufrufer „ui" behauptet. Der
Kanal beschreibt, wie die Antwort tatsächlich hereinkam — über diese Route
ist das die Oberfläche. Ihn als Feld anzubieten hieße, den Angreifer nach
seinem Kanal zu fragen.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from jarvis_api.db.approval_store import PostgresApprovalStore
from jarvis_api.deps import ActionStore, Approvals, CurrentSession, SessionToken
from jarvis_contracts import ApprovalChannel, PendingAction, Session
from jarvis_core.orchestrator import utc_now

__all__ = ["router"]

router = APIRouter(prefix="/actions", tags=["approvals"])

KANAL: ApprovalChannel = "ui"
"""Der Kanal dieser Route — eine Eigenschaft des Transportwegs, kein Parameter."""


# --------------------------------------------------------------------------
# Ein- und Ausgaben
# --------------------------------------------------------------------------


class PreviewFieldView(BaseModel):
    """Ein Feld der Vorschau, so wie es angezeigt und bestätigt wird."""

    label: str
    value: str
    emphasis: str
    truncated: bool


class ActionView(BaseModel):
    """Eine offene Bestätigung, wie die Oberfläche sie zeigt.

    Ohne ``invocation_id``: Sie ist der Anker des Grant-Verbrauchs und hat in
    einer Antwort nichts zu suchen — ein Strukturtest führt sie deshalb unter
    den Identitätsfeldern. Ohne ``user_id`` und ``session_id`` aus demselben
    Grund; wer fragt, steht fest.
    """

    id: str
    run_id: str
    tool_name: str
    risk: str
    reason: str
    requested_channel: str
    preview_title: str
    preview_fields: list[PreviewFieldView]
    """Die Vorschau, Feld für Feld — dieselbe Struktur, die bestätigt wird.

    Sie wird aus den validierten Argumenten gebaut, nicht aus einer vom Modell
    formulierten Beschreibung. Eine Zusammenfassung als Fließtext hier wäre ein
    zweiter Ort, an dem der Inhalt entsteht, und damit die Stelle, an der
    Anzeige und Ausführung auseinandergehen können.
    """

    reversible: bool
    warnings: list[str]
    expires_at: datetime
    nonce: str | None
    """Nur für Bestätigungen **dieser** Sitzung.

    Eine Bestätigung ist an die Sitzung gebunden, in der sie angefordert wurde;
    ``respond()`` weist eine fremde ohnehin ab. Die Nonce trotzdem
    herauszugeben, wäre die Preisgabe eines Geheimnisses, mit dem der
    Empfänger nichts anfangen darf — und der einzige Zweck der Liste ist zu
    zeigen, was offen ist, nicht was anderswo einlösbar wäre.
    """


class RespondRequest(BaseModel):
    """Die Antwort des Menschen. Führt weder Nutzer noch Sitzung noch Kanal."""

    nonce: str = Field(min_length=32, max_length=128)
    approve: bool


class RespondResult(BaseModel):
    approved: bool
    reason: str


def _view(aktion: PendingAction, *, eigene_sitzung: bool) -> ActionView:
    return ActionView(
        id=str(aktion.id),
        run_id=str(aktion.run_id),
        tool_name=aktion.tool_name,
        risk=str(aktion.risk),
        reason=aktion.reason,
        requested_channel=str(aktion.requested_channel),
        preview_title=aktion.preview.title,
        preview_fields=[
            PreviewFieldView(
                label=f.label, value=f.value, emphasis=f.emphasis, truncated=f.truncated
            )
            for f in aktion.preview.fields
        ],
        reversible=aktion.preview.reversible,
        warnings=list(aktion.preview.warnings),
        expires_at=aktion.expires_at,
        nonce=aktion.nonce if eigene_sitzung else None,
    )


async def _eigene_aktion(
    action_id: UUID, session: Session, store: PostgresApprovalStore
) -> PendingAction:
    """Die Bestätigung des angemeldeten Nutzers — oder 404.

    Geprüft wird die Zugehörigkeit zum **Nutzer**, nicht zur Sitzung: Ob die
    richtige Sitzung antwortet, ist eine Frage der Gültigkeit und gehört ins
    Gateway, das sie mit einer sprechenden Begründung beantwortet („bitte dort
    bestätigen, wo die Vorschau angezeigt wurde"). Hier ginge dieselbe Auskunft
    als 404 verloren, und der Nutzer stünde ohne Hinweis da.

    Fremd und nicht vorhanden ergeben dieselbe Antwort — 403 bestätigte die
    Existenz.
    """
    aktion = await store.get(action_id)
    if aktion is None or aktion.user_id != session.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Bestätigung nicht gefunden."
        )
    return aktion


# --------------------------------------------------------------------------
# Endpunkte
# --------------------------------------------------------------------------


@router.get("", response_model=list[ActionView])
async def list_actions(session: CurrentSession, actions: ActionStore) -> list[ActionView]:
    """Offene Bestätigungen des angemeldeten Nutzers."""
    offen = await actions.open_for_user(session.user_id)
    return [_view(a, eigene_sitzung=a.session_id == session.id) for a in offen]


@router.post("/{action_id}/respond", response_model=RespondResult)
async def respond_action(
    action_id: UUID,
    payload: RespondRequest,
    session: CurrentSession,
    token: SessionToken,
    actions: ActionStore,
    approvals: Approvals,
) -> RespondResult:
    """Erteilt oder verweigert eine Bestätigung — genau einmal.

    Die Einmaligkeit trägt die Datenbank (``burn()`` als bedingtes UPDATE),
    nicht diese Route. Zwei gleichzeitige „Ja" ergeben eine Bestätigung und
    eine Abweisung.

    Eine Ablehnung ist kein Fehler: Sie ist eine gültige Antwort und endet mit
    200 und ``approved=false``. Ein 4xx hier würde die Entscheidung des
    Menschen als Störung führen.

    Was die Antwort **nicht** enthält, ist der sanierte Payload. Er entsteht
    im Gateway und ist die Eingabe der Ausführung, nicht Auskunft an den
    Client — der hat den Inhalt in der Vorschau bereits gesehen und
    bestätigt.
    """
    await _eigene_aktion(action_id, session, actions)
    ergebnis = await approvals.respond(
        action_id=action_id,
        nonce=payload.nonce,
        approve=payload.approve,
        user_id=session.user_id,
        session_id=session.id,
        session_token=token,
        channel=KANAL,
        now=utc_now(),
    )
    return RespondResult(approved=ergebnis.approved, reason=ergebnis.reason)
