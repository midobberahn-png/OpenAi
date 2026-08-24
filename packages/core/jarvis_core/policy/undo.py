"""Rücknahme: die Zusage „das kannst du rückgängig machen" einlösen.

``ToolResult.undo_token`` war ein Vertragsfeld, das niemand setzte und kein
Endpunkt entgegennahm. Deshalb stand ``calendar.create`` auf
``supports_undo=False`` — der Wert speist ``ActionPreview.reversible``, also den
Satz, den ein Mensch **vor** seiner Bestätigung liest. Eine Vorschau, die
Umkehrbarkeit verspricht, während nichts umkehren kann, senkt die Aufmerksamkeit
genau dort, wo die Bestätigung ihren Zweck hat.

Dieses Modul baut den Weg. Damit darf der Wert umgestellt werden — vorher nicht.

**Warum ein eigenes Gate und nicht der bestehende Weg.**

Eine Rücknahme ist eine Wirkung nach außen: Sie löscht einen Termin. Es gibt in
diesem System genau einen Weg zu einer Wirkung, und der führt durch ein Gate,
das eine nicht fälschbare Erlaubnis ausstellt (``policy-single-entry-point``).
Eine Rücknahme daran vorbei wäre ein zweiter Weg — und zwar ausgerechnet einer,
der löscht.

Der bestehende Weg passt trotzdem nicht: ``ExecutionGrant`` autorisiert *einen
Aufruf mit diesen Argumenten*, geprüft gegen einen Payload-Hash und eine
Policy-Entscheidung über einen Scope. Eine Rücknahme hat keine Argumente, die
ein Mensch bestätigt hätte, und kein Scope beschreibt sie: Wer
``calendar.create`` darf, darf deswegen nicht ``calendar.delete`` — und wer sie
über ein Undo bekäme, hätte das Löschrecht durch die Hintertür.

**Zwei Übergänge, zwei Ansprüche.** Dieses Gate sichert den ersten:

    protokollierter Aufruf → UndoGrant     ``claim_undo``   (hier)
    UndoGrant → Undo-Handler               ``consume_undo`` (Registry)

Der zweite fehlte in der ersten Fassung, und eine externe Prüfung zu
``61d4428`` hat ihn benannt: Wer die ausgestellte Erlaubnis behält, legt sie
erneut vor — Typ, Nutzer und Werkzeugname gelten unverändert. Der Anspruch am
Gate trägt die *Ausstellung*, nicht die *Wiedervorlage*.

**Die Antwort ist Verengung statt Erlaubnis.** Eine Rücknahme kann

* nur einen **protokollierten, ausgeführten** Aufruf treffen,
* nur den **eigenen** (die Zugehörigkeit kommt aus dem Lauf, nicht aus dem
  Request),
* nur innerhalb von ``UNDO_TTL``,
* nur **einmal**,
* und nur das, was das Werkzeug selbst als seinen Rücknahmepunkt notiert hat —
  der Token stammt aus der Datenbank und nie vom Aufrufer.

Damit ist sie kein Löschrecht, sondern die Rücknahme genau dieser einen
Wirkung. Das ist der Unterschied, an dem die ganze Zulässigkeit hängt, und
deshalb steht er hier und nicht in einem Kommentar an der Route.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from jarvis_core.ports.invocations import InvocationStore, UndoClaim

__all__ = ["UndoDenied", "UndoGateway", "UndoGrant"]


_UNDO_SENTINEL = object()
"""Nur dieses Modul besitzt den Wert. Siehe ``UndoGrant``."""


class UndoDenied(Exception):
    """Die Rücknahme ist nicht zulässig — und es ist nichts geschehen.

    Ein Grund und kein Detail: Ob es den Aufruf nicht gibt, ob er einem anderen
    gehört, ob die Frist abgelaufen ist oder ob schon jemand zurückgenommen hat,
    ist für den Aufrufer dieselbe Auskunft — „nicht jetzt, nicht du". Die
    Unterscheidung nach außen zu tragen hieße, einem Fremden zu bestätigen, dass
    es einen Aufruf mit dieser Kennung gibt.
    """


class UndoGrant(BaseModel):
    """Erlaubnis, **einen** protokollierten Aufruf zurückzunehmen.

    Dieselbe Bauart wie ``ExecutionGrant`` und aus demselben Grund: Die Registry
    gibt keinen Undo-Handler heraus; wer zurücknehmen will, braucht dieses
    Objekt, und es entsteht ausschließlich in ``UndoGateway.authorize()``.

    Der Sentinel macht die Konstruktion unbequem; die eigentliche Absicherung
    ist der AST-Test, der jeden Aufruf außerhalb dieses Moduls meldet — dieselbe
    Ehrlichkeit wie beim Ausführungs-Grant.

    **Der Token steht hier und kommt nicht vom Aufrufer.** Er stammt aus der
    Zeile, die das Gate soeben beansprucht hat. Käme er aus dem Request, wäre
    dieses Objekt eine Fähigkeit, die sich raten lässt.
    """

    model_config = ConfigDict(frozen=True)

    tool_name: str
    undo_token: str
    invocation_id: UUID
    user_id: UUID
    granted_at: datetime

    def __init__(self, /, _sentinel: object = None, **data: Any) -> None:
        if _sentinel is not _UNDO_SENTINEL:
            raise RuntimeError(
                "UndoGrant darf nur vom UndoGateway erzeugt werden. Ein selbst gebauter "
                "Grant wäre die Umgehung des Rücknahme-Gates — und damit ein Löschweg "
                "ohne Zugehörigkeitsprüfung."
            )
        super().__init__(**data)

    @classmethod
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> UndoGrant:
        """Gesperrt wie beim Ausführungs-Grant: ``model_construct`` ruft
        ``__init__`` nicht auf und liefe am Wächter vorbei."""
        raise RuntimeError(
            "UndoGrant.model_construct() ist gesperrt — es umginge den Wächter im "
            "Konstruktor. Grants entstehen ausschließlich im UndoGateway."
        )


class UndoGateway:
    """Das Rücknahme-Gate: beansprucht, prüft, stellt aus."""

    def __init__(self, invocations: InvocationStore) -> None:
        self._invocations = invocations

    async def authorize(self, invocation_id: UUID, *, user_id: UUID, now: datetime) -> UndoGrant:
        """Beansprucht die Rücknahme und gibt die Erlaubnis dazu aus.

        **Der Anspruch entsteht vor der Wirkung, nicht danach.** Dieselbe
        Überlegung wie beim Grant-Verbrauch und beim Planschritt: Ein
        ``prüfen … zurücknehmen … vermerken`` ist bei zwei gleichzeitigen
        Anfragen zwei Rücknahmen. Der Speicher setzt deshalb den Zustand in
        derselben Anweisung, in der er ihn liest — und genau einer gewinnt.

        Wer verliert, bekommt ``UndoDenied``. Dass die zweite Rücknahme eines
        gelöschten Termins folgenlos *wäre*, ist eine Eigenschaft dieses
        Werkzeugs und keine des Weges; ein Weg, der sich auf sie verließe,
        wäre beim nächsten Werkzeug falsch.

        **Was dieser Anspruch nicht leistet:** Er endet mit der Ausstellung.
        Die ausgestellte Erlaubnis ein zweites Mal vorzulegen verhindert erst
        der Verbrauch in ``ToolRegistry.undo()`` — und zwar unmittelbar vor dem
        Handler, aus demselben Grund wie beim Ausführungs-Grant.

        ``user_id`` kommt von der Kante aus der Sitzung. Sie geht **in die
        Abfrage** und nicht in eine Prüfung darüber: Eine Zugehörigkeit, die
        sich weglassen lässt, wird irgendwann weggelassen.
        """
        anspruch: UndoClaim | None = await self._invocations.claim_undo(
            invocation_id, user_id=user_id, now=now
        )
        if anspruch is None:
            raise UndoDenied(
                "Dieser Vorgang lässt sich nicht zurücknehmen: Er gehört nicht dir, ist "
                "nicht ausgeführt worden, wurde bereits zurückgenommen — oder die Frist "
                "ist abgelaufen."
            )
        if not anspruch.undo_token:
            # Der Aufruf ist zurücknehmbar geführt, hat aber keinen
            # Rücknahmepunkt hinterlassen. Das ist ein Fehler im Werkzeug und
            # keiner des Nutzers; er darf trotzdem nicht durchgehen, sonst
            # riefe der Handler mit leerem Token irgendetwas auf.
            raise UndoDenied(
                "Zu diesem Vorgang ist kein Rücknahmepunkt vermerkt. Das Werkzeug hat "
                "keinen hinterlassen; zurücknehmen lässt sich damit nichts."
            )

        return UndoGrant(
            _UNDO_SENTINEL,
            tool_name=anspruch.tool_name,
            undo_token=anspruch.undo_token,
            invocation_id=invocation_id,
            user_id=user_id,
            granted_at=now,
        )
