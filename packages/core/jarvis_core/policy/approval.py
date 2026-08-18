"""Approval Gateway und Ausführungs-Gate.

Siehe docs/07-security-permissions.md §5 und §4a.

Dies ist der sicherheitskritischste Teil des Systems. Vier Invarianten werden
hier durchgesetzt:

* ``payload-immutable-after-approval`` — ausgeführt wird, was in der Vorschau stand
* ``approval-bound-to-payload-hash`` — die Zustimmung gilt einem Inhalt, nicht einer Aktionsart
* ``approval-toctou-protected`` — kein Zeitfenster zwischen Prüfung und Ausführung
* ``approval-nonce-single-use`` — atomar, auch unter Nebenläufigkeit

Der entscheidende Ablauf ist **nicht**::

    Payload → Bestätigung → Payload erneut aus dem Zustand laden → Ausführung

sondern::

    Payload → Kanonisierung → Hash → Bestätigung → Hash-Vergleich → Ausführung

Der Unterschied ist der ganze Punkt: In der ersten Fassung entsteht genau das
Zeitfenster, in dem ein anderer Inhalt untergeschoben werden kann.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from jarvis_contracts import (
    ActionPreview,
    ApprovalChannel,
    PendingAction,
    PolicyEffect,
    PolicyRequest,
    RiskLevel,
    SanitizedPayload,
    TaintLevel,
    ToolSpec,
)
from jarvis_core.policy.engine import PolicyEngine
from jarvis_core.ports.approval import ApprovalStore, BurnResult

__all__ = [
    "DEFAULT_TTL",
    "NONCE_BYTES",
    "ApprovalGateway",
    "ApprovalOutcome",
    "ExecutionDenied",
    "ExecutionGrant",
    "canonical_arguments",
    "payload_hash",
]


DEFAULT_TTL = timedelta(minutes=10)
"""Nach dieser Zeit verfällt eine Bestätigung.

Ohne Ablauf könnte ein Dialog von gestern Abend heute früh noch wirken — der
Nutzer erinnert sich dann nicht mehr, was er freigegeben hat.
"""

NONCE_BYTES = 32
"""256 Bit Entropie. Erraten ist damit kein Angriffsweg."""


def canonical_arguments(arguments: dict[str, Any]) -> bytes:
    """Kanonische Byte-Darstellung der Werkzeugargumente.

    Deterministisch: sortierte Schlüssel, keine Leerzeichen, UTF-8. Ohne diese
    Festlegung ergäbe dieselbe Argumentmenge je nach Serialisierungsreihenfolge
    unterschiedliche Hashes — und der Vergleich vor der Ausführung würde
    zufällig scheitern. Ein Sicherheitsvergleich, der gelegentlich falsch
    Alarm gibt, wird abgeschaltet.
    """
    return json.dumps(
        arguments,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def payload_hash(tool_name: str, arguments: dict[str, Any]) -> str:
    """``SHA-256(tool_name || 0x00 || kanonische Argumente)`` als Hexstring.

    Der Werkzeugname geht mit ein: Sonst ließe sich eine Bestätigung für
    ``calendar.create`` mit identischen Argumenten auf ein anderes Werkzeug
    übertragen.
    """
    digest = hashlib.sha256()
    digest.update(tool_name.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(canonical_arguments(arguments))
    return digest.hexdigest()


class ExecutionDenied(Exception):
    """Das Ausführungs-Gate hat die Ausführung verweigert.

    Wird ausdrücklich als Ausnahme geführt, nicht als Rückgabewert: Ein
    Aufrufer, der den Rückgabewert ignoriert, würde sonst trotzdem ausführen.
    """

    def __init__(self, reason: str, *, code: str) -> None:
        self.reason = reason
        self.code = code
        super().__init__(f"[{code}] {reason}")


_GRANT_SENTINEL = object()
"""Nur dieses Modul besitzt den Wert. Siehe ``ExecutionGrant``."""


class ExecutionGrant(BaseModel):
    """Erlaubnis, genau einen Werkzeugaufruf auszuführen.

    Existiert, damit ein Werkzeug nicht ohne Gate ausführbar ist: Die Registry
    verlangt einen Grant, und der entsteht ausschließlich in
    ``ApprovalGateway.authorize_execution()``.

    Python kann eine Konstruktion nicht wirklich verhindern — der Sentinel
    macht sie unbequem, die eigentliche Absicherung ist der AST-Test in
    ``tests/unit/test_layering.py``, der jeden Aufruf außerhalb dieses Moduls
    als Fehler meldet. Diese Ehrlichkeit ist wichtiger als eine Scheinbarriere.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    tool_name: str
    arguments: dict[str, Any]
    verified_hash: str
    run_id: UUID
    user_id: UUID
    invocation_id: UUID
    granted_at: datetime

    def __init__(self, /, _sentinel: object = None, **data: Any) -> None:
        if _sentinel is not _GRANT_SENTINEL:
            raise RuntimeError(
                "ExecutionGrant darf nur vom ApprovalGateway erzeugt werden. Ein "
                "selbst gebauter Grant wäre die Umgehung des Ausführungs-Gates."
            )
        super().__init__(**data)

    @classmethod
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> ExecutionGrant:
        """Der bequemste Weg am Wächter vorbei — deshalb geschlossen.

        ``model_construct`` ist Pydantics Schnellpfad und ruft ``__init__``
        nicht auf; der Sentinel oben liefe damit ins Leere. Ein Angreifer
        braucht dafür bereits Codeausführung im Prozess und hat dann ohnehin
        andere Wege — aber ein Wächter, an dem eine dokumentierte Methode
        vorbeiführt, ist schlechter als keiner: Er erzeugt Vertrauen, das er
        nicht trägt.
        """
        raise RuntimeError(
            "ExecutionGrant.model_construct() ist gesperrt — es umginge den "
            "Wächter im Konstruktor. Grants entstehen ausschließlich im "
            "ApprovalGateway."
        )


class ApprovalOutcome(BaseModel):
    """Ergebnis einer Bestätigungsantwort."""

    model_config = ConfigDict(frozen=True)

    approved: bool
    reason: str
    sanitized: SanitizedPayload | None = None
    """Gesetzt, wenn die Bestätigung einen kontaminierten Lauf saniert hat."""


class ApprovalGateway:
    """Erzeugt Bestätigungsanfragen und bewacht die Ausführung."""

    def __init__(
        self,
        store: ApprovalStore,
        policy: PolicyEngine,
        *,
        ttl: timedelta = DEFAULT_TTL,
    ) -> None:
        self._store = store
        self._policy = policy
        self._ttl = ttl

    # -- 1. Anfrage ------------------------------------------------------
    async def request(
        self,
        *,
        spec: ToolSpec,
        arguments: dict[str, Any],
        preview: ActionPreview,
        reason: str,
        run_id: UUID,
        invocation_id: UUID,
        user_id: UUID,
        session_id: UUID,
        channel: ApprovalChannel,
        now: datetime,
    ) -> PendingAction:
        """Legt eine Bestätigungsanfrage an — mit eingefrorenem Payload-Hash.

        Der Hash entsteht **hier**, aus denselben Argumenten, aus denen die
        Vorschau gebaut wurde. Würde er erst später gebildet, wäre die Bindung
        wertlos.
        """
        action = PendingAction(
            id=uuid4(),
            run_id=run_id,
            invocation_id=invocation_id,
            user_id=user_id,
            session_id=session_id,
            tool_name=spec.name,
            preview=preview,
            risk=spec.risk,
            reason=reason,
            payload_hash=payload_hash(spec.name, arguments),
            nonce=secrets.token_urlsafe(NONCE_BYTES),
            requested_channel=channel,
            expires_at=now + self._ttl,
            created_at=now,
        )
        await self._store.create(action, arguments)
        return action

    # -- 2. Antwort ------------------------------------------------------
    async def respond(
        self,
        *,
        action_id: UUID,
        nonce: str,
        approve: bool,
        user_id: UUID,
        session_id: UUID,
        channel: ApprovalChannel,
        now: datetime,
    ) -> ApprovalOutcome:
        """Löst eine Bestätigung ein — genau einmal.

        Die Einmaligkeit wird von der Datenbank erzwungen, nicht hier. Ein
        ``if nonce_valid: ... mark_used()`` wäre bei zwei gleichzeitigen
        Anfragen ein Doppelverbrauch; deshalb ein atomares Compare-and-Set.
        """
        action = await self._store.get(action_id)
        if action is None:
            return ApprovalOutcome(approved=False, reason="Bestätigung nicht gefunden.")

        # Bindungsprüfungen vor dem Verbrauch — eine fehlgeschlagene Bindung
        # darf die Nonce nicht entwerten, sonst wäre sie ein Denial-of-Service.
        if action.user_id != user_id:
            return ApprovalOutcome(
                approved=False, reason="Bestätigung gehört zu einem anderen Nutzer."
            )
        if action.session_id != session_id:
            return ApprovalOutcome(
                approved=False,
                reason=(
                    "Bestätigung gehört zu einer anderen Sitzung. Bitte dort bestätigen, "
                    "wo die Vorschau angezeigt wurde."
                ),
            )
        if not action.allows_channel(channel):
            return ApprovalOutcome(
                approved=False,
                reason=self._channel_reason(action, channel),
            )
        if action.is_expired(now):
            await self._store.expire(action_id, now)
            return ApprovalOutcome(
                approved=False,
                reason="Die Bestätigung ist abgelaufen. Bitte den Vorgang erneut anstoßen.",
            )

        burn = await self._store.burn(
            action_id=action_id,
            nonce=nonce,
            response="approved" if approve else "rejected",
            channel=channel,
            now=now,
        )
        if burn is BurnResult.NONCE_MISMATCH:
            return ApprovalOutcome(approved=False, reason="Bestätigung ungültig.")
        if burn is BurnResult.ALREADY_USED:
            return ApprovalOutcome(
                approved=False,
                reason="Diese Bestätigung wurde bereits eingelöst.",
            )
        if burn is BurnResult.EXPIRED:
            return ApprovalOutcome(approved=False, reason="Die Bestätigung ist abgelaufen.")

        if not approve:
            return ApprovalOutcome(approved=False, reason="Vom Nutzer abgelehnt.")

        return ApprovalOutcome(
            approved=True,
            reason="Vom Nutzer bestätigt.",
            sanitized=SanitizedPayload(
                tool_name=action.tool_name,
                arguments=await self._store.frozen_arguments(action_id),
                origin_run_id=action.run_id,
                approved_at=now,
                approved_by=user_id,
                payload_hash=action.payload_hash,
            ),
        )

    # -- 3. Ausführungs-Gate ---------------------------------------------
    async def authorize_execution(
        self,
        *,
        action_id: UUID,
        arguments: dict[str, Any],
        spec: ToolSpec,
        taint: TaintLevel,
        run_id: UUID,
        sanitized_from_run_id: UUID | None = None,
        allowed_data_class: Any = None,
        now: datetime,
    ) -> ExecutionGrant:
        """Letzte Prüfung unmittelbar vor dem Werkzeugaufruf.

        ``run_id`` ist der Lauf, in dem tatsächlich ausgeführt wird — nicht
        zwingend der, in dem bestätigt wurde. Beide auseinanderzuhalten ist
        nötig, weil die Sanierung den bestätigten Payload absichtlich in einem
        *neuen*, sauberen Lauf ausführt. Genau deshalb muss die Beziehung
        geprüft werden: Ohne sie wäre eine Bestätigung aus Lauf A in jedem
        beliebigen Lauf einlösbar, und die Laufbindung des Grants hinge an
        einer Angabe, die niemand kontrolliert.

        Drei Prüfungen, die alle nötig sind:

        1. **Hash-Vergleich.** Der Hash der tatsächlich auszuführenden
           Argumente muss dem entsprechen, der bei der Anfrage festgehalten
           wurde. Damit ist eine Änderung zwischen Klick und Ausführung
           erkennbar — der Angriff, gegen den das Einfrieren gedacht ist.
        2. **Erneute Policy-Prüfung.** Zwischen Bestätigung und Ausführung kann
           sich der Zustand geändert haben: Recht entzogen, Kontamination
           hinzugekommen, Einschränkung verschärft, Werkzeug deaktiviert. Eine
           alte Bestätigung darf keine neue Berechtigung erzeugen.

        Ohne Prüfung 2 wäre die Bestätigung ein Freifahrtschein mit
        zehnminütiger Gültigkeit.
        """
        action = await self._store.get(action_id)
        if action is None:
            raise ExecutionDenied("Bestätigung nicht gefunden.", code="approval-missing")

        if action.response != "approved":
            raise ExecutionDenied(
                "Für diesen Vorgang liegt keine Bestätigung vor.", code="approval-not-granted"
            )

        if action.is_expired(now):
            raise ExecutionDenied(
                "Die Bestätigung ist zwischen Freigabe und Ausführung abgelaufen.",
                code="approval-expired",
            )

        # (0) Laufbindung. Zulässig sind genau zwei Fälle: der Lauf, in dem
        # bestätigt wurde, und der daraus hervorgegangene sanierte Lauf. Alles
        # andere wäre eine Bestätigung, die in einem fremden Zusammenhang
        # wirkt — der Nutzer hat dann etwas anderes freigegeben, als geschieht.
        if run_id != action.run_id and sanitized_from_run_id != action.run_id:
            raise ExecutionDenied(
                "Die Bestätigung gehört zu einem anderen Lauf.",
                code="run-mismatch",
            )

        # (1) Hash-Vergleich
        actual = payload_hash(spec.name, arguments)
        if not secrets.compare_digest(actual, action.payload_hash):
            raise ExecutionDenied(
                "Der auszuführende Inhalt weicht von dem ab, der bestätigt wurde. "
                "Der Vorgang wird abgebrochen.",
                code="payload-mismatch",
            )
        if spec.name != action.tool_name:
            raise ExecutionDenied(
                "Die Bestätigung gilt für ein anderes Werkzeug.", code="tool-mismatch"
            )

        # (2) Erneute Policy-Prüfung
        recheck = await self._policy.decide(
            PolicyRequest(
                user_id=action.user_id,
                run_id=action.run_id,
                tool_name=spec.name,
                arguments=arguments,
                allowed_data_class=allowed_data_class or spec.data_class,
            ),
            taint=taint,
            now=now,
        )
        if recheck.effect is PolicyEffect.DENY:
            raise ExecutionDenied(
                f"Die Berechtigungslage hat sich geändert: {recheck.reason}",
                code="policy-changed",
            )

        return ExecutionGrant(
            _GRANT_SENTINEL,
            tool_name=spec.name,
            arguments=arguments,
            verified_hash=actual,
            # Der *ausführende* Lauf, nicht der bestätigende: Beim sanierten
            # Lauf sind das verschiedene, und die Registry vergleicht gegen den
            # Kontext, in dem tatsächlich gearbeitet wird.
            run_id=run_id,
            user_id=action.user_id,
            invocation_id=action.invocation_id,
            granted_at=now,
        )

    # -- 3b. Ausführungs-Gate ohne Bestätigung ---------------------------
    async def authorize_allowed(
        self,
        *,
        request: PolicyRequest,
        spec: ToolSpec,
        taint: TaintLevel,
        invocation_id: UUID,
        now: datetime,
    ) -> ExecutionGrant:
        """Gate für Aufrufe, die *keine* Bestätigung brauchen.

        Ohne diesen Weg gäbe es für ein unbedenkliches Werkzeug überhaupt keine
        Ausführung: Die Registry verlangt einen Grant, und den erzeugte bisher
        nur der Bestätigungspfad. Die Alternative wäre gewesen, den Orchestrator
        an der Registry vorbei ausführen zu lassen — also genau der zweite Pfad,
        den ``policy-single-entry-point`` ausschließt.

        Entscheidend ist, **wer** hier entscheidet: Die Erlaubnis stammt aus
        einem eigenen ``PolicyEngine.decide()`` in diesem Gate, nicht aus einer
        vom Aufrufer mitgebrachten Entscheidung. Ein Orchestrator, der bereits
        ``ALLOW`` erhalten hat, kann es nicht durchreichen — er kann nur erneut
        fragen lassen. Damit bleibt die Policy Engine die einzige Quelle der
        Erlaubnis, und eine zwischenzeitliche Änderung (entzogenes Recht, neu
        hinzugekommene Kontamination) wirkt auch hier sofort.

        Die verbleibende Angriffsfläche ist der ``PolicyRequest`` selbst: Wer
        ihn baut, bestimmt ``trigger`` und ``allowed_data_class``. Deshalb
        leitet der Executor beide ausschließlich aus dem persistierten ``Run``
        ab und nie aus einer Modellausgabe — belegt in
        ``tests/unit/test_executor.py``.
        """
        if spec.name != request.tool_name:
            # Sonst prüfte die Engine ein Werkzeug und der Grant führte ein
            # anderes aus: ``decide()`` schlägt über ``request.tool_name`` nach,
            # ausgeführt würde ``spec.name``. Ein Aufrufer könnte damit die
            # Erlaubnis für mail.read gegen einen Grant für mail.send tauschen.
            raise ExecutionDenied(
                "Geprüftes und auszuführendes Werkzeug stimmen nicht überein.",
                code="tool-mismatch",
            )

        decision = await self._policy.decide(request, taint=taint, now=now)

        if decision.effect is PolicyEffect.DENY:
            raise ExecutionDenied(decision.reason, code="policy-denied")
        if decision.effect is PolicyEffect.CONFIRM:
            raise ExecutionDenied(
                f"Dieser Vorgang verlangt eine Bestätigung: {decision.reason}",
                code="approval-required",
            )

        return ExecutionGrant(
            _GRANT_SENTINEL,
            tool_name=spec.name,
            arguments=request.arguments,
            verified_hash=payload_hash(spec.name, request.arguments),
            run_id=request.run_id,
            user_id=request.user_id,
            invocation_id=invocation_id,
            granted_at=now,
        )

    # -- Hilfsmittel -----------------------------------------------------
    @staticmethod
    def _channel_reason(action: PendingAction, channel: ApprovalChannel) -> str:
        if action.risk is RiskLevel.CRITICAL:
            return (
                "Dieser Vorgang ist nicht umkehrbar und lässt sich nur in der Oberfläche "
                "bestätigen — nicht per Sprache oder Geste."
            )
        return (
            f"Diese Bestätigung wurde über „{action.requested_channel}“ angefordert und "
            f"kann nicht über „{channel}“ eingelöst werden. Bestätige dort, wo die "
            "Vorschau angezeigt wurde."
        )
