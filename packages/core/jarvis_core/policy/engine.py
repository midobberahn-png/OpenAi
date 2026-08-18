"""Policy Engine — der einzige Weg zur Werkzeugausführung.

Siehe docs/07-security-permissions.md §3 und §4a.

Die Prüfreihenfolge ist bedeutungstragend und nicht beliebig umstellbar:
Die Taint-Prüfung steht **vor** allem anderen, weil eine erteilte Berechtigung
in einem kontaminierten Lauf nichts wert sein darf. Stünde sie hinter der
Berechtigungsprüfung, wäre die Reihenfolge zwar oft gleichgültig — aber genau
in dem Fall nicht, auf den es ankommt.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from jarvis_contracts import (
    ActionPreview,
    PermissionMode,
    PolicyDecision,
    PolicyRequest,
    PreviewField,
    RiskLevel,
    TaintGateOutcome,
    TaintLevel,
    ToolSpec,
)
from jarvis_core.ports.permissions import PermissionStore, RateLimiter, ToolLookup
from jarvis_core.tools.registry import UnknownTool

__all__ = ["PolicyEngine", "build_preview"]

_MAX_PREVIEW_VALUE = 400


def build_preview(
    spec: ToolSpec,
    arguments: dict[str, object],
    *,
    known_recipients: set[str] | None = None,
) -> ActionPreview:
    """Vorschau aus dem *validierten Argument-Objekt*.

    Nicht aus einer Modellformulierung — sonst könnte das Modell etwas anderes
    anzeigen, als es ausführt (docs/07-security-permissions.md §5).
    """
    known = {r.lower() for r in (known_recipients or set())}
    fields: list[PreviewField] = []
    warnings: list[str] = []

    for key in sorted(arguments):
        raw = arguments[key]
        text = ", ".join(str(v) for v in raw) if isinstance(raw, list | tuple) else str(raw)
        truncated = len(text) > _MAX_PREVIEW_VALUE
        emphasis: Literal["normal", "warn"] = "normal"

        # Empfänger und Teilnehmer, die weder in Kontakten noch im bisherigen
        # Verlauf vorkommen, werden hervorgehoben. Das ist die Stelle, an der
        # ein eingeschmuggelter Adressat auffallen muss.
        if key in spec.outbound_fields or key in {"to", "cc", "bcc", "attendees", "recipients"}:
            values = raw if isinstance(raw, list | tuple) else [raw]
            unknown = [str(v) for v in values if str(v).lower() not in known]
            if unknown and known:
                emphasis = "warn"
                warnings.append("Nicht in deinen Kontakten: " + ", ".join(sorted(unknown)))

        fields.append(
            PreviewField(
                label=key,
                value=text[:_MAX_PREVIEW_VALUE],
                emphasis=emphasis,
                truncated=truncated,
            )
        )

    return ActionPreview(
        tool_name=spec.name,
        title=spec.description.split(".")[0].strip() or spec.name,
        fields=fields,
        risk=spec.risk,
        reversible=spec.supports_undo,
        warnings=warnings,
    )


class PolicyEngine:
    """Entscheidet über jede Werkzeugausführung.

    Hält absichtlich keinen Zustand: Jede Entscheidung ergibt sich vollständig
    aus der Anfrage und den nachgeladenen Berechtigungen. Damit ist sie
    reproduzierbar — eine Policy-Entscheidung, die von vorherigen Aufrufen
    abhängt, wäre nicht auditierbar.
    """

    def __init__(
        self,
        tools: ToolLookup,
        permissions: PermissionStore,
        *,
        rate_limiter: RateLimiter | None = None,
        known_recipients: set[str] | None = None,
    ) -> None:
        self._tools = tools
        self._permissions = permissions
        self._rate_limiter = rate_limiter
        self._known_recipients = known_recipients or set()

    async def decide(
        self,
        req: PolicyRequest,
        *,
        taint: TaintLevel = TaintLevel.CLEAN,
        now: datetime | None = None,
    ) -> PolicyDecision:
        moment = now or datetime.now(tz=None)

        spec = self._tools.get(req.tool_name)
        if spec is None:
            # Halluzinierte Werkzeugnamen sind ein eigener Fall und dürfen
            # nicht als Berechtigungsfehler erscheinen — sonst würde die UI
            # anbieten, eine Berechtigung für etwas zu erteilen, das es nicht
            # gibt.
            raise UnknownTool(f"Unbekanntes Werkzeug: {req.tool_name!r}")

        # ---- (1) Taint. Steht vor allem anderen. -------------------------
        gate = spec.taint_gate(tainted=taint.is_tainted, arguments=req.arguments)
        if gate is TaintGateOutcome.BLOCKED:
            return PolicyDecision.deny(
                self._taint_reason(spec, req.arguments),
                scope=spec.scopes[0] if spec.scopes else None,
                escalate_to_user=True,
            )

        # ---- (2) Datenklassifikation. Hartes Filter. ---------------------
        if spec.data_class > req.allowed_data_class:
            return PolicyDecision.deny(
                f"Daten der Stufe {spec.data_class} sind in diesem Kontext nicht zulässig "
                f"(erlaubt bis {req.allowed_data_class}).",
                scope=spec.scopes[0] if spec.scopes else None,
            )

        # ---- (3) Erteilte Rechte -----------------------------------------
        needs_confirmation = False
        for scope in spec.scopes:
            grant = await self._permissions.get_grant(req.user_id, scope)
            if grant is None or grant.mode is PermissionMode.DENY:
                return PolicyDecision.deny(
                    f"Die Berechtigung „{scope}“ ist nicht erteilt.",
                    scope=scope,
                    offer_grant=True,
                )
            if not grant.is_valid_at(moment):
                return PolicyDecision.deny(
                    f"Die Berechtigung „{scope}“ ist abgelaufen.",
                    scope=scope,
                    offer_grant=True,
                )
            # ---- (4) Einschränkungen --------------------------------------
            violation = grant.constraints.check(req.arguments, now=moment)
            if violation is not None:
                return PolicyDecision.deny(
                    violation.message,
                    scope=scope,
                    violation=violation,
                    offer_grant=True,
                )
            if grant.mode is PermissionMode.CONFIRM:
                needs_confirmation = True

        # ---- (5) Unbeaufsichtigte Auslöser sind strenger ------------------
        if not req.trigger_is_supervised and spec.risk >= RiskLevel.MEDIUM:
            return PolicyDecision.confirm(
                "Automatisierter Vorgang mit Außenwirkung — es ist niemand anwesend, "
                "der ihn beaufsichtigt.",
                self._preview(spec, req),
                scope=spec.scopes[0] if spec.scopes else None,
            )

        # ---- (6) Risikoklasse und Sanierung ------------------------------
        if gate is TaintGateOutcome.SANITIZABLE:
            return PolicyDecision.confirm(
                "Dieser Vorgang hat externe Inhalte gelesen. Prüfe den Payload; nach "
                "deiner Bestätigung wird er unverändert in einem neuen, sauberen Lauf "
                "ausgeführt.",
                self._preview(spec, req),
                scope=spec.scopes[0] if spec.scopes else None,
            )

        if spec.risk.needs_confirmation or needs_confirmation:
            return PolicyDecision.confirm(
                self._confirm_reason(spec),
                self._preview(spec, req),
                scope=spec.scopes[0] if spec.scopes else None,
            )

        # ---- (7) Betriebsgrenzen -----------------------------------------
        if (
            self._rate_limiter is not None
            and spec.rate_limit
            and await self._rate_limiter.exceeded(req.user_id, spec.name, spec.rate_limit)
        ):
            return PolicyDecision.deny(
                f"Nutzungsgrenze für {spec.name} erreicht ({spec.rate_limit}).",
                scope=spec.scopes[0] if spec.scopes else None,
            )

        return PolicyDecision.allow(
            "Berechtigung erteilt, Risiko niedrig.",
            scope=spec.scopes[0] if spec.scopes else None,
        )

    async def effective_tools(
        self,
        user_id: UUID,
        candidate_names: set[str],
        *,
        taint: TaintLevel = TaintLevel.CLEAN,
    ) -> set[str]:
        """Werkzeugset, das einem Modell überhaupt angeboten werden darf.

        Verengung an *einer* Stelle statt in jedem Agenten: Schnittmenge aus
        angefragten Werkzeugen, erteilten Rechten und — bei Kontamination —
        den unbedenklichen Werkzeugen. Was hier wegfällt, sieht das Modell
        nicht; es kann also nicht einmal versuchen, es aufzurufen.
        """
        granted = await self._permissions.granted_scopes(user_id)
        allowed: set[str] = set()
        for name in candidate_names:
            spec = self._tools.get(name)
            if spec is None:
                continue
            if not set(spec.scopes) <= granted:
                continue
            if taint.is_tainted and spec.is_blocked_by_taint():
                # Sanierbare Werkzeuge bleiben im Angebot: Die Entscheidung
                # fällt erst in decide(), weil sie von den Argumenten abhängt.
                if spec.payload_inspectability.clearable_by_confirmation:
                    allowed.add(name)
                continue
            allowed.add(name)
        return allowed

    # -- Hilfsmittel -----------------------------------------------------
    def _preview(self, spec: ToolSpec, req: PolicyRequest) -> ActionPreview:
        return build_preview(spec, req.arguments, known_recipients=self._known_recipients)

    def _taint_reason(self, spec: ToolSpec, arguments: dict[str, object]) -> str:
        """Erklärt die Sperre so, dass der Nutzer weiß, was er tun kann."""
        if spec.risk is RiskLevel.CRITICAL:
            return (
                f"„{spec.name}“ ist nach dem Lesen externer Inhalte gesperrt, weil die "
                "Aktion nicht rückgängig zu machen ist. Wenn du sie willst, stoße sie "
                "bitte selbst an."
            )
        effective = spec.effective_inspectability(arguments)
        if effective is not spec.payload_inspectability:
            return (
                f"„{spec.name}“ würde hier nach außen wirken (Empfänger oder Teilnehmer "
                "sind gesetzt) und ist nach dem Lesen externer Inhalte gesperrt. Ohne "
                "Empfänger wäre der Vorgang zulässig."
            )
        return (
            f"„{spec.name}“ ist nach dem Lesen externer Inhalte gesperrt, weil sich der "
            "Inhalt nicht vollständig prüfen lässt. Formuliere die Aktion bitte selbst, "
            "dann läuft sie in einem sauberen Vorgang."
        )

    @staticmethod
    def _confirm_reason(spec: ToolSpec) -> str:
        if spec.risk is RiskLevel.CRITICAL:
            return "Nicht umkehrbar — Bestätigung nur in der Oberfläche möglich."
        if spec.risk is RiskLevel.HIGH:
            return "Aktion mit Außenwirkung, nicht zurückholbar."
        return "Für diesen Vorgang hast du Bestätigung verlangt."
