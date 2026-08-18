"""Werkzeugvertrag: Spezifikation, Aufruf, Ergebnis.

Siehe docs/06-agenten-tools.md §4.

Werkzeuge kennen ihre Risikoklasse, entscheiden aber nie über ihre eigene
Ausführung — das tut ausschließlich die Policy Engine.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .classification import DataClass
from .permissions import PolicyEffect, RiskLevel, ScopeName

__all__ = [
    "SAFE_WHEN_TAINTED_MAX_RISK",
    "InvocationStatus",
    "Source",
    "ToolInvocation",
    "ToolResult",
    "ToolSpec",
]


SAFE_WHEN_TAINTED_MAX_RISK = RiskLevel.LOW
"""Höchste Risikoklasse, die in einem kontaminierten Kontext noch zulässig ist,
wenn ein Werkzeug ``forbidden_when_tainted`` nicht ausdrücklich setzt."""


class Source(BaseModel):
    """Quellenbeleg. Pflicht bei Recherche- und Dokumentergebnissen."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["web", "document", "email", "calendar", "memory"]
    title: str
    ref: str
    """URL, Dokument-ID oder Message-ID."""

    locator: str | None = None
    """Seite, Abschnitt oder Zeilenbereich innerhalb der Quelle."""

    retrieved_at: datetime | None = None


class ToolSpec(BaseModel):
    """Vollständige Beschreibung eines Werkzeugs.

    Aus dieser Spezifikation entstehen: das JSON-Schema für das Modell, die
    Laufzeitvalidierung und die generierte Werkzeugdokumentation.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$", max_length=80)
    description: str = Field(min_length=10, max_length=1000)
    """Was das Modell sieht. Ungenaue Beschreibungen sind die häufigste
    Ursache für falsch gewählte Werkzeuge."""

    parameters: dict[str, Any]
    """JSON Schema, aus der Funktionssignatur abgeleitet."""

    returns: dict[str, Any] | None = None

    scopes: list[ScopeName] = Field(default_factory=list)
    risk: RiskLevel
    data_class: DataClass = DataClass.P1

    idempotent: bool = False
    """Steuert, ob nach einem Timeout wiederholt werden darf."""

    requires_preview: bool = False
    """Erzwingt ein Vorschauobjekt vor der Ausführung."""

    forbidden_when_tainted: bool = True
    """Gesperrt, sobald der Lauf Fremdinhalt verarbeitet hat.

    Standard ist ``True`` — Werkzeuge müssen sich ausdrücklich als
    unbedenklich erklären, nicht umgekehrt (docs/07-security §4).
    """

    reads_untrusted_content: bool = False
    """Setzt den Lauf auf ``tainted``, sobald dieses Werkzeug ausgeführt wurde."""

    rate_limit: str | None = Field(default=None, pattern=r"^\d+/(second|minute|hour|day)$")
    timeout_s: float = Field(default=30.0, gt=0, le=600)
    supports_undo: bool = False

    plugin: str | None = None
    """Herkunftsplugin, falls das Werkzeug nicht eingebaut ist."""

    @model_validator(mode="after")
    def _risk_consistency(self) -> ToolSpec:
        if self.risk.needs_confirmation and not self.requires_preview:
            raise ValueError(
                f"Werkzeug {self.name!r}: Risiko {self.risk} verlangt requires_preview=True — "
                "eine Bestätigung ohne Vorschau ist wertlos."
            )
        if self.risk is not RiskLevel.LOW and not self.scopes:
            raise ValueError(
                f"Werkzeug {self.name!r}: Risiko {self.risk} ohne Scope ist unzulässig."
            )
        return self

    def is_blocked_by_taint(self) -> bool:
        """Ist dieses Werkzeug in einem kontaminierten Kontext gesperrt?"""
        if self.forbidden_when_tainted:
            return True
        return self.risk > SAFE_WHEN_TAINTED_MAX_RISK

    def effective_risk(self, declared: RiskLevel | None = None) -> RiskLevel:
        """Ein Plugin darf seine eigene Risikoeinstufung nicht senken.

        Siehe docs/12-plugins.md §4. Der Kern nimmt immer den höheren Wert.
        """
        if declared is None:
            return self.risk
        return max(self.risk, declared)


class InvocationStatus(StrEnum):
    """Lebenszyklus eines Werkzeugaufrufs."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    EXPIRED = "expired"
    BLOCKED = "blocked"
    """Von der Policy Engine gesperrt — z. B. durch Taint."""

    def __str__(self) -> str:
        return self.value


class ToolResult(BaseModel):
    """Ergebnis einer Werkzeugausführung."""

    ok: bool
    data: dict[str, Any] | None = None
    display: str = ""
    """Kurzfassung für die Oberfläche."""

    error: str | None = None
    undo_token: str | None = None
    """15 Minuten gültig. Für MEDIUM-Werkzeuge wirksamer als ein weiterer Dialog."""

    sources: list[Source] = Field(default_factory=list)
    produced_data_class: DataClass = DataClass.P1
    """Klassifikation des Ergebnisses — propagiert in den Lauf."""

    taints_context: bool = False
    """Hat dieses Ergebnis Fremdinhalt eingebracht?"""

    @model_validator(mode="after")
    def _error_when_not_ok(self) -> ToolResult:
        if not self.ok and not self.error:
            raise ValueError("Fehlgeschlagene Werkzeugaufrufe müssen 'error' setzen.")
        return self


class ToolInvocation(BaseModel):
    """Ein konkreter Werkzeugaufruf innerhalb eines Laufs."""

    id: UUID
    run_id: UUID
    step_id: UUID | None = None
    tool_name: str
    arguments: dict[str, Any]
    risk_level: RiskLevel
    policy_decision: PolicyEffect
    decision_reason: str
    idempotency_key: str | None = None
    status: InvocationStatus = InvocationStatus.PENDING
    result: ToolResult | None = None
    created_at: datetime
    executed_at: datetime | None = None
