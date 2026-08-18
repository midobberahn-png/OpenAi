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
    "PayloadInspectability",
    "SanitizedPayload",
    "Source",
    "TaintGateOutcome",
    "ToolInvocation",
    "ToolResult",
    "ToolSpec",
]


SAFE_WHEN_TAINTED_MAX_RISK = RiskLevel.LOW
"""Höchste Risikoklasse, die in einem kontaminierten Kontext noch zulässig ist,
wenn ein Werkzeug ``forbidden_when_tainted`` nicht ausdrücklich setzt."""


class PayloadInspectability(StrEnum):
    """Kann ein Mensch diesen Payload vollständig prüfen?

    Entscheidet, ob eine Bestätigung Kontamination aufheben darf
    (docs/16-v1.1-review.md §1). Eine Bestätigung ist nur dann eine echte
    Sicherheitsprüfung, wenn der Mensch tatsächlich sieht, was er freigibt.
    """

    STRUCTURED = "structured"
    """Kurze, typisierte Felder — Datum, Zeit, ID, Titel. In Sekunden erfassbar.
    Beispiel: ``calendar.create``."""

    FREEFORM = "freeform"
    """Enthält Freitext mit Außenwirkung. Eine um eine Ziffer veränderte IBAN
    oder eine ausgetauschte URL im Fließtext übersieht auch ein aufmerksamer
    Leser — genau darauf zielen reale Angriffe. Beispiel: ``send_email``."""

    OPAQUE = "opaque"
    """Nicht sinnvoll darstellbar: Binärdaten, Skripte, Befehle.
    Beispiel: ``shell.exec``."""

    @property
    def clearable_by_confirmation(self) -> bool:
        """Nur strukturierte Payloads dürfen Kontamination aufheben."""
        return self is PayloadInspectability.STRUCTURED


class TaintGateOutcome(StrEnum):
    """Ergebnis der Taint-Prüfung eines Werkzeugaufrufs."""

    PERMITTED = "permitted"
    """Nicht kontaminiert oder Werkzeug unbedenklich — normale Ausführung."""

    SANITIZABLE = "sanitizable"
    """Kontaminiert, aber der Payload ist vollständig prüfbar. Nach Bestätigung
    wird ein neuer, sauberer Lauf mit eingefrorenem Payload gestartet."""

    BLOCKED = "blocked"
    """Kontaminiert und nicht sanierbar. Der Nutzer muss die Aktion selbst
    anstoßen — dann entsteht von Anfang an ein sauberer Lauf."""


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

    payload_inspectability: PayloadInspectability = PayloadInspectability.FREEFORM
    """Kann ein Mensch den Payload vollständig prüfen?

    Standard ist ``FREEFORM`` — die sichere Annahme. Werkzeuge müssen sich
    ausdrücklich als vollständig prüfbar erklären, nicht umgekehrt.

    Achtung: Dies ist die *statische* Einstufung. Die tatsächlich gültige
    ergibt sich aus ``effective_inspectability()`` und kann je Aufruf strenger
    ausfallen — siehe ``outbound_fields``.
    """

    outbound_fields: list[str] = Field(default_factory=list)
    """Felder, deren Befüllung eine Nachricht an Dritte auslöst.

    Hintergrund: Ein Kalendereintrag *ohne* Teilnehmer ist eine private Notiz
    und vollständig prüfbar. Derselbe Eintrag *mit* Teilnehmern verschickt
    Einladungen — das ist Außenwirkung, unabhängig davon, wie strukturiert der
    Payload aussieht. Eine Einstufung allein auf Werkzeugebene wäre hier zu
    grob und würde genau den Angriff durchlassen, bei dem eine präparierte
    Mail einen zusätzlichen Teilnehmer einschmuggelt.

    Beispiel: ``calendar.create`` → ``["attendees"]``.
    """

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
        if (
            self.payload_inspectability is PayloadInspectability.STRUCTURED
            and not self.requires_preview
            and self.risk is not RiskLevel.LOW
        ):
            raise ValueError(
                f"Werkzeug {self.name!r}: 'structured' erlaubt Taint-Sanierung und "
                "verlangt deshalb requires_preview=True — ohne Vorschau gäbe es "
                "nichts zu prüfen."
            )
        return self

    def is_blocked_by_taint(self) -> bool:
        """Ist dieses Werkzeug in einem kontaminierten Kontext gesperrt?"""
        if self.forbidden_when_tainted:
            return True
        return self.risk > SAFE_WHEN_TAINTED_MAX_RISK

    def effective_inspectability(
        self, arguments: dict[str, Any] | None = None
    ) -> PayloadInspectability:
        """Prüfbarkeit für *diesen konkreten* Aufruf.

        Ohne Argumente wird die statische Einstufung zurückgegeben. Sind
        Argumente vorhanden und ist mindestens ein ``outbound_fields``-Feld
        belegt, gilt der Aufruf als ``FREEFORM`` — er wirkt nach außen.
        """
        if self.payload_inspectability is not PayloadInspectability.STRUCTURED:
            return self.payload_inspectability
        if arguments is None:
            return self.payload_inspectability

        for field in self.outbound_fields:
            value = arguments.get(field)
            if value:  # nicht None, nicht leere Liste, nicht leerer String
                return PayloadInspectability.FREEFORM
        return PayloadInspectability.STRUCTURED

    def taint_gate(
        self, *, tainted: bool, arguments: dict[str, Any] | None = None
    ) -> TaintGateOutcome:
        """Entscheidet über die Behandlung in einem kontaminierten Lauf.

        Siehe docs/16-v1.1-review.md §1. Diese Methode löst den Widerspruch
        aus V1.0 auf: Ohne sie wäre der häufigste Alltagsablauf — Mails lesen
        und daraus einen Termin anlegen — dauerhaft gesperrt. Ein
        Sicherheitsmechanismus, der den Normalfall blockiert, wird abgeschaltet
        und ist damit wirkungslos.

        Die Sanierung ist eng gefasst: Sie setzt voraus, dass der Mensch den
        Payload tatsächlich vollständig prüfen kann.
        """
        if not tainted or not self.is_blocked_by_taint():
            return TaintGateOutcome.PERMITTED

        # Irreversibles wird nie saniert — dort ist der Preis eines Fehlers
        # zu hoch, um ihn gegen Komfort abzuwägen.
        if self.risk is RiskLevel.CRITICAL:
            return TaintGateOutcome.BLOCKED

        # Bewusst die *effektive* Einstufung: Ein Kalendereintrag mit
        # eingeschmuggeltem Teilnehmer ist keine private Notiz mehr.
        if self.effective_inspectability(arguments).clearable_by_confirmation:
            return TaintGateOutcome.SANITIZABLE

        return TaintGateOutcome.BLOCKED

    def effective_risk(self, declared: RiskLevel | None = None) -> RiskLevel:
        """Ein Plugin darf seine eigene Risikoeinstufung nicht senken.

        Siehe docs/12-plugins.md §4. Der Kern nimmt immer den höheren Wert.
        """
        if declared is None:
            return self.risk
        return max(self.risk, declared)


class SanitizedPayload(BaseModel):
    """Ein vom Nutzer bestätigter, eingefrorener Werkzeug-Payload.

    Grundlage des sanierten Laufs (docs/16-v1.1-review.md §1). Vier
    Invarianten machen das Gate zur Ergänzung des Taint-Schutzes statt zu
    seiner Umgehung:

    1. **Eingefroren** — ``frozen=True``; was bestätigt wurde, wird ausgeführt.
    2. **Keine Kontextvererbung** — der saubere Lauf sieht den Herkunftslauf
       nicht, auch nicht dessen Zusammenfassung.
    3. **Genau ein Aufruf** — der sanierte Lauf plant nicht und delegiert nicht.
    4. **Verknüpft im Audit** — ``origin_run_id`` erhält die Nachvollziehbarkeit.
    """

    model_config = ConfigDict(frozen=True)

    tool_name: str
    arguments: dict[str, Any]
    """Byte-identisch das, was der Nutzer in der Vorschau gesehen hat."""

    origin_run_id: UUID
    """Der kontaminierte Lauf, aus dem der Payload stammt. Nur für das Audit —
    der saubere Lauf greift nicht darauf zu."""

    approved_at: datetime
    approved_by: UUID
    payload_hash: str = Field(min_length=64, max_length=64)
    """SHA-256 über die kanonisierten Argumente. Der Executor prüft ihn vor der
    Ausführung erneut: Ohne diese Prüfung könnte zwischen Bestätigung und
    Ausführung etwas anderes eingeschleust werden."""


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
