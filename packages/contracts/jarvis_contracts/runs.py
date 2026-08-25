"""Lauf, Plan, Budget — das zentrale Ausführungsobjekt.

Siehe docs/04-orchestrator.md §5–§7.

Der Zustand eines Laufs liegt vollständig persistiert vor. Daraus folgen drei
Eigenschaften, die ein reiner In-Memory-Agentenloop nicht hat: Pausierbarkeit
über Prozessgrenzen, Wiederaufnahme nach Absturz und Kanalunabhängigkeit.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .classification import DataClass, TaintLevel
from .run_state import RunState

__all__ = [
    "BUDGET_PRESETS",
    "Capability",
    "Complexity",
    "Intent",
    "ModelCapability",
    "Plan",
    "PlanStep",
    "RoutingDecision",
    "Run",
    "RunBudget",
    "RunStatus",
    "RunStep",
    "RunTrigger",
    "TurnClassification",
    "Usage",
]


class RunStatus(StrEnum):
    QUEUED = "queued"
    PLANNING = "planning"
    EXECUTING = "executing"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"
    BUDGET_EXCEEDED = "budget_exceeded"

    @property
    def is_terminal(self) -> bool:
        return self in {
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
            RunStatus.BUDGET_EXCEEDED,
        }

    @property
    def is_resumable(self) -> bool:
        """Läufe, die ein Worker-Neustart wieder aufnehmen muss."""
        return self in {
            RunStatus.QUEUED,
            RunStatus.PLANNING,
            RunStatus.EXECUTING,
            RunStatus.AWAITING_CONFIRMATION,
        }

    def __str__(self) -> str:
        return self.value


class RunTrigger(StrEnum):
    USER = "user"
    SCHEDULE = "schedule"
    EVENT = "event"
    WEBHOOK = "webhook"

    @property
    def is_supervised(self) -> bool:
        """Ist ein Mensch anwesend, der bestätigen könnte?"""
        return self is RunTrigger.USER

    def __str__(self) -> str:
        return self.value


class Intent(StrEnum):
    CHAT = "chat"
    QUESTION = "question"
    TASK = "task"
    COMMAND = "command"
    RESEARCH = "research"
    CREATIVE = "creative"
    CODE = "code"
    CLARIFICATION = "clarification"

    def __str__(self) -> str:
        return self.value


class Complexity(StrEnum):
    TRIVIAL = "trivial"
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"

    @property
    def level(self) -> int:
        return {"trivial": 0, "simple": 1, "moderate": 2, "complex": 3}[self.value]

    def __str__(self) -> str:
        return self.value


class Capability(StrEnum):
    """Fähigkeiten, die ein Modell für eine Aufgabe mitbringen muss."""

    TOOL_CALLING = "tool_calling"
    VISION = "vision"
    LONG_CONTEXT = "long_context"
    STRUCTURED_OUTPUT = "structured_output"
    REASONING = "reasoning"

    def __str__(self) -> str:
        return self.value


class TurnClassification(BaseModel):
    """Ergebnis der ersten Orchestrator-Stufe.

    Ein günstiger Aufruf (lokales Modell), der jede weitere Entscheidung
    vorbereitet — und als Datensatz gegen eine Eval-Suite prüfbar ist.
    """

    intent: Intent
    complexity: Complexity
    data_class: DataClass
    required_capabilities: list[Capability] = Field(default_factory=list)
    likely_tools: list[str] = Field(default_factory=list)
    needs_realtime_info: bool = False
    is_multi_step: bool = False
    explicit_model_request: str | None = None
    """'Nutze Claude' — überschreibt das Routing, soweit zulässig."""

    ambiguous_references: list[str] = Field(default_factory=list)
    """Pronomen und Verweise, die aufgelöst werden müssen."""

    confidence: float = Field(ge=0.0, le=1.0, default=1.0)


class RunBudget(BaseModel):
    """Harte Grenzen eines Laufs. Überschreitung beendet sauber mit Teilergebnis."""

    model_config = ConfigDict(frozen=True)

    max_tokens: int = Field(default=120_000, gt=0)
    max_steps: int = Field(default=20, gt=0)
    max_seconds: float = Field(default=120.0, gt=0)
    max_cost_eur: Decimal = Field(default=Decimal("0.50"), gt=0)
    max_tool_calls: int = Field(default=15, gt=0)
    max_agent_depth: int = Field(default=2, ge=0, le=4)
    """Verhindert Agenten-Rekursion."""

    def split(self, parts: int) -> RunBudget:
        """Teilbudget für einen Sub-Agenten."""
        if parts < 1:
            raise ValueError("parts muss mindestens 1 sein")
        return RunBudget(
            max_tokens=max(1, self.max_tokens // parts),
            max_steps=max(1, self.max_steps // parts),
            max_seconds=self.max_seconds,
            max_cost_eur=max(Decimal("0.001"), self.max_cost_eur / parts),
            max_tool_calls=max(1, self.max_tool_calls // parts),
            max_agent_depth=max(0, self.max_agent_depth - 1),
        )


BUDGET_PRESETS: dict[str, RunBudget] = {
    "voice": RunBudget(
        max_tokens=20_000,
        max_steps=8,
        max_seconds=20.0,
        max_cost_eur=Decimal("0.05"),
        max_tool_calls=5,
    ),
    "text": RunBudget(),
    "research": RunBudget(
        max_tokens=400_000,
        max_steps=60,
        max_seconds=600.0,
        max_cost_eur=Decimal("2.00"),
        max_tool_calls=60,
    ),
    "automation": RunBudget(
        max_tokens=60_000,
        max_steps=15,
        max_seconds=300.0,
        max_cost_eur=Decimal("0.20"),
        max_tool_calls=10,
    ),
}
"""Latenz ist bei Sprache das eigentliche Budget; bei Automationen ist es die
Tatsache, dass niemand zusieht."""


class Usage(BaseModel):
    """Verbrauch eines Laufs. Wird fortlaufend gegen das Budget geprüft."""

    tokens_in: int = 0
    tokens_out: int = 0
    steps: int = 0
    tool_calls: int = 0
    cost_eur: Decimal = Decimal("0")
    elapsed_s: float = 0.0

    @property
    def tokens_total(self) -> int:
        return self.tokens_in + self.tokens_out

    def exceeds(self, budget: RunBudget) -> str | None:
        """Welche Grenze ist überschritten? ``None`` heißt: im Rahmen."""
        if self.tokens_total >= budget.max_tokens:
            return f"Token-Budget erreicht ({self.tokens_total}/{budget.max_tokens})."
        if self.steps >= budget.max_steps:
            return f"Schrittgrenze erreicht ({self.steps}/{budget.max_steps})."
        if self.tool_calls >= budget.max_tool_calls:
            return f"Werkzeuggrenze erreicht ({self.tool_calls}/{budget.max_tool_calls})."
        if self.cost_eur >= budget.max_cost_eur:
            return f"Kostengrenze erreicht ({self.cost_eur:.4f} €/{budget.max_cost_eur} €)."
        if self.elapsed_s >= budget.max_seconds:
            return f"Zeitgrenze erreicht ({self.elapsed_s:.1f}s/{budget.max_seconds}s)."
        return None

    def merge(self, other: Usage) -> Usage:
        return Usage(
            tokens_in=self.tokens_in + other.tokens_in,
            tokens_out=self.tokens_out + other.tokens_out,
            steps=self.steps + other.steps,
            tool_calls=self.tool_calls + other.tool_calls,
            cost_eur=self.cost_eur + other.cost_eur,
            elapsed_s=max(self.elapsed_s, other.elapsed_s),
        )


class PlanStep(BaseModel):
    """Ein Schritt eines Ausführungsplans."""

    seq: int = Field(ge=1)
    description: str = Field(min_length=1)
    """In natürlicher Sprache — die UI zeigt den Plan vor der Ausführung."""

    kind: Literal["tool", "agent", "llm", "confirm"]
    target: str
    depends_on: list[int] = Field(default_factory=list)
    """Ermöglicht echte Parallelität unabhängiger Schritte."""

    optional: bool = False


class Plan(BaseModel):
    """Validierter Ausführungsplan — kein Freitext."""

    goal: str = Field(min_length=1)
    steps: list[PlanStep] = Field(min_length=1)
    estimated_tokens: int = 0
    requires_confirmation: bool = False
    fallback: str | None = None

    @model_validator(mode="after")
    def _validate_dependencies(self) -> Plan:
        seen: set[int] = set()
        for step in self.steps:
            if step.seq in seen:
                raise ValueError(f"Doppelte Schrittnummer: {step.seq}")
            for dep in step.depends_on:
                if dep not in seen:
                    raise ValueError(
                        f"Schritt {step.seq} hängt von {dep} ab, das nicht vorher ausgeführt wird."
                    )
            seen.add(step.seq)
        return self

    def ready_steps(self, completed: set[int]) -> list[PlanStep]:
        """Schritte, die jetzt (parallel) laufen können."""
        return [s for s in self.steps if s.seq not in completed and set(s.depends_on) <= completed]


class ModelCapability(BaseModel):
    """Was ein Modell kann — und für welche Datenklasse es zugelassen ist."""

    model_config = ConfigDict(frozen=True)

    name: str
    provider: str
    max_data_class: DataClass
    """Pro Deployment konfiguriert, nicht vom Modell behauptet."""

    context_window: int = Field(gt=0)
    supports_tools: bool = True
    supports_vision: bool = False
    cost_per_1m_in: Decimal = Decimal("0")
    cost_per_1m_out: Decimal = Decimal("0")
    cost_per_1m_cached_in: Decimal | None = None
    """Preis für Eingabetokens, die aus dem Prompt-Cache gelesen wurden.

    ``None`` heißt **nicht**„kostenlos", sondern „wie ``cost_per_1m_in``". Das
    ist die vorsichtige Richtung: Ein Budget, das zu hoch rechnet, hält zu früh
    an; eines, das zu niedrig rechnet, hält zu spät — und dann ist das Geld weg.

    **Alle drei Preise sind Euro je einer Million Tokens**, und sie sind
    Konfiguration. Wer Dollarpreise einträgt, misst in Dollar und nennt es
    Euro; der Katalog beschreibt das Deployment, er ruft keine Preisliste ab."""

    @property
    def is_priced(self) -> bool:
        """Ist bekannt, was ein Aufruf dieses Modells kostet?

        Für ein lokales Modell ist ``False`` richtig und folgenlos: Es kostet
        Strom, keine Rechnung. Für einen fremden Anbieter ist es der
        Unterschied zwischen einer Grenze und einer Statistik — deshalb prüft
        das Model Gateway es, bevor es einen fremden Anbieter aufruft.

        Ein Preis von null gilt als „nicht konfiguriert" und nicht als
        „kostenlos". Ein kostenloses Cloud-Modell gibt es nicht; ein
        vergessener Eintrag schon.
        """
        return self.cost_per_1m_in > 0 and self.cost_per_1m_out > 0

    def cost_for(self, *, tokens_in: int, tokens_out: int, cached_tokens_in: int = 0) -> Decimal:
        """Was dieser Verbrauch kostet — in Euro.

        Die Rechnung steht **hier** und nicht im Adapter: Ein Adapter, der
        Preise mitbrächte, führte eine zweite Wahrheit darüber, und die
        veraltet, sobald ein Anbieter seine Liste ändert. Sie steht auch nicht
        im Budget-Tracker, der die Preise gar nicht kennt.

        ``cached_tokens_in`` ist **zusätzlich** zu ``tokens_in`` zu verstehen,
        nicht darin enthalten — die Adapter rechnen beides auseinander, weil
        die Anbieter es unterschiedlich melden.
        """
        aus_cache = (
            self.cost_per_1m_cached_in
            if self.cost_per_1m_cached_in is not None
            else self.cost_per_1m_in
        )
        gesamt = (
            Decimal(tokens_in) * self.cost_per_1m_in
            + Decimal(cached_tokens_in) * aus_cache
            + Decimal(tokens_out) * self.cost_per_1m_out
        )
        return gesamt / Decimal(1_000_000)

    p50_latency_ms: int = 800
    zero_retention: bool = False
    is_local: bool = False

    def supports(self, capabilities: list[Capability]) -> bool:
        for cap in capabilities:
            if cap is Capability.TOOL_CALLING and not self.supports_tools:
                return False
            if cap is Capability.VISION and not self.supports_vision:
                return False
            if cap is Capability.LONG_CONTEXT and self.context_window < 200_000:
                return False
        return True

    def accepts(self, data_class: DataClass) -> bool:
        """Hartes Filter — nicht verhandelbar."""
        return data_class <= self.max_data_class


class RoutingDecision(BaseModel):
    """Modellwahl mit Begründung. Die Begründung erscheint in der UI."""

    model_config = ConfigDict(frozen=True)

    model: str
    provider: str
    reason: str = Field(min_length=1)
    max_data_class: DataClass
    """Höchste Klasse, die das gewählte Modell verarbeiten darf.

    Pflichtfeld und Teil der Entscheidung, nicht Konfiguration daneben: Der
    Executor leitet daraus die Obergrenze jedes Werkzeugaufrufs ab. Läge der
    Wert nicht hier, müsste ihn der Aufrufer mitgeben — und ein Aufrufer, der
    die eigene Obergrenze bestimmt, hat keine.
    """

    is_fallback: bool = False
    rejected: dict[str, str] = Field(default_factory=dict)
    """Modell → Ablehnungsgrund. Macht das Routing nachvollziehbar."""


class RunStep(BaseModel):
    """Ein ausgeführter Schritt. Zugleich Datenquelle des Aktivitätsprotokolls."""

    id: UUID
    run_id: UUID
    seq: int
    kind: Literal["classify", "route", "plan", "agent", "tool", "llm", "verify"]
    agent_name: str | None = None
    model_used: str | None = None
    description: str = ""
    status: Literal["running", "ok", "failed", "skipped", "blocked"] = "running"
    usage: Usage = Field(default_factory=Usage)
    latency_ms: int | None = None
    error: str | None = None
    started_at: datetime
    finished_at: datetime | None = None


class Run(BaseModel):
    """Der persistierte Zustand einer Orchestrator-Ausführung."""

    id: UUID
    user_id: UUID
    conversation_id: UUID | None = None
    trigger: RunTrigger = RunTrigger.USER
    status: RunStatus = RunStatus.QUEUED
    classification: TurnClassification | None = None
    routing: RoutingDecision | None = None
    plan: Plan | None = None
    taint_level: TaintLevel = TaintLevel.CLEAN
    data_class: DataClass = DataClass.P1
    budget: RunBudget = Field(default_factory=RunBudget)
    usage: Usage = Field(default_factory=Usage)
    state: RunState = Field(default_factory=RunState)
    """Typisierter Zwischenzustand — Grundlage der Wiederaufnahme."""

    trace_id: str
    error: dict[str, str] | None = None
    started_at: datetime
    finished_at: datetime | None = None

    sanitized_from_run_id: UUID | None = None
    """Gesetzt, wenn dieser Lauf aus einem Taint-Sanitization-Gate hervorging.

    Der Lauf ist ``clean``, führt genau einen bestätigten Werkzeugaufruf aus
    und hat **keinen** Zugriff auf den Herkunftslauf — die Verknüpfung dient
    ausschließlich der Nachvollziehbarkeit im Audit
    (docs/16-v1.1-review.md §1).
    """

    @model_validator(mode="after")
    def _sanitized_runs_are_clean(self) -> Run:
        """Ein sanierter Lauf, der selbst kontaminiert startet, wäre sinnlos —
        und ein stiller Weg, die Sperre zu umgehen."""
        if self.sanitized_from_run_id is not None and self.taint_level is TaintLevel.TAINTED:
            raise ValueError(
                "Ein sanierter Lauf muss sauber starten; sonst hebt das Gate die "
                "Sperre nicht auf, sondern umgeht sie."
            )
        return self

    @property
    def next_step_seq(self) -> int:
        """Die nächste freie Schrittnummer — **oberhalb des ganzen Plans**.

        ``completed_steps`` führt zweierlei: erledigte Planschritte und
        Aufrufe, die jemand selbst ausgelöst hat (``POST /runs/{id}/steps``,
        die Werkzeugaufrufe eines Agentenschrittes). Der Plan liest daraus, was
        noch fällig ist, und unterscheidet nicht, woher eine Nummer stammt.

        **Deshalb genügt ``max(erledigte) + 1`` nicht.** Gemessen: Plan aus
        „① Termin anlegen ② Antwort formulieren"; nach ① ruft der Nutzer ein
        Werkzeug selbst auf und bekommt die Nummer 2. Danach gilt Planschritt 2
        als erledigt, ohne je gelaufen zu sein — der Lauf endet ohne Antwort.
        Kein Fehler schlägt an; es fehlt nur etwas.

        Die Nummer liegt deshalb über **beidem**: über allem, was erledigt ist,
        und über allem, was der Plan überhaupt vergibt. Damit kann ein Aufruf
        außerhalb des Plans keinen Planschritt mehr belegen — auch keinen, der
        erst später fällig wird.
        """
        erledigt = max((s.seq for s in self.state.completed_steps), default=0)
        geplant = max((s.seq for s in self.plan.steps), default=0) if self.plan else 0
        return max(erledigt, geplant) + 1

    def with_taint(self, level: TaintLevel) -> Run:
        """Kontamination ist monoton — sie kann nur hinzukommen, nie verschwinden."""
        return self.model_copy(update={"taint_level": self.taint_level.merge(level)})
