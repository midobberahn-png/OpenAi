"""Agentenvertrag: Spezifikation, Anfrage, Ergebnis, Handoff.

Siehe docs/06-agenten-tools.md.

Least Privilege ist der eigentliche Grund für Sub-Agenten: Der Research Agent
liest Fremdinhalt und besitzt deshalb strukturell keine sendenden Werkzeuge.
Spezialisierung ist hier ein Sicherheitsmechanismus, keine Organisationsform.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .classification import DataClass, TaintLevel
from .context import ContextBundle
from .runs import RunBudget, Usage
from .tools import Source

__all__ = ["AgentRequest", "AgentResult", "AgentSpec", "AgentStatus"]


class AgentStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    NEEDS_CONFIRMATION = "needs_confirmation"
    BUDGET_EXCEEDED = "budget_exceeded"

    def __str__(self) -> str:
        return self.value


class AgentSpec(BaseModel):
    """Definition eines Agenten."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=40)
    description: str = Field(min_length=10)
    """Der Supervisor liest das, um zu entscheiden, wohin er delegiert."""

    system_prompt: str = Field(min_length=1)

    allowed_tools: list[str] = Field(default_factory=list)
    """Whitelist, nie Blacklist. Eine Blacklist vergisst man."""

    max_data_class: DataClass = DataClass.P2
    model_preference: str | None = None
    max_iterations: int = Field(default=8, ge=1, le=50)

    accepts_untrusted_input: bool = False
    """Darf dieser Agent Fremdinhalt lesen? Wenn ja, braucht er ein
    entsprechend eingeschränktes Werkzeugset."""

    can_delegate: bool = False
    """Nur der Supervisor."""

    @model_validator(mode="after")
    def _untrusted_readers_cannot_send(self) -> AgentSpec:
        """Ein Agent, der Fremdinhalt liest, darf keine sendenden Werkzeuge
        führen — sonst ist der Injection-Pfad offen, bevor Taint überhaupt greift."""
        if self.accepts_untrusted_input:
            forbidden = {"send_email", "mail.send", "chat.send", "smarthome.set"}
            overlap = forbidden & set(self.allowed_tools)
            if overlap:
                raise ValueError(
                    f"Agent {self.name!r} liest Fremdinhalt und darf daher "
                    f"folgende Werkzeuge nicht führen: {sorted(overlap)}"
                )
        return self

    def effective_tools(
        self, granted: set[str], *, tainted: bool = False, safe_tools: set[str] | None = None
    ) -> set[str]:
        """Schnittmenge aus Agentenrechten, Nutzerrechten und Taint-Zustand.

        Ein Agent bekommt nie mehr Rechte, als der Nutzer erteilt hat — auch
        wenn seine ``allowed_tools`` mehr enthalten. Die Verengung passiert
        an genau dieser Stelle, nicht in jedem Agenten.
        """
        effective = set(self.allowed_tools) & granted
        if tainted:
            effective &= safe_tools or set()
        return effective


class AgentRequest(BaseModel):
    """Delegationsauftrag an einen Sub-Agenten."""

    task: str = Field(min_length=1)
    context: ContextBundle
    budget: RunBudget
    parent_run_id: UUID
    depth: int = Field(default=0, ge=0)
    inherited_taint: TaintLevel = TaintLevel.CLEAN

    @model_validator(mode="after")
    def _depth_within_budget(self) -> AgentRequest:
        if self.depth > self.budget.max_agent_depth:
            raise ValueError(
                f"Agententiefe {self.depth} überschreitet Budgetgrenze "
                f"{self.budget.max_agent_depth} — mögliche Rekursion."
            )
        return self


class AgentResult(BaseModel):
    """Ergebnis eines Sub-Agenten."""

    status: AgentStatus
    output: str = ""
    structured: dict[str, object] | None = None
    sources: list[Source] = Field(default_factory=list)
    """Pflicht bei Research- und Document-Agenten."""

    tools_used: list[str] = Field(default_factory=list)

    taint_acquired: bool = False
    """Propagiert nach oben: Hat der Agent Fremdinhalt gelesen, gilt der
    gesamte übergeordnete Lauf als kontaminiert."""

    produced_data_class: DataClass = DataClass.P1
    usage: Usage = Field(default_factory=Usage)
    followups: list[str] = Field(default_factory=list)
    error: str | None = None

    @model_validator(mode="after")
    def _failed_needs_error(self) -> AgentResult:
        if self.status is AgentStatus.FAILED and not self.error:
            raise ValueError("Gescheiterte Agentenläufe müssen 'error' setzen.")
        return self

    @property
    def taint_level(self) -> TaintLevel:
        return TaintLevel.TAINTED if self.taint_acquired else TaintLevel.CLEAN


Handoff = Literal["delegate", "return", "escalate"]
