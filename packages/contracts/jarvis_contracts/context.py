"""Context Engine: Fragmente, Budgetierung, Referenzauflösung.

Siehe docs/05-memory-context.md §5–§6.

Memory beantwortet 'was weiß ich?'. Die Context Engine beantwortet
'was gehört jetzt ins Prompt?' — die schwierigere der beiden Fragen.
"""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .classification import DataClass, TaintLevel, escalate

__all__ = [
    "CONTEXT_BUDGETS",
    "ContextBundle",
    "ContextCost",
    "ContextFragment",
    "ContextPriority",
    "ContextRequest",
    "ReferenceResolution",
    "SalientEntity",
]


CONTEXT_BUDGETS: dict[str, int] = {
    "voice": 4_000,
    "text": 16_000,
    "agent": 32_000,
}
"""Im Sprachpfad dominiert die Latenz — ein kurzes Prompt ist dort wichtiger
als vollständiger Kontext."""


class ContextCost(StrEnum):
    """Was das Beschaffen kostet. Steuert, ob ein Provider im Latenzpfad
    überhaupt zulässig ist."""

    FREE = "free"
    DB = "db"
    NETWORK = "network"

    @property
    def allowed_in_voice_path(self) -> bool:
        return self is not ContextCost.NETWORK

    def __str__(self) -> str:
        return self.value


class ContextPriority(IntEnum):
    """Verdrängungsreihenfolge bei Budgetüberschreitung.

    Niedrigere Werte werden zuletzt verdrängt.
    """

    PINNED = 0
    """Kernpräferenzen und aktuelle Nachricht — nie verdrängt."""

    CONVERSATION = 1
    RETRIEVAL = 2
    STRUCTURED = 3
    """Kalender, Aufgaben — auf Zusammenfassung reduzierbar."""

    OPTIONAL = 4
    """Zuerst entfernt."""


class ContextFragment(BaseModel):
    """Ein Stück Kontext von einem Provider."""

    model_config = ConfigDict(frozen=True)

    source: str
    content: str
    tokens: int = Field(ge=0)
    relevance: float = Field(ge=0.0, le=1.0, default=1.0)
    priority: ContextPriority = ContextPriority.OPTIONAL
    data_class: DataClass = DataClass.P1

    is_untrusted: bool = False
    """Löst Taint aus, sobald das Fragment in den Kontext aufgenommen wird.
    Fremdinhalt kann Anweisungen enthalten (docs/07-security §4)."""

    truncatable: bool = True


class ContextRequest(BaseModel):
    """Anforderung an die Context Engine."""

    user_id: UUID
    conversation_id: UUID | None = None
    query: str
    channel: Literal["voice", "text", "agent"] = "text"
    max_data_class: DataClass = DataClass.P3
    now: datetime
    exclude_providers: list[str] = Field(default_factory=list)

    @property
    def token_budget(self) -> int:
        return CONTEXT_BUDGETS[self.channel]


class ContextBundle(BaseModel):
    """Der zusammengestellte Kontext eines Turns."""

    fragments: list[ContextFragment] = Field(default_factory=list)
    total_tokens: int = 0
    budget: int
    dropped: list[str] = Field(default_factory=list)
    """Welche Provider wegen Budget entfielen — erscheint im Aktivitätsprotokoll."""

    @property
    def data_class(self) -> DataClass:
        """Höchste Klasse im Bündel. Bestimmt das zulässige Modell."""
        return escalate(*(f.data_class for f in self.fragments))

    @property
    def taint(self) -> TaintLevel:
        """Enthält das Bündel Fremdinhalt?"""
        if any(f.is_untrusted for f in self.fragments):
            return TaintLevel.TAINTED
        return TaintLevel.CLEAN

    def render(self) -> str:
        """Setzt die Fragmente zum Prompt-Abschnitt zusammen.

        Fremdinhalt wird ausgezeichnet abgegrenzt. Das ist eine
        Verteidigungslinie, nicht *die* Verteidigung — die trägt das
        Taint-Tracking.
        """
        parts: list[str] = []
        for fragment in sorted(self.fragments, key=lambda f: f.priority.value):
            if fragment.is_untrusted:
                parts.append(
                    f'<untrusted_content source="{fragment.source}">\n'
                    f"{fragment.content}\n"
                    f"</untrusted_content>"
                )
            else:
                parts.append(f"## {fragment.source}\n{fragment.content}")
        return "\n\n".join(parts)


class SalientEntity(BaseModel):
    """Eine im Gespräch erwähnte Entität — Grundlage der Referenzauflösung."""

    kind: Literal["person", "event", "document", "task", "project", "email"]
    label: str
    ref: str
    mentioned_at: datetime
    mention_count: int = 1
    gender: Literal["m", "f", "n", "unknown"] = "unknown"
    """Im Deutschen ein starkes Signal: 'ihm' schließt weibliche Kandidaten aus."""

    def salience(self, now: datetime, *, halflife_s: float = 300.0) -> float:
        age = max(0.0, (now - self.mentioned_at).total_seconds())
        recency: float = 0.5 ** (age / halflife_s)
        return recency * (1.0 + 0.2 * min(self.mention_count, 5))


class ReferenceResolution(BaseModel):
    """Ergebnis der Auflösung eines Pronomens oder Verweises."""

    reference: str
    resolved: SalientEntity | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    candidates: list[SalientEntity] = Field(default_factory=list)
    needs_clarification: bool = True

    def clarification_question(self) -> str | None:
        if not self.needs_clarification:
            return None
        if len(self.candidates) > 1:
            names = " oder ".join(c.label for c in self.candidates[:3])
            return f"Meinst du {names}?"
        return f"Wen genau meinst du mit „{self.reference}“?"
