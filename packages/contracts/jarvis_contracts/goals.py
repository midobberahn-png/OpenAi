"""Ziele, Projekte und Entitäten.

Siehe docs/17-identity-goals.md §3 und §4.

Die Entitätenschicht bedient bewusst drei getrennt entstandene Anforderungen:
Referenzauflösung („schreib *ihm*"), Ziele/Projekte und präzises Retrieval
ohne Vektorrauschen. Dass dieselbe Struktur alle drei trägt, ist das stärkste
Argument für ihren Zuschnitt — ein zusätzlicher Graph-Layer wäre eine vierte
Antwort auf dieselbe Frage.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .classification import DataClass

__all__ = [
    "Entity",
    "EntityKind",
    "EntityLink",
    "EntityRelation",
    "Goal",
    "GoalHorizon",
    "GoalProgress",
    "GoalStatus",
]


# --------------------------------------------------------------------------
# Ziele
# --------------------------------------------------------------------------


class GoalHorizon(StrEnum):
    TAG = "tag"
    WOCHE = "woche"
    MONAT = "monat"
    QUARTAL = "quartal"
    JAHR = "jahr"
    OFFEN = "offen"

    @property
    def is_project_scale(self) -> bool:
        """Projekte sind Ziele auf Quartalsebene oder darunter."""
        return self in {GoalHorizon.TAG, GoalHorizon.WOCHE, GoalHorizon.MONAT, GoalHorizon.QUARTAL}


class GoalStatus(StrEnum):
    AKTIV = "aktiv"
    PAUSIERT = "pausiert"
    ERREICHT = "erreicht"
    VERWORFEN = "verworfen"

    @property
    def is_open(self) -> bool:
        return self in {GoalStatus.AKTIV, GoalStatus.PAUSIERT}


class Goal(BaseModel):
    """Ein Ziel, Projekt oder Meilenstein.

    Bewusst kein Memory-Eintrag: Ein Ziel hat einen Zustand, einen Horizont,
    Fortschritt und Randbedingungen — und andere Objekte verweisen darauf.
    Ein Retrieval-Treffer beantwortet „Wie weit bin ich?" nicht.

    Projekte sind Ziele mit ``horizon <= quartal``, Meilensteine solche mit
    ``parent_id``. Eine eigene Tabelle je Ebene brächte keinen Gewinn.
    """

    id: UUID
    user_id: UUID
    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=4000)
    horizon: GoalHorizon = GoalHorizon.OFFEN
    status: GoalStatus = GoalStatus.AKTIV
    priority: int = Field(ge=1, le=5, default=3)
    parent_id: UUID | None = None

    constraints: list[str] = Field(default_factory=list, max_length=10)
    """Randbedingungen wie „nebenberuflich", „ohne Fremdkapital"."""

    target_date: date | None = None
    progress_note: str | None = Field(default=None, max_length=2000)
    """Zuletzt *festgestellter* Stand — nicht geschätzter."""

    data_class: DataClass = DataClass.P2
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def _completion_consistency(self) -> Goal:
        if self.status is GoalStatus.ERREICHT and self.completed_at is None:
            raise ValueError("Erreichte Ziele brauchen ein Abschlussdatum.")
        if self.parent_id == self.id:
            raise ValueError("Ein Ziel kann nicht sein eigenes Oberziel sein.")
        return self

    @property
    def is_project(self) -> bool:
        return self.horizon.is_project_scale and self.status.is_open


class GoalProgress(BaseModel):
    """Belegter Fortschritt eines Ziels.

    JARVIS leitet Fortschritt **nicht** aus Gesprächsverläufen ab, sondern
    ausschließlich aus verknüpften Objekten: erledigte Aufgaben, gehaltene
    Termine, erstellte Dokumente. Was sich nicht belegen lässt, wird als offen
    ausgewiesen — ein Assistent, der Fortschritt erfindet, ist schlimmer als
    einer, der keinen ausweist.
    """

    model_config = ConfigDict(frozen=True)

    goal_id: UUID
    tasks_done: int = 0
    tasks_open: int = 0
    linked_events: int = 0
    linked_documents: int = 0
    last_activity_at: datetime | None = None
    sub_goals_reached: int = 0
    sub_goals_total: int = 0

    @property
    def has_evidence(self) -> bool:
        return bool(
            self.tasks_done or self.linked_events or self.linked_documents or self.sub_goals_reached
        )

    def describe(self) -> str:
        """Menschenlesbarer Stand — ohne Schätzung."""
        if not self.has_evidence:
            return "Noch keine belegbare Aktivität."
        parts: list[str] = []
        if self.tasks_done or self.tasks_open:
            parts.append(f"{self.tasks_done} von {self.tasks_done + self.tasks_open} Aufgaben")
        if self.sub_goals_total:
            parts.append(f"{self.sub_goals_reached} von {self.sub_goals_total} Teilzielen")
        if self.linked_events:
            parts.append(f"{self.linked_events} Termine")
        if self.linked_documents:
            parts.append(f"{self.linked_documents} Dokumente")
        return ", ".join(parts)


# --------------------------------------------------------------------------
# Entitäten
# --------------------------------------------------------------------------


class EntityKind(StrEnum):
    PERSON = "person"
    ORGANISATION = "organisation"
    PROJEKT = "projekt"
    ORT = "ort"
    GOAL = "goal"
    THEMA = "thema"


class Entity(BaseModel):
    """Eine benannte Sache, auf die sich Gespräche und Objekte beziehen."""

    id: UUID
    user_id: UUID
    kind: EntityKind
    canonical_name: str = Field(min_length=1, max_length=200)
    aliases: list[str] = Field(default_factory=list, max_length=20)
    """„Thomas", „Thomas M.", „Herr Müller" — trägt die Namensauflösung."""

    gender: Literal["m", "f", "n", "unknown"] = "unknown"
    """Im Deutschen ein starkes Signal für die Referenzauflösung: „ihm"
    schließt weibliche Kandidaten aus."""

    attributes: dict[str, Any] = Field(default_factory=dict)
    """Rolle, E-Mail-Adresse, Beziehung — je nach ``kind``."""

    data_class: DataClass = DataClass.P2
    goal_id: UUID | None = None
    """Gesetzt, wenn ``kind == GOAL`` — verbindet Entität und Ziel."""

    last_mentioned_at: datetime | None = None
    mention_count: int = 0
    created_at: datetime

    @model_validator(mode="after")
    def _goal_kind_needs_goal(self) -> Entity:
        if self.kind is EntityKind.GOAL and self.goal_id is None:
            raise ValueError("Entitäten vom Typ 'goal' müssen auf ein Ziel verweisen.")
        return self

    def matches(self, name: str) -> bool:
        """Namensabgleich über kanonischen Namen und Aliase."""
        needle = name.strip().casefold()
        if needle == self.canonical_name.casefold():
            return True
        return any(needle == alias.casefold() for alias in self.aliases)

    def salience(self, now: datetime, *, halflife_s: float = 300.0) -> float:
        """Wie naheliegend ist diese Entität gerade als Bezugspunkt?"""
        if self.last_mentioned_at is None:
            return 0.0
        age = max(0.0, (now - self.last_mentioned_at).total_seconds())
        recency: float = 0.5 ** (age / halflife_s)
        return recency * (1.0 + 0.2 * min(self.mention_count, 5))


class EntityLink(BaseModel):
    """Verknüpfung einer Entität mit einem beliebigen Objekt.

    Ersetzt den vorgeschlagenen Knowledge Graph: „Was habe ich letzte Woche mit
    Thomas besprochen?" ist ein Join über ``entity_id`` plus Zeitfilter, kein
    Ähnlichkeitsproblem (docs/16-v1.1-review.md §3+4).
    """

    entity_id: UUID
    target_kind: Literal["memory", "document", "task", "goal", "message", "event"]
    target_id: UUID
    role: str | None = Field(default=None, max_length=60)
    """Etwa „Teilnehmer", „Autor", „Auftraggeber"."""

    created_at: datetime


class EntityRelation(BaseModel):
    """Beziehung zwischen zwei Entitäten.

    Bewusst schlicht gehalten: gerichtete Kante mit Typ. Reicht für „Thomas
    arbeitet an Projekt X" und „Projekt X gehört zu Ziel Y", ohne eine zweite
    Abfragesprache einzuführen.
    """

    from_entity_id: UUID
    to_entity_id: UUID
    relation: str = Field(min_length=1, max_length=60)
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    created_at: datetime

    @model_validator(mode="after")
    def _no_self_relation(self) -> EntityRelation:
        if self.from_entity_id == self.to_entity_id:
            raise ValueError("Eine Entität kann nicht mit sich selbst in Beziehung stehen.")
        return self
