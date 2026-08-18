"""Gedächtnis: Datensätze, Provenienz, Abfragen.

Siehe docs/05-memory-context.md.

Grundsatz: Nichts wird blind gespeichert. Jeder Eintrag trägt Provenienz und
Konfidenz, damit auf die Frage 'woher weißt du das?' eine Antwort existiert.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .classification import DataClass

__all__ = [
    "DEFAULT_RETRIEVAL_WEIGHTS",
    "MemoryCandidate",
    "MemoryHit",
    "MemoryKind",
    "MemoryQuery",
    "MemoryRecord",
    "MemoryStatus",
    "Provenance",
    "RetrievalWeights",
    "SourceType",
]


class MemoryKind(StrEnum):
    SEMANTIC_FACT = "semantic_fact"
    PREFERENCE = "preference"
    EPISODIC = "episodic"
    ENTITY = "entity"
    PROCEDURE = "procedure"

    def __str__(self) -> str:
        return self.value


class MemoryStatus(StrEnum):
    CANDIDATE = "candidate"
    """Extrahiert, aber noch nicht bestätigt — liegt in der Kuratierungsqueue."""

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    """Durch einen neueren Eintrag ersetzt. Bleibt erhalten, damit
    nachvollziehbar ist, was JARVIS wann geglaubt hat."""

    REJECTED = "rejected"

    def __str__(self) -> str:
        return self.value


class SourceType(StrEnum):
    USER_STATED = "user_stated"
    """Vom Nutzer ausdrücklich gesagt. Höchste Konfidenz."""

    INFERRED = "inferred"
    """Vom Modell abgeleitet. Geht immer in die Kuratierungsqueue."""

    IMPORTED = "imported"
    OBSERVED = "observed"

    @property
    def auto_acceptable(self) -> bool:
        return self is SourceType.USER_STATED

    def __str__(self) -> str:
        return self.value


class Provenance(BaseModel):
    """Herkunft eines Gedächtniseintrags. Ohne diese Felder ist ein
    Langzeitgedächtnis nicht auditierbar."""

    model_config = ConfigDict(frozen=True)

    source_type: SourceType
    message_id: UUID | None = None
    document_id: UUID | None = None
    email_id: str | None = None
    run_id: UUID | None = None
    note: str | None = None

    def describe(self) -> str:
        """Menschenlesbare Antwort auf 'woher weißt du das?'"""
        match self.source_type:
            case SourceType.USER_STATED:
                return "Du hast es mir gesagt."
            case SourceType.INFERRED:
                return "Ich habe es aus unserem Gespräch abgeleitet."
            case SourceType.IMPORTED:
                return "Aus einer importierten Quelle."
            case SourceType.OBSERVED:
                return "Aus einer beobachteten Aktion."


class MemoryRecord(BaseModel):
    """Ein Fakt. Bewusst ein Fakt pro Datensatz — das macht Korrektur und
    Löschung präzise."""

    id: UUID
    user_id: UUID
    kind: MemoryKind
    content: str = Field(min_length=1, max_length=4000)
    structured: dict[str, Any] | None = None
    data_class: DataClass = DataClass.P2
    provenance: Provenance
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    status: MemoryStatus = MemoryStatus.CANDIDATE
    superseded_by: UUID | None = None
    importance: float = Field(ge=0.0, le=1.0, default=0.5)
    access_count: int = 0
    last_accessed_at: datetime | None = None
    valid_from: datetime
    valid_until: datetime | None = None
    retention_until: datetime | None = None

    @model_validator(mode="after")
    def _superseded_needs_target(self) -> MemoryRecord:
        if self.status is MemoryStatus.SUPERSEDED and self.superseded_by is None:
            raise ValueError("Ersetzte Einträge müssen auf ihren Nachfolger verweisen.")
        return self

    def is_valid_at(self, moment: datetime) -> bool:
        if self.status is not MemoryStatus.ACTIVE:
            return False
        if self.valid_from > moment:
            return False
        return self.valid_until is None or self.valid_until > moment


class MemoryCandidate(BaseModel):
    """Extrahierter Kandidat vor der Übernahme ins Gedächtnis."""

    content: str = Field(min_length=1, max_length=4000)
    kind: MemoryKind
    data_class: DataClass = DataClass.P2
    provenance: Provenance
    confidence: float = Field(ge=0.0, le=1.0)
    conflicts_with: list[UUID] = Field(default_factory=list)
    """Bestehende Einträge, denen dieser Kandidat widerspricht."""

    def auto_acceptable(self, *, threshold: float = 0.9) -> bool:
        """Automatisch übernommen werden nur ausdrückliche Aussagen mit hoher
        Konfidenz und ohne Widerspruch."""
        return (
            self.provenance.source_type.auto_acceptable
            and self.confidence >= threshold
            and not self.conflicts_with
        )


class RetrievalWeights(BaseModel):
    """Gewichtung des hybriden Retrievals.

    Wird gegen die Eval-Suite kalibriert, nicht nach Gefühl gesetzt
    (docs/15-testing.md §4.2).
    """

    model_config = ConfigDict(frozen=True)

    semantic: float = Field(ge=0.0, le=1.0, default=0.55)
    keyword: float = Field(ge=0.0, le=1.0, default=0.25)
    recency: float = Field(ge=0.0, le=1.0, default=0.10)
    importance: float = Field(ge=0.0, le=1.0, default=0.10)
    recency_halflife_days: float = Field(gt=0, default=30.0)

    @model_validator(mode="after")
    def _sums_to_one(self) -> RetrievalWeights:
        total = self.semantic + self.keyword + self.recency + self.importance
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Retrieval-Gewichte müssen sich zu 1.0 summieren, sind {total}.")
        return self


DEFAULT_RETRIEVAL_WEIGHTS = RetrievalWeights()


class MemoryQuery(BaseModel):
    """Abfrage gegen das Gedächtnis."""

    user_id: UUID
    query: str = Field(min_length=1)
    kinds: list[MemoryKind] = Field(default_factory=list)
    k: int = Field(default=8, ge=1, le=100)
    max_data_class: DataClass = DataClass.P3
    """Sicherheitsrelevant: Geht der Turn an ein Cloud-Modell, dürfen
    P3-Erinnerungen nicht in die Ergebnismenge gelangen."""

    weights: RetrievalWeights = DEFAULT_RETRIEVAL_WEIGHTS
    include_superseded: bool = False


class MemoryHit(BaseModel):
    """Ein Treffer mit aufgeschlüsselter Bewertung — wichtig fürs Debugging
    schlechter Retrieval-Ergebnisse."""

    record: MemoryRecord
    score: float
    semantic_score: float = 0.0
    keyword_score: float = 0.0
    recency_score: float = 0.0
    matched_by: Literal["semantic", "keyword", "both"] = "both"
