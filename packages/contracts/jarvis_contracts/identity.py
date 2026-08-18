"""Identity & Preference Engine.

Siehe docs/17-identity-goals.md.

Beantwortet die Frage, die V1.0 offenließ: *Wie soll ich mich diesem Menschen
gegenüber verhalten?* — getrennt von *Was weiß ich über ihn?* (Memory) und
*Woran arbeitet er?* (Goals).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .memory import SourceType
from .permissions import TimeWindow

__all__ = [
    "CORE_PROFILE_TOKEN_BUDGET",
    "BehaviourRule",
    "CoreProfile",
    "DomainPreference",
    "Formality",
    "PreferenceDomain",
    "Proactivity",
    "ResponseLength",
]


CORE_PROFILE_TOKEN_BUDGET = 400
"""Harte Obergrenze für das immer geladene Kernprofil.

Nicht kosmetisch: Im Sprachpfad stehen laut docs/08-voice.md §6 insgesamt
4.000 Kontext-Token zur Verfügung, und die Prompt-Länge geht direkt in die
Zeit bis zum ersten Token ein. Eine Präferenzschicht ohne Budget frisst genau
das Latenzbudget auf, das Sprachbedienung benutzbar macht.
"""


class Formality(StrEnum):
    DU = "du"
    SIE = "sie"


class ResponseLength(StrEnum):
    KNAPP = "knapp"
    NORMAL = "normal"
    AUSFUEHRLICH = "ausführlich"


class Proactivity(StrEnum):
    """Wie oft darf JARVIS ungefragt sprechen?"""

    AUS = "aus"
    DEZENT = "dezent"
    NORMAL = "normal"
    AKTIV = "aktiv"

    @property
    def max_per_day(self) -> int:
        return {"aus": 0, "dezent": 2, "normal": 5, "aktiv": 12}[self.value]


class PreferenceDomain(StrEnum):
    MAIL = "mail"
    CALENDAR = "calendar"
    TASKS = "tasks"
    RESEARCH = "research"
    VOICE = "voice"
    MODELS = "models"
    SMARTHOME = "smarthome"


class CoreProfile(BaseModel):
    """Bei jedem Turn im Prompt. Klein gehalten, weil es überall mitfährt."""

    model_config = ConfigDict(frozen=True)

    address_as: str = Field(min_length=1, max_length=60)
    formality: Formality = Formality.DU
    language: str = Field(default="de", min_length=2, max_length=10)
    response_length: ResponseLength = ResponseLength.NORMAL
    timezone: str = "Europe/Berlin"
    working_hours: TimeWindow | None = None
    proactivity: Proactivity = Proactivity.DEZENT

    hard_rules: list[str] = Field(default_factory=list, max_length=5)
    """Höchstens fünf, je höchstens 120 Zeichen.

    Wer zwanzig Regeln hat, hat keine Regeln — weder für ein Modell noch für
    einen Menschen. Die Grenze erzwingt die Priorisierung.
    """

    @model_validator(mode="after")
    def _rules_are_short(self) -> CoreProfile:
        for rule in self.hard_rules:
            if len(rule) > 120:
                raise ValueError(
                    f"Verhaltensregel zu lang ({len(rule)} Zeichen, max. 120): {rule[:40]}…"
                )
            if not rule.strip():
                raise ValueError("Leere Verhaltensregel ist unzulässig.")
        return self

    def estimated_tokens(self) -> int:
        """Grobe Schätzung — 4 Zeichen je Token ist für Deutsch brauchbar."""
        text = " ".join(
            [
                self.address_as,
                self.language,
                self.timezone,
                self.response_length.value,
                self.proactivity.value,
                *self.hard_rules,
            ]
        )
        return len(text) // 4 + 40  # Aufschlag für Feldnamen und Struktur

    def fits_budget(self) -> bool:
        return self.estimated_tokens() <= CORE_PROFILE_TOKEN_BUDGET


class DomainPreference(BaseModel):
    """Domänenspezifische Präferenz — nur geladen, wenn die Domäne im Spiel ist."""

    id: UUID
    user_id: UUID
    domain: PreferenceDomain
    key: str = Field(min_length=1, max_length=80)
    value: Any
    source: SourceType
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    updated_at: datetime


class BehaviourRule(BaseModel):
    """Do/Don't-Regel für Stil und Verhalten.

    **Steuert niemals Berechtigungen.** „Frag nicht jedes Mal nach" ist eine
    Stilregel und darf keine Policy-Entscheidung verändern; wer weniger
    Bestätigungen will, ändert das im Permission Center — dort ist die Änderung
    sichtbar, auditiert und widerrufbar.

    Ohne diese Trennung wäre eine per Prompt Injection eingeschleuste
    „Verhaltensregel" ein Weg zur Rechteerweiterung.
    """

    id: UUID
    user_id: UUID
    kind: Literal["do", "dont"]
    rule: str = Field(min_length=1, max_length=200)
    domain: PreferenceDomain | None = None
    priority: int = Field(ge=1, le=5, default=3)
    source: SourceType
    enabled: bool = True

    @model_validator(mode="after")
    def _no_permission_language(self) -> BehaviourRule:
        """Erkennt den offensichtlichen Missbrauchsversuch.

        Kein vollständiger Schutz — die eigentliche Absicherung ist, dass die
        Policy Engine Verhaltensregeln gar nicht liest. Diese Prüfung fängt
        versehentliche Formulierungen früh ab und macht die Grenze sichtbar.
        """
        lowered = self.rule.lower()
        forbidden = [
            "ohne nachfrage",
            "ohne rückfrage",
            "ohne bestätigung",
            "nicht nachfragen",
            "frag nicht",
            "immer erlauben",
            "keine bestätigung",
        ]
        for phrase in forbidden:
            if phrase in lowered:
                raise ValueError(
                    f"Verhaltensregeln dürfen keine Berechtigungen ändern "
                    f"(gefunden: {phrase!r}). Bestätigungsverhalten wird "
                    f"ausschließlich im Permission Center eingestellt."
                )
        return self
