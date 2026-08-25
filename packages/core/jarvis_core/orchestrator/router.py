"""Stufe 3 — Modellwahl.

Siehe docs/04-orchestrator.md §3 und §4.

Der Router ist **kein Modell**, sondern eine reine Funktion über der
Klassifikation. Eine Modellwahl, die selbst von einem Modell getroffen wird,
ist weder reproduzierbar noch testbar noch gegen Prompt Injection abgesichert:
Sie wäre der Punkt, an dem ein präparierter Text entscheidet, wohin die Daten
gehen.

Die Reihenfolge der Prüfungen ist bedeutungstragend:

1. **Harte Filter** — Datenklasse, Fähigkeiten, Erreichbarkeit. Nicht
   verhandelbar, nicht gewichtbar.
2. **Ausdrücklicher Wunsch** — gilt nur *innerhalb* der Kandidatenmenge. Ein
   Wunsch kann eine Auswahl treffen, aber keine Zulassung erzeugen.
3. **Gewichtung** — Eignung, Latenz, Kosten. Erst hier wird abgewogen.

Wer die Schritte 1 und 2 tauscht, hat einen Router, dem man mit einem Satz im
Nutzertext die Datenklassifikation aushebelt.
"""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from jarvis_contracts import (
    Capability,
    DataClass,
    ModelCapability,
    RoutingDecision,
    TurnClassification,
)

__all__ = ["HealthSnapshot", "NoEligibleModel", "RoutingPreferences", "route"]


class NoEligibleModel(Exception):
    """Kein Modell erfüllt die harten Anforderungen.

    Ausdrücklich ein Fehler und kein stiller Rückfall: Ein Router, der bei
    fehlenden lokalen Kandidaten ersatzweise ein Cloud-Modell wählt, wäre genau
    die Umgehung, gegen die die Datenklassifikation existiert. Lieber kein
    Ergebnis als das falsche Ziel — der Fehler wird dem Nutzer benannt
    (docs/04-orchestrator.md §9).
    """


class HealthSnapshot(BaseModel):
    """Erreichbarkeit der Anbieter zum Zeitpunkt der Entscheidung."""

    model_config = ConfigDict(frozen=True)

    unavailable_providers: frozenset[str] = frozenset()

    def is_up(self, provider: str) -> bool:
        return provider not in self.unavailable_providers


class RoutingPreferences(BaseModel):
    """Gewichte der Abwägung — Konfiguration, kein Code.

    Die Gewichte wirken ausschließlich innerhalb der bereits gefilterten
    Kandidatenmenge. Kein Gewicht kann ein Modell zulassen, das die
    Datenklasse nicht führen darf; das ist der Unterschied zwischen einer
    Präferenz und einem Filter.
    """

    model_config = ConfigDict(frozen=True)

    quality_weight: float = Field(default=1.0, ge=0.0)
    latency_weight: float = Field(default=0.5, ge=0.0)
    cost_weight: float = Field(default=0.3, ge=0.0)

    quality: dict[str, float] = Field(default_factory=dict)
    """Eignung je Modellname (0…1). Aus Evals gespeist, nicht geschätzt.
    Unbekannte Modelle erhalten ``default_quality``."""

    default_quality: float = Field(default=0.5, ge=0.0, le=1.0)

    prefer_local: bool = False
    """Bevorzugt lokale Modelle bei sonst vergleichbarer Bewertung — etwa im
    Offline-Betrieb oder bei knappem Tagesbudget."""

    local_bonus: float = Field(default=0.15, ge=0.0)


def route(
    classification: TurnClassification,
    models: Sequence[ModelCapability],
    *,
    health: HealthSnapshot | None = None,
    prefs: RoutingPreferences | None = None,
    local_only: bool = False,
) -> RoutingDecision:
    """Wählt ein Modell für diesen Turn.

    Deterministisch: Dieselbe Klassifikation, dieselbe Modellliste und
    dieselben Gewichte ergeben dieselbe Entscheidung — bis hin zur
    Reihenfolge bei Punktgleichheit.

    ``local_only`` verengt die Kandidatenmenge auf Modelle, die auf diesem
    Gerät laufen. Es steht bei den **harten Filtern** und nicht bei den
    Gewichten, und das ist die ganze Entscheidung: ``prefs.prefer_local`` gibt
    einen Bonus, den ein besseres Cloud-Modell überbietet — ein erschöpftes
    Tagesbudget ist keine Vorliebe. Wer es als Gewicht führte, hätte eine
    Kostengrenze, die bei genügend Qualitätsvorsprung nachgibt.
    """
    snapshot = health or HealthSnapshot()
    weights = prefs or RoutingPreferences()

    rejected: dict[str, str] = {}
    candidates = [
        model
        for model in models
        if _admit(model, classification, snapshot, rejected=rejected, local_only=local_only)
    ]

    if not candidates:
        return _fallback(classification, models, snapshot, weights, rejected)

    if classification.explicit_model_request:
        wish = _resolve_wish(classification.explicit_model_request, candidates)
        if wish is not None:
            return RoutingDecision(
                model=wish.name,
                provider=wish.provider,
                reason=f"Ausdrücklich angefordert: „{classification.explicit_model_request}“.",
                max_data_class=wish.max_data_class,
                rejected=rejected,
            )
        rejected.setdefault(
            classification.explicit_model_request,
            "Angefordertes Modell ist für diese Datenklasse oder Fähigkeit nicht zugelassen.",
        )

    best = _best(candidates, weights)
    for model in candidates:
        if model.name != best.name:
            rejected.setdefault(model.name, "Niedriger bewertet (Eignung, Latenz, Kosten).")

    return RoutingDecision(
        model=best.name,
        provider=best.provider,
        reason=_reason(best, classification, weights),
        max_data_class=best.max_data_class,
        rejected=rejected,
    )


# --------------------------------------------------------------------------
# Harte Filter
# --------------------------------------------------------------------------


def _admit(
    model: ModelCapability,
    classification: TurnClassification,
    health: HealthSnapshot,
    *,
    rejected: dict[str, str],
    local_only: bool = False,
) -> bool:
    """Drei Filter, jeder mit Begründung für die Oberfläche.

    Die Begründungen sind kein Beiwerk: „Ich nutze gerade ein anderes Modell“
    ohne Grund ist für den Nutzer nicht überprüfbar — und damit ist die
    Zusicherung, dass P3 lokal bleibt, nicht nachvollziehbar.
    """
    if not model.accepts(classification.data_class):
        rejected[model.name] = (
            f"Nicht für {classification.data_class} zugelassen "
            f"(zulässig bis {model.max_data_class})."
        )
        return False

    if classification.data_class is DataClass.P3 and not model.is_local:
        # Zweite, unabhängige Barriere: ``max_data_class`` ist Konfiguration und
        # kann fehlerhaft gesetzt sein. P3 bleibt strukturell auf dem Gerät —
        # eine Fehlkonfiguration darf daran nichts ändern.
        rejected[model.name] = "P3 wird ausschließlich lokal verarbeitet."
        return False

    if not model.supports(classification.required_capabilities):
        missing = [
            capability
            for capability in classification.required_capabilities
            if not model.supports([capability])
        ]
        rejected[model.name] = "Fehlende Fähigkeit: " + ", ".join(str(m) for m in missing) + "."
        return False

    if not health.is_up(model.provider):
        rejected[model.name] = f"Anbieter {model.provider} ist nicht erreichbar."
        return False

    if local_only and not model.is_local:
        # Die Begründung landet in der Oberfläche. „Ich nutze gerade ein
        # anderes Modell" ohne Grund ist für einen Nutzer nicht überprüfbar —
        # und bei einer *Kosten*grenze ist der Grund die Auskunft, die er
        # eigentlich sucht.
        rejected[model.name] = "Tagesbudget erschöpft — bis Mitternacht nur lokale Modelle."
        return False

    return True


def _fallback(
    classification: TurnClassification,
    models: Sequence[ModelCapability],
    health: HealthSnapshot,
    prefs: RoutingPreferences,
    rejected: dict[str, str],
) -> RoutingDecision:
    """Letzter Versuch: lokal, mit gelockerten *Fähigkeiten*.

    Gelockert wird ausschließlich, was Komfort betrifft. Die Datenklasse bleibt
    ein hartes Filter — sonst wäre der Fallback der Weg, auf dem P3-Daten das
    Gerät verlassen, sobald ein Anbieter ausfällt.
    """
    local = [
        model
        for model in models
        if model.is_local
        and model.accepts(classification.data_class)
        and health.is_up(model.provider)
    ]
    if not local:
        raise NoEligibleModel(
            f"Kein Modell ist für {classification.data_class} zugelassen und erreichbar. "
            "Abgelehnt: "
            + ("; ".join(f"{name}: {reason}" for name, reason in sorted(rejected.items())) or "—")
        )

    best = _best(local, prefs)
    return RoutingDecision(
        model=best.name,
        provider=best.provider,
        reason="Rückfall auf ein lokales Modell — kein regulärer Kandidat verfügbar.",
        max_data_class=best.max_data_class,
        is_fallback=True,
        rejected=rejected,
    )


# --------------------------------------------------------------------------
# Gewichtung
# --------------------------------------------------------------------------


def _best(candidates: Sequence[ModelCapability], prefs: RoutingPreferences) -> ModelCapability:
    """Höchste Bewertung; bei Gleichstand der alphabetisch erste Name.

    Der Tie-Break ist keine Formalie: Ohne ihn hinge das Ergebnis an der
    Reihenfolge der Modellliste, und die Entscheidung wäre nicht reproduzierbar.
    """
    return max(
        sorted(candidates, key=lambda m: m.name),
        key=lambda m: _score(m, candidates, prefs),
    )


def _score(
    model: ModelCapability, field: Sequence[ModelCapability], prefs: RoutingPreferences
) -> float:
    quality = prefs.quality.get(model.name, prefs.default_quality)
    latency = 1.0 - _normalized(
        float(model.p50_latency_ms), [float(m.p50_latency_ms) for m in field]
    )
    cost = 1.0 - _normalized(_cost_of(model), [_cost_of(m) for m in field])

    score = (
        prefs.quality_weight * quality + prefs.latency_weight * latency + prefs.cost_weight * cost
    )
    if prefs.prefer_local and model.is_local:
        score += prefs.local_bonus
    return score


def _cost_of(model: ModelCapability) -> float:
    """Ein-/Ausgabe zusammengefasst; Ausgaben wiegen schwerer, weil sie es
    in der Abrechnung tun."""
    return float(model.cost_per_1m_in + Decimal(3) * model.cost_per_1m_out)


def _normalized(value: float, field: Sequence[float]) -> float:
    """Min-Max-Normierung über die Kandidatenmenge.

    Ohne Bezug auf die Menge wären Latenz und Kosten nicht vergleichbar — ein
    Modell mit 400 ms und eines mit 2000 ms unterscheiden sich anders als
    0,05 € und 0,50 €.
    """
    low, high = min(field), max(field)
    if high <= low:
        return 0.0
    return (value - low) / (high - low)


def _resolve_wish(request: str, candidates: Sequence[ModelCapability]) -> ModelCapability | None:
    """Löst „nutze Claude“ auf ein zugelassenes Modell auf.

    Gesucht wird nur in der bereits gefilterten Menge: Ein Wunsch wählt aus,
    was ohnehin zulässig ist. Bei mehreren Treffern gewinnt der alphabetisch
    erste — wieder aus Gründen der Reproduzierbarkeit.
    """
    needle = request.strip().lower()
    matches = [
        model
        for model in sorted(candidates, key=lambda m: m.name)
        if needle in model.name.lower() or needle == model.provider.lower()
    ]
    if not matches and needle in {"lokal", "lokales modell", "local"}:
        matches = [model for model in sorted(candidates, key=lambda m: m.name) if model.is_local]
    return matches[0] if matches else None


def _reason(
    model: ModelCapability, classification: TurnClassification, prefs: RoutingPreferences
) -> str:
    """Begründung für die Oberfläche.

    Briefing §2 verlangt Transparenz über das verwendete Modell — sinnvoll ist
    sie nur mitsamt dem *Warum*.
    """
    parts = [f"Datenklasse {classification.data_class} zulässig"]
    if model.is_local:
        parts.append("lokal verarbeitet")
    if Capability.VISION in classification.required_capabilities:
        parts.append("bildfähig")
    if Capability.LONG_CONTEXT in classification.required_capabilities:
        parts.append(f"Kontextfenster {model.context_window:,}".replace(",", "."))
    if prefs.prefer_local and model.is_local:
        parts.append("lokale Verarbeitung bevorzugt")
    parts.append("beste Bewertung aus Eignung, Latenz und Kosten")
    return ", ".join(parts) + "."
