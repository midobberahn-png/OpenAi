"""Routing — harte Filter vor jeder Abwägung.

Der Router ist die Stelle, an der entschieden wird, *wohin* Daten gehen.
Entsprechend prüft diese Suite vor allem, was er nicht tut: kein Cloud-Modell
für P3, kein Gewicht, das ein Filter aufwiegt, kein Modellwunsch, der eine
Zulassung erzeugt.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from jarvis_contracts import (
    Capability,
    Complexity,
    DataClass,
    Intent,
    ModelCapability,
    TurnClassification,
)
from jarvis_core.orchestrator import HealthSnapshot, NoEligibleModel, RoutingPreferences, route

pytestmark = pytest.mark.security


LOCAL = ModelCapability(
    name="llama-3.1-8b",
    provider="ollama",
    max_data_class=DataClass.P3,
    context_window=128_000,
    supports_tools=True,
    p50_latency_ms=250,
    is_local=True,
)

CLOUD_FAST = ModelCapability(
    name="cloud-fast",
    provider="anbieter_a",
    max_data_class=DataClass.P1,
    context_window=200_000,
    supports_tools=True,
    cost_per_1m_in=Decimal("0.30"),
    cost_per_1m_out=Decimal("1.50"),
    p50_latency_ms=400,
)

CLOUD_STRONG = ModelCapability(
    name="cloud-strong",
    provider="anbieter_b",
    max_data_class=DataClass.P2,
    context_window=1_000_000,
    supports_tools=True,
    supports_vision=True,
    cost_per_1m_in=Decimal("3.00"),
    cost_per_1m_out=Decimal("15.00"),
    p50_latency_ms=1_200,
)

FLEET = (LOCAL, CLOUD_FAST, CLOUD_STRONG)


def _classification(
    data_class: DataClass = DataClass.P1,
    *,
    capabilities: list[Capability] | None = None,
    wish: str | None = None,
) -> TurnClassification:
    return TurnClassification(
        intent=Intent.TASK,
        complexity=Complexity.SIMPLE,
        data_class=data_class,
        required_capabilities=capabilities or [],
        explicit_model_request=wish,
    )


class TestHarteFilter:
    @pytest.mark.invariant("data-class-hard-filter")
    def test_p3_geht_nur_lokal(self) -> None:
        decision = route(_classification(DataClass.P3), FLEET)
        assert decision.model == LOCAL.name
        assert "cloud-strong" in decision.rejected

    @pytest.mark.invariant("data-class-hard-filter")
    def test_fehlkonfiguriertes_cloud_modell_bekommt_kein_p3(self) -> None:
        """``max_data_class`` ist Konfiguration und kann falsch gesetzt sein.
        Die zweite Barriere hängt nicht an ihr, sondern an ``is_local`` — sonst
        genügte ein Tippfehler in einer YAML-Datei, damit Gesundheitsdaten das
        Gerät verlassen."""
        misconfigured = CLOUD_STRONG.model_copy(update={"max_data_class": DataClass.P3})
        decision = route(_classification(DataClass.P3), [LOCAL, misconfigured])
        assert decision.model == LOCAL.name
        assert "ausschließlich lokal" in decision.rejected[misconfigured.name]

    def test_fehlende_faehigkeit_schliesst_aus(self) -> None:
        decision = route(
            _classification(DataClass.P1, capabilities=[Capability.VISION]),
            [CLOUD_FAST, CLOUD_STRONG],
        )
        assert decision.model == CLOUD_STRONG.name
        assert "Fehlende Fähigkeit" in decision.rejected[CLOUD_FAST.name]

    def test_ausgefallener_anbieter_wird_uebergangen(self) -> None:
        health = HealthSnapshot(unavailable_providers=frozenset({"anbieter_b"}))
        decision = route(_classification(DataClass.P2), FLEET, health=health)
        assert decision.model != CLOUD_STRONG.name
        assert "nicht erreichbar" in decision.rejected[CLOUD_STRONG.name]

    def test_kein_zulaessiges_modell_ist_ein_fehler_kein_rueckfall(self) -> None:
        """Lieber kein Ergebnis als das falsche Ziel."""
        with pytest.raises(NoEligibleModel):
            route(_classification(DataClass.P3), [CLOUD_FAST, CLOUD_STRONG])


class TestModellwunsch:
    def test_wunsch_waehlt_innerhalb_der_kandidaten(self) -> None:
        decision = route(_classification(DataClass.P1, wish="cloud-strong"), FLEET)
        assert decision.model == CLOUD_STRONG.name
        assert "Ausdrücklich angefordert" in decision.reason

    @pytest.mark.invariant("data-class-hard-filter")
    def test_wunsch_erzeugt_keine_zulassung(self) -> None:
        """„Nutze cloud-strong“ bei P3-Daten wählt nicht cloud-strong.
        Ein Wunsch trifft eine Auswahl; er verschiebt keine Grenze."""
        decision = route(_classification(DataClass.P3, wish="cloud-strong"), FLEET)
        assert decision.model == LOCAL.name
        assert CLOUD_STRONG.name in decision.rejected

    def test_unbekannter_wunsch_wird_begruendet_verworfen(self) -> None:
        decision = route(_classification(DataClass.P1, wish="gpt-9"), FLEET)
        assert decision.model in {m.name for m in FLEET}
        assert "gpt-9" in decision.rejected


class TestAbwaegung:
    def test_gewichte_entscheiden_nur_innerhalb_der_kandidaten(self) -> None:
        prefs = RoutingPreferences(quality={"cloud-strong": 1.0, "llama-3.1-8b": 0.2})
        assert route(_classification(DataClass.P2), FLEET, prefs=prefs).model == CLOUD_STRONG.name
        # Dieselben Gewichte, aber P3: Die Bewertung ändert nichts am Filter.
        assert route(_classification(DataClass.P3), FLEET, prefs=prefs).model == LOCAL.name

    def test_lokale_bevorzugung_wirkt_bei_gleicher_eignung(self) -> None:
        prefs = RoutingPreferences(prefer_local=True)
        assert route(_classification(DataClass.P1), FLEET, prefs=prefs).model == LOCAL.name

    def test_entscheidung_ist_reproduzierbar(self) -> None:
        """Punktgleichheit wird alphabetisch aufgelöst; ohne diesen Tie-Break
        hinge das Ergebnis an der Reihenfolge der Modellliste."""
        forward = route(_classification(DataClass.P2), FLEET)
        backward = route(_classification(DataClass.P2), tuple(reversed(FLEET)))
        assert forward.model == backward.model

    def test_rueckfall_wird_als_solcher_ausgewiesen(self) -> None:
        health = HealthSnapshot(unavailable_providers=frozenset({"anbieter_a", "anbieter_b"}))
        decision = route(
            _classification(DataClass.P1, capabilities=[Capability.VISION]),
            FLEET,
            health=health,
        )
        assert decision.is_fallback
        assert decision.model == LOCAL.name

    def test_jede_entscheidung_traegt_eine_begruendung(self) -> None:
        """Briefing §2: Das verwendete Modell wird transparent gemacht —
        sinnvoll nur mitsamt dem Warum."""
        decision = route(_classification(DataClass.P2), FLEET)
        assert decision.reason.strip().endswith(".")
        assert str(DataClass.P2) in decision.reason
