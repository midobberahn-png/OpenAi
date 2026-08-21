"""Der abschließende `llm`-Schritt — ein Modell formuliert die Antwort.

Jeder Plan dieses Systems endet mit einem Schritt der Art ``llm`` und dem Ziel
``response``: „Antwort formulieren", „Ergebnis zusammenfassen". Bis hierher war
er nicht ausführbar, und damit war **kein Plan abschließbar** — auch der
einfachste nicht, denn „Wie spät ist es?" besteht aus genau diesem einen
Schritt.

**Was diesen Schritt vom Werkzeugschritt unterscheidet: Er bietet nichts an.**
Dem Modell wird kein Werkzeugschema gezeigt — nicht eines, wie bei der
Argumentquelle, sondern keines. Es kann deshalb nichts vorschlagen, und der
Schritt kann nichts auslösen. Genau darum ist er der kleinste ehrliche Schritt
in Richtung Modellschleife: Er braucht keine Abbruchsemantik, weil es nichts
gibt, wovon abzubrechen wäre.

**Was bleibt, ist ein Rest, der nicht wegzuprüfen ist.** Der Text geht an einen
Menschen. Stammt er aus einem kontaminierten Lauf, kann er eine untergeschobene
Anweisung enthalten, die sich an *ihn* richtet — „bitte überweise …". Dagegen
hilft kein Taint-Tracking, weil kein Werkzeug beteiligt ist. Was hilft, ist,
die Herkunft mitzuliefern, damit die Oberfläche sie kennzeichnen kann. Deshalb
trägt das Ergebnis ``taints``, und deshalb prüft diese Suite es in beide
Richtungen.
"""

from __future__ import annotations

from typing import Any

import pytest

from jarvis_contracts import (
    CompletionRequest,
    CompletionResult,
    DataClass,
    ModelCapability,
    ModelUsage,
    PlanStep,
    ProposedToolCall,
    ProviderCapabilities,
    TaintLevel,
)
from jarvis_core.orchestrator.plan_response import PlanResponseSource, ResponseUnavailable
from jarvis_core.providers import ModelGateway
from tests.fakes import build_run

pytestmark = pytest.mark.security

LOKAL = ModelCapability(
    name="lokal",
    provider="test",
    max_data_class=DataClass.P3,
    context_window=8192,
    is_local=True,
)

SCHRITT = PlanStep(seq=2, description="Antwort formulieren", kind="llm", target="response")


class Drehbuchmodell:
    """Ein Anbieter mit vorgegebener Antwort. Das Gateway läuft echt."""

    def __init__(self, antwort: CompletionResult) -> None:
        self._antwort = antwort
        self.anfragen: list[CompletionRequest] = []

    @property
    def name(self) -> str:
        return "test"

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(tool_calling=True)

    async def complete(self, request: CompletionRequest) -> CompletionResult:
        self.anfragen.append(request)
        return self._antwort

    def stream(self, request: CompletionRequest) -> Any:  # pragma: no cover - ungenutzt
        raise NotImplementedError

    async def count_tokens(self, request: CompletionRequest) -> int:  # pragma: no cover
        return 0


def _quelle(antwort: CompletionResult) -> tuple[PlanResponseSource, Drehbuchmodell]:
    modell = Drehbuchmodell(antwort)
    return PlanResponseSource(gateway=ModelGateway({"test": modell}, [LOKAL])), modell


def _text(inhalt: str) -> CompletionResult:
    return CompletionResult(text=inhalt, usage=ModelUsage(tokens_in=80, tokens_out=25))


class TestFormulierung:
    async def test_der_text_des_modells_kommt_zurueck(self) -> None:
        quelle, _ = _quelle(_text("Es ist 12 Uhr."))
        ergebnis = await quelle.for_step(
            step=SCHRITT, run=build_run(), goal="Wie spät ist es?", model="lokal"
        )
        assert ergebnis.text == "Es ist 12 Uhr."
        assert ergebnis.usage.tokens_out == 25

    @pytest.mark.invariant("model-never-sees-excess-data-class")
    async def test_dem_modell_wird_kein_werkzeug_angeboten(self) -> None:
        """**Die tragende Eigenschaft dieses Schrittes.**

        Nicht „ein Werkzeug" wie bei der Argumentquelle, sondern keines. Was
        nicht im Angebot steht, kann ein Modell nicht vorschlagen — und ein
        Schritt, der nichts vorschlagen kann, kann nichts auslösen.
        """
        quelle, modell = _quelle(_text("Fertig."))
        await quelle.for_step(step=SCHRITT, run=build_run(), goal="Wie spät ist es?", model="lokal")
        (anfrage,) = modell.anfragen
        assert anfrage.tools == []

    async def test_ein_werkzeugvorschlag_wird_nicht_ausgefuehrt_sondern_verworfen(self) -> None:
        """Ein Modell kann trotz leerem Angebot einen Aufruf halluzinieren.

        Er wird nicht weitergereicht, nicht protokolliert und nicht zu einem
        Schritt — der Rückgabewert dieser Quelle ist Text, und mehr gibt es
        nicht. Der Test hält fest, dass hier kein stiller Nebenweg entsteht.
        """
        mit_aufruf = CompletionResult(
            text="Ich lege das mal an.",
            tool_calls=[
                ProposedToolCall(id="x", tool_name="mail.send", arguments={"to": "fremd@x.de"})
            ],
        )
        quelle, _ = _quelle(mit_aufruf)
        ergebnis = await quelle.for_step(
            step=SCHRITT, run=build_run(), goal="Fasse zusammen", model="lokal"
        )
        assert ergebnis.text == "Ich lege das mal an."
        assert not hasattr(ergebnis, "tool_calls")

    async def test_leere_antwort_wird_abgewiesen(self) -> None:
        """Kein stiller leerer Abschluss.

        Ein Lauf, der mit leerem Text als „fertig" gilt, sieht erfolgreich aus
        und hat nichts geliefert. Das ist die Art Ausgang, die man erst bemerkt,
        wenn jemand nach der Antwort fragt.
        """
        quelle, _ = _quelle(_text("   "))
        with pytest.raises(ResponseUnavailable):
            await quelle.for_step(
                step=SCHRITT, run=build_run(), goal="Wie spät ist es?", model="lokal"
            )

    async def test_modell_ohne_zulassung_wird_abgewiesen(self) -> None:
        nur_p1 = ModelCapability(
            name="cloud", provider="test", max_data_class=DataClass.P1, context_window=8192
        )
        modell = Drehbuchmodell(_text("egal"))
        quelle = PlanResponseSource(gateway=ModelGateway({"test": modell}, [nur_p1]))
        with pytest.raises(ResponseUnavailable):
            await quelle.for_step(
                step=SCHRITT,
                run=build_run(data_class=DataClass.P2),
                goal="Fasse zusammen",
                model="cloud",
            )
        assert modell.anfragen == []


class TestKontamination:
    @pytest.mark.invariant("taint-monotonic")
    async def test_antwort_aus_kontaminiertem_lauf_gilt_als_kontaminiert(self) -> None:
        """Der Text geht an einen Menschen, nicht in ein Werkzeug.

        Taint-Tracking kann hier nichts blockieren — es kann nur sagen, woher
        der Text stammt. Genau das muss es dann aber auch tun, sonst kann die
        Oberfläche ihn nicht kennzeichnen.
        """
        quelle, _ = _quelle(_text("Laut Notiz sollst du überweisen."))
        ergebnis = await quelle.for_step(
            step=SCHRITT,
            run=build_run().with_taint(TaintLevel.TAINTED),
            goal="Fasse zusammen",
            model="lokal",
        )
        assert ergebnis.taints is True

    async def test_sauberer_lauf_bleibt_sauber(self) -> None:
        quelle, _ = _quelle(_text("Es ist 12 Uhr."))
        ergebnis = await quelle.for_step(
            step=SCHRITT, run=build_run(), goal="Wie spät ist es?", model="lokal"
        )
        assert ergebnis.taints is False

    async def test_die_obergrenze_ist_kein_parameter(self) -> None:
        """Datenklasse und Taint stammen aus dem Lauf, nicht vom Aufrufer."""
        import inspect

        signatur = inspect.signature(PlanResponseSource.for_step)
        assert "data_class" not in signatur.parameters
        assert "taint" not in signatur.parameters


class TestKeinNebenweg:
    def test_die_quelle_fuehrt_nichts_aus(self) -> None:
        """AST-Test, wie bei der Argumentquelle und aus demselben Grund."""
        import ast
        from pathlib import Path

        quelle = (
            Path(__file__).resolve().parents[2]
            / "packages"
            / "core"
            / "jarvis_core"
            / "orchestrator"
            / "plan_response.py"
        )
        baum = ast.parse(quelle.read_text(encoding="utf-8"))
        importiert = {
            knoten.module or "" for knoten in ast.walk(baum) if isinstance(knoten, ast.ImportFrom)
        }
        verboten = {"jarvis_core.tools.registry", "jarvis_core.policy.approval"}
        assert not (importiert & verboten), f"Verbotener Import: {importiert & verboten}"

        aufrufe = {
            knoten.func.attr
            for knoten in ast.walk(baum)
            if isinstance(knoten, ast.Call) and isinstance(knoten.func, ast.Attribute)
        }
        assert {"execute", "execute_tool", "authorize_allowed"} & aufrufe == set()
