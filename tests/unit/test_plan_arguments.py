"""Argumente eines Planschrittes, formuliert von einem Modell.

Bis hierher hat ein Mensch die Werkzeugargumente getippt. Ab hier formuliert
sie ein Modell, und damit ändert sich die Beweislage: Der Payload-Hash der
Bestätigung ist keine Formalie mehr, sondern die Stelle, an der Angezeigtes
und Ausgeführtes übereinstimmen.

Diese Suite hält die Eigenschaften fest, die den Unterschied tragen. Vier davon
sind Verengungen gegenüber einer gewöhnlichen Werkzeugschleife:

1. **Das Werkzeug steht fest.** Der Plan nennt es; das Modell füllt nur die
   Argumente. Nennt es ein anderes, wird der Schritt abgewiesen — nicht das
   Werkzeug getauscht.
2. **Das Angebot ist eins.** Dem Modell wird genau ein Werkzeugschema gezeigt,
   nicht der Katalog. Was es nicht sieht, kann es nicht vorschlagen.
3. **Die Antwort erbt die Kontamination ihres Kontextes.** Ein Lauf, der eine
   Datei gelesen hat, bekommt keine sauberen Argumente zurück.
4. **Sie führt nichts aus.** Der Rückgabewert ist ein Argumentobjekt, kein
   Ergebnis. Ausgeführt wird über denselben Weg wie eine Absicht des Nutzers.
"""

from __future__ import annotations

from typing import Any

import pytest

from jarvis_contracts import (
    CompletionRequest,
    CompletionResult,
    DataClass,
    ModelCapability,
    PayloadInspectability,
    PlanStep,
    ProposedToolCall,
    ProviderCapabilities,
    RiskLevel,
    TaintLevel,
    ToolSpec,
)
from jarvis_core.orchestrator.plan_arguments import (
    ArgumentsUnavailable,
    PlanArgumentSource,
)
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

TERMIN = ToolSpec(
    name="calendar.create",
    description="Legt einen Termin im Kalender an, mit oder ohne Teilnehmer.",
    parameters={
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "start": {"type": "string"},
            "end": {"type": "string"},
            "attendees": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["title", "start", "end"],
        "additionalProperties": False,
    },
    scopes=["calendar.create"],
    risk=RiskLevel.MEDIUM,
    data_class=DataClass.P2,
    requires_preview=True,
    payload_inspectability=PayloadInspectability.STRUCTURED,
    outbound_fields=["attendees"],
)

SCHRITT = PlanStep(seq=1, description="Termin anlegen", kind="tool", target="calendar.create")

VORSCHLAG = {
    "title": "Abstimmung",
    "start": "2026-09-01T10:00:00+02:00",
    "end": "2026-09-01T11:00:00+02:00",
}


class Drehbuchmodell:
    """Ein Anbieter, der eine vorgegebene Antwort liefert und die Anfrage merkt.

    Kein Mock des Gateways: Der Adapter sitzt am Port, das Gateway läuft echt.
    Sonst prüfte die Suite, ob eine Attrappe tut, was man ihr sagt.
    """

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


def _quelle(antwort: CompletionResult) -> tuple[PlanArgumentSource, Drehbuchmodell]:
    modell = Drehbuchmodell(antwort)
    return PlanArgumentSource(gateway=ModelGateway({"test": modell}, [LOKAL])), modell


def _mit_vorschlag(argumente: dict[str, Any], *, name: str = "calendar.create") -> CompletionResult:
    return CompletionResult(
        tool_calls=[ProposedToolCall(id="a1", tool_name=name, arguments=argumente)]
    )


class TestFormulierung:
    async def test_argumente_des_modells_werden_zurueckgegeben(self) -> None:
        quelle, _ = _quelle(_mit_vorschlag(VORSCHLAG))
        ergebnis = await quelle.for_step(
            spec=TERMIN, step=SCHRITT, run=build_run(), goal="Termin anlegen", model="lokal"
        )
        assert ergebnis.arguments == VORSCHLAG

    async def test_dem_modell_wird_genau_ein_werkzeug_gezeigt(self) -> None:
        """Der Katalog ist kein Angebot an dieser Stelle.

        Der Plan hat das Werkzeug bereits bestimmt und der Nutzer hat den Plan
        gesehen. Ein zweites Werkzeug im Schema wäre eine Wahl, die niemand
        angekündigt hat.
        """
        quelle, modell = _quelle(_mit_vorschlag(VORSCHLAG))
        await quelle.for_step(
            spec=TERMIN, step=SCHRITT, run=build_run(), goal="Termin anlegen", model="lokal"
        )
        (anfrage,) = modell.anfragen
        assert [w["name"] for w in anfrage.tools] == ["calendar.create"]

    async def test_fremdes_werkzeug_im_vorschlag_wird_abgewiesen(self) -> None:
        """Nicht getauscht, nicht ignoriert — abgewiesen.

        Ein Modell, das ein anderes Werkzeug nennt, hat den Plan verlassen.
        Den Vorschlag stillschweigend auf das geplante Werkzeug umzubiegen
        führte Argumente aus, die für etwas anderes formuliert wurden.
        """
        quelle, _ = _quelle(_mit_vorschlag(VORSCHLAG, name="mail.send"))
        with pytest.raises(ArgumentsUnavailable) as abgewiesen:
            await quelle.for_step(
                spec=TERMIN, step=SCHRITT, run=build_run(), goal="Termin anlegen", model="lokal"
            )
        assert "mail.send" in str(abgewiesen.value)

    async def test_antwort_ohne_werkzeugaufruf_wird_abgewiesen(self) -> None:
        """Kein Raten. Ein Modell, das nur Text liefert, hat nichts geliefert."""
        quelle, _ = _quelle(CompletionResult(text="Ich bräuchte noch das Datum."))
        with pytest.raises(ArgumentsUnavailable):
            await quelle.for_step(
                spec=TERMIN, step=SCHRITT, run=build_run(), goal="Termin anlegen", model="lokal"
            )


class TestKontamination:
    @pytest.mark.invariant("taint-monotonic")
    async def test_kontaminierter_lauf_liefert_kontaminierte_argumente(self) -> None:
        """Die Argumente erben, was im Kontext stand.

        Das ist die Eigenschaft, an der der ganze Zuschnitt hängt: Ein Modell,
        das eine präparierte Datei gelesen hat, formuliert Argumente, die als
        Fremdinhalt gelten — und das Taint-Gate entscheidet danach, ob sie eine
        Bestätigung bekommen oder gar nicht erst laufen.
        """
        quelle, _ = _quelle(_mit_vorschlag(VORSCHLAG))
        ergebnis = await quelle.for_step(
            spec=TERMIN,
            step=SCHRITT,
            run=build_run().with_taint(TaintLevel.TAINTED),
            goal="Termin anlegen",
            model="lokal",
        )
        assert ergebnis.taints is True

    async def test_sauberer_lauf_bleibt_sauber(self) -> None:
        """Die Gegenprobe. „Jede Modellantwort ist Fremdinhalt" wäre die
        naheliegende Regel und würde nach dem ersten Aufruf jeden Lauf
        kontaminieren — der Widerspruch aus V1.0."""
        quelle, _ = _quelle(_mit_vorschlag(VORSCHLAG))
        ergebnis = await quelle.for_step(
            spec=TERMIN, step=SCHRITT, run=build_run(), goal="Termin anlegen", model="lokal"
        )
        assert ergebnis.taints is False

    async def test_der_taint_geht_in_den_gateway_aufruf(self) -> None:
        """Nicht als Feld der Anfrage — als getrennter Parameter.

        ``CompletionRequest`` trägt weder Datenklasse noch Taint, damit kein
        Aufrufer seine eigene Obergrenze mitbringt. Geprüft wird deshalb am
        Ergebnis und nicht an der Anfrage.
        """
        quelle, modell = _quelle(_mit_vorschlag(VORSCHLAG))
        await quelle.for_step(
            spec=TERMIN,
            step=SCHRITT,
            run=build_run().with_taint(TaintLevel.TAINTED),
            goal="Termin anlegen",
            model="lokal",
        )
        (anfrage,) = modell.anfragen
        assert not hasattr(anfrage, "taint")
        assert not hasattr(anfrage, "data_class")


class TestObergrenze:
    @pytest.mark.invariant("model-never-sees-excess-data-class")
    async def test_die_datenklasse_stammt_aus_dem_lauf_und_nicht_vom_aufrufer(self) -> None:
        """Ein Lauf, dessen Modell nur P1 darf, bekommt für P2-Daten nichts.

        ``for_step`` nimmt keine Datenklasse entgegen; sie stammt aus dem
        persistierten Lauf. Ein Parameter dafür wäre die Obergrenze als Angabe
        des Aufrufers — dieselbe Lücke wie ``user_id`` im Request-Body.
        """
        import inspect

        signatur = inspect.signature(PlanArgumentSource.for_step)
        assert "data_class" not in signatur.parameters
        assert "taint" not in signatur.parameters

    async def test_modell_ohne_zulassung_wird_abgewiesen(self) -> None:
        """Fail closed: Das Gateway lehnt ab, und die Ablehnung wird zur
        Abweisung des Schrittes — nicht zu einem leeren Argumentobjekt."""
        nur_p1 = ModelCapability(
            name="cloud", provider="test", max_data_class=DataClass.P1, context_window=8192
        )
        modell = Drehbuchmodell(_mit_vorschlag(VORSCHLAG))
        quelle = PlanArgumentSource(gateway=ModelGateway({"test": modell}, [nur_p1]))
        with pytest.raises(ArgumentsUnavailable):
            await quelle.for_step(
                spec=TERMIN,
                step=SCHRITT,
                run=build_run(data_class=DataClass.P2),
                goal="Termin anlegen",
                model="cloud",
            )
        # Und der Adapter wurde nicht einmal gefragt.
        assert modell.anfragen == []


class TestKeinNebenweg:
    async def test_die_quelle_fuehrt_nichts_aus(self) -> None:
        """Ein AST-Test, weil eine Absicht im Kopf des Autors nicht trägt.

        Die Argumentquelle darf keine Registry, keinen Executor und kein
        Approval Gateway kennen. Sie liefert Daten; ausgeführt wird über
        denselben Weg wie eine Absicht des Nutzers.
        """
        import ast
        from pathlib import Path

        quelle = (
            Path(__file__).resolve().parents[2]
            / "packages"
            / "core"
            / "jarvis_core"
            / "orchestrator"
            / "plan_arguments.py"
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
        assert "execute" not in aufrufe
        assert "execute_tool" not in aufrufe
        assert "authorize_allowed" not in aufrufe
