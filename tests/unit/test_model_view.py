"""Was ein Modell von einem Werkzeugergebnis zu sehen bekommt.

Bis hierher: die Zusammenfassung eines Schrittes, also für ``files.read`` Pfad
und Bytezahl. Der Alltagsfall „lies X und fasse zusammen" lief damit durch und
antwortete „ich kenne den Inhalt nicht" — ausführbar und wertlos.

Ab hier fließen Werkzeugdaten in den Prompt, und damit steht Fremdinhalt darin.
Die Entscheidung ist in drei Achsen gefallen (ADR-014):

**A — deklarierte Projektion.** Ein Werkzeug erklärt, welche Felder seines
Ergebnisses ein Modell sehen darf (``model_visible_fields``). Vorgabe ist
**leer**: Wer nichts erklärt, gibt nichts preis. Dieselbe Beweislast wie bei
``payload_inspectability`` und ``forbidden_when_tainted`` — Werkzeuge müssen
sich ausdrücklich öffnen, nicht ausdrücklich schließen.

**B — Kappung auf dem modellzugewandten Weg.** Nicht im Werkzeug: Die 256 KB
von ``files.read`` gehen an den *Eigentümer* über HTTP, und ihn zu beschneiden,
weil ein Modell mitliest, verschlechtert das Werkzeug für seinen Zweck. Zwei
Verbraucher, zwei Grenzen.

**C — Auszeichnung als Komfort, nicht als Schutz.** Fremdinhalt steht in einem
eigenen, markierten Block. Das verbessert das Verhalten und **sichert nichts
ab**: Ein Modell lässt sich aus einer Trennmarke herausreden. Diese Suite prüft
deshalb, dass die Marke da ist — und ausdrücklich nicht, dass sie wirkt. Wer
hier einen Test „Injection wird durch die Marke verhindert" ergänzt, hat die
Zusage missverstanden.

Abgesichert wird weiterhin an den Stellen, die es können: Taint-Tracking sperrt
Werkzeuge, die Datenklassifikation sperrt Modelle.
"""

from __future__ import annotations

import pytest

from jarvis_contracts import (
    DataClass,
    PayloadInspectability,
    RiskLevel,
    ToolResult,
    ToolSpec,
)
from jarvis_core.orchestrator.plan_context import MAX_MODELLSICHT, modellsicht

pytestmark = pytest.mark.security


def _spec(**kw: object) -> ToolSpec:
    basis: dict[str, object] = {
        "name": "files.read",
        "description": "Liest eine Datei und liefert ihren Inhalt zurück.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}},
        "risk": RiskLevel.LOW,
        "scopes": ["files.read"],
        "data_class": DataClass.P2,
        "forbidden_when_tainted": False,
        "reads_untrusted_content": True,
        "payload_inspectability": PayloadInspectability.STRUCTURED,
    }
    basis.update(kw)
    return ToolSpec(**basis)  # type: ignore[arg-type]


ERGEBNIS = ToolResult(
    ok=True,
    data={
        "path": "/heim/notiz.md",
        "text": "Kickoff am Mittwoch.",
        "bytes_read": 20,
        "truncated": False,
    },
    display="/heim/notiz.md — 20 Bytes",
)


class TestDeklarierteProjektion:
    @pytest.mark.invariant("tool-result-model-view-is-declared")
    def test_ohne_deklaration_sieht_das_modell_nichts(self) -> None:
        """**Die Vorgabe ist die Zusage.**

        Ein Werkzeug, das nichts erklärt, gibt nichts in einen Prompt. Wäre die
        Vorgabe „alles", entschiede jedes künftige Werkzeug stillschweigend
        mit, was ein Modell liest — und niemand sähe es im Diff.
        """
        assert modellsicht(_spec(), ERGEBNIS) == ""

    @pytest.mark.invariant("tool-result-model-view-is-declared")
    def test_nur_deklarierte_felder_gehen_durch(self) -> None:
        sicht = modellsicht(_spec(model_visible_fields=["text"]), ERGEBNIS)
        assert "Kickoff am Mittwoch." in sicht
        assert "/heim/notiz.md" not in sicht, "Der Pfad war nicht deklariert."
        assert "bytes_read" not in sicht

    def test_mehrere_felder_werden_benannt(self) -> None:
        """Damit ein Modell weiß, was es liest — zwei nackte Werte sind
        nicht zuzuordnen."""
        sicht = modellsicht(_spec(model_visible_fields=["path", "text"]), ERGEBNIS)
        assert "path" in sicht and "text" in sicht

    def test_ein_deklariertes_feld_das_fehlt_stoert_nicht(self) -> None:
        """Ein Werkzeug darf ein Feld je nach Fall weglassen — etwa im
        Fehlerfall. Eine Ausnahme dafür wäre ein Absturz auf einem Weg, der
        ohnehin schon schiefging."""
        leer = ToolResult(ok=False, error="verweigert", data=None, display="Zugriff verweigert")
        assert modellsicht(_spec(model_visible_fields=["text"]), leer) == ""

    def test_ein_gescheitertes_ergebnis_gibt_nichts_preis(self) -> None:
        """Bei ``ok=False`` steht in ``error`` womöglich ein Pfad oder eine
        Meldung des Dateisystems. Nichts davon ist deklariert, also geht
        nichts davon in den Prompt."""
        gescheitert = ToolResult(
            ok=False, error="/geheim/pfad nicht lesbar", display="Datei nicht lesbar"
        )
        assert "geheim" not in modellsicht(_spec(model_visible_fields=["text"]), gescheitert)


class TestKappung:
    @pytest.mark.invariant("tool-result-model-view-is-declared")
    def test_langer_inhalt_wird_gekappt(self) -> None:
        """Die Zahlen: ``files.read`` liefert bis 256.000 Bytes, das
        Kontextfenster fasst 128.000 Token. Eine einzige Datei könnte die
        Hälfte belegen — bei jedem Folgeschritt erneut."""
        lang = ToolResult(ok=True, data={"text": "x" * 500_000}, display="viel")
        sicht = modellsicht(_spec(model_visible_fields=["text"]), lang)
        assert len(sicht) <= MAX_MODELLSICHT + 200, len(sicht)

    def test_die_kappung_wird_benannt(self) -> None:
        """Ein Modell, das ein Fragment für das Ganze hält, fasst falsch
        zusammen — und sagt nicht dazu, dass es rät."""
        lang = ToolResult(ok=True, data={"text": "x" * 500_000}, display="viel")
        assert "gekürzt" in modellsicht(_spec(model_visible_fields=["text"]), lang)

    def test_kurzer_inhalt_bleibt_unangetastet(self) -> None:
        sicht = modellsicht(_spec(model_visible_fields=["text"]), ERGEBNIS)
        assert "gekürzt" not in sicht


class TestAuszeichnung:
    """**Komfort, nicht Schutz** — und deshalb prüft diese Klasse nur, dass die
    Marke da ist.

    Ein Test, der behauptete, die Marke verhindere etwas, wäre die Art Zusage,
    die dieses Projekt dreimal teuer bezahlt hat: eine Aussage ohne
    Mechanismus. Was Fremdinhalt folgenlos macht, sind Taint-Gate und
    Datenklassifikation.
    """

    def test_fremdinhalt_steht_in_einem_erkennbaren_block(self) -> None:
        sicht = modellsicht(_spec(model_visible_fields=["text"]), ERGEBNIS)
        assert sicht.startswith("---"), sicht[:40]
        assert "Daten" in sicht

    def test_die_marke_nennt_das_werkzeug(self) -> None:
        """Damit im Verlauf mehrerer Schritte zuzuordnen ist, woher was stammt."""
        assert "files.read" in modellsicht(_spec(model_visible_fields=["text"]), ERGEBNIS)
