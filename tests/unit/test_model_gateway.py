"""Model Gateway — was ein Modell überhaupt sehen darf.

Die Angriffsflächen dieses Blocks stehen im Review: Prompt Injection,
Tool-Call-Injection, unvertrauenswürdige Modellausgabe, P3-Abfluss,
Taint-Ausbreitung über den Modellkontext.

Diese Suite deckt die Seite ab, die *vor* dem Aufruf liegt — wer wen fragen
darf. Was mit der Antwort geschieht, prüft die Executor-Suite; dass ein
Werkzeugvorschlag kein Auftrag ist, prüfen beide.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from jarvis_contracts import (
    CompletionRequest,
    CompletionResult,
    DataClass,
    Message,
    MessageRole,
    ModelCapability,
    ModelUsage,
    ProposedToolCall,
    ProviderCapabilities,
    TaintLevel,
)
from jarvis_core.providers import ModelGateway, ModelNotPermitted

pytestmark = pytest.mark.security


LOKAL = ModelCapability(
    name="llama-3.1-8b",
    provider="ollama",
    max_data_class=DataClass.P3,
    context_window=128_000,
    is_local=True,
)

CLOUD_P1 = ModelCapability(
    name="cloud-fast",
    provider="anbieter_a",
    max_data_class=DataClass.P1,
    context_window=200_000,
    cost_per_1m_in=Decimal("0.30"),
)

CLOUD_P2 = ModelCapability(
    name="cloud-stark",
    provider="anbieter_b",
    max_data_class=DataClass.P2,
    context_window=1_000_000,
)

FEHLKONFIGURIERT = ModelCapability(
    name="cloud-verrutscht",
    provider="anbieter_b",
    max_data_class=DataClass.P3,
    context_window=200_000,
    is_local=False,
)
"""Ein Cloud-Modell, das in der Konfiguration versehentlich P3 führt.

Genau dieser Fall ist der Grund für die zweite Prüfung: ``max_data_class`` ist
eine Zeile in einer Datei, ``is_local`` eine Eigenschaft des Deployments.
"""


CLOUD_OHNE_VORHALTUNG = ModelCapability(
    name="cloud-p1-ohne-zusage",
    provider="anbieter_a",
    max_data_class=DataClass.P1,
    context_window=200_000,
    is_local=False,
)
"""Ein Cloud-Modell, das P1 führt — ohne hinterlegte Zero-Retention-Zusage.

Die Lage, die vor dieser Regel unbemerkt durchging: ``zero_retention`` stand im
Vertrag und wurde von nichts gelesen."""

CLOUD_MIT_VORHALTUNG = ModelCapability(
    name="cloud-p1-mit-zusage",
    provider="anbieter_a",
    max_data_class=DataClass.P1,
    context_window=200_000,
    zero_retention=True,
    is_local=False,
)


class NotierenderProvider:
    """Merkt sich, was er zu sehen bekommen hat.

    Der wichtigste Nachweis dieser Suite ist wieder eine Null: dass der
    Provider bei einer unzulässigen Anfrage *gar nichts* gesehen hat. Ein
    Adapter, der die Anfrage bekommt und sie selbst ablehnt, hätte die Daten
    bereits im Speicher — und bei einem Netzwerkadapter im Netz.
    """

    def __init__(self, name: str, *, antwort: CompletionResult | None = None) -> None:
        self._name = name
        self.gesehen: list[CompletionRequest] = []
        self._antwort = antwort or CompletionResult(text="fertig", provider=name)

    @property
    def name(self) -> str:
        return self._name

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities()

    async def complete(self, request: CompletionRequest) -> CompletionResult:
        self.gesehen.append(request)
        return self._antwort

    def stream(self, request: CompletionRequest):  # pragma: no cover - hier ungenutzt
        raise NotImplementedError

    async def count_tokens(self, request: CompletionRequest) -> int:
        return sum(len(m.content) // 4 for m in request.messages)


def _gateway(*modelle: ModelCapability) -> tuple[ModelGateway, dict[str, NotierenderProvider]]:
    provider = {name: NotierenderProvider(name) for name in {m.provider for m in modelle}}
    return ModelGateway(provider, modelle), provider


def _anfrage(model: str = "llama-3.1-8b") -> CompletionRequest:
    return CompletionRequest(
        model=model,
        messages=[Message(role=MessageRole.USER, content="Was steht in meinem Arztbrief?")],
    )


class TestDatenklasse:
    @pytest.mark.invariant("model-never-sees-excess-data-class")
    async def test_p3_erreicht_kein_cloud_modell(self) -> None:
        """Der Kern der Zusicherung — und der Nachweis ist, dass der Adapter
        nichts gesehen hat."""
        gateway, provider = _gateway(LOKAL, CLOUD_P2)

        with pytest.raises(ModelNotPermitted) as abgelehnt:
            await gateway.complete(_anfrage("cloud-stark"), data_class=DataClass.P3)

        assert abgelehnt.value.code == "data-class-exceeded"
        assert provider["anbieter_b"].gesehen == [], "Der Anbieter darf die Daten nie sehen"

    @pytest.mark.invariant("model-never-sees-excess-data-class")
    async def test_fehlkonfiguration_rettet_kein_cloud_modell(self) -> None:
        """``max_data_class`` ist Konfiguration und kann falsch gesetzt sein.
        Die zweite Barriere hängt an ``is_local`` — sonst genügte ein
        Tippfehler in einer YAML-Datei, damit Gesundheitsdaten das Gerät
        verlassen."""
        gateway, provider = _gateway(LOKAL, FEHLKONFIGURIERT)

        with pytest.raises(ModelNotPermitted) as abgelehnt:
            await gateway.complete(_anfrage("cloud-verrutscht"), data_class=DataClass.P3)

        assert abgelehnt.value.code == "p3-must-stay-local"
        assert provider["anbieter_b"].gesehen == []

    async def test_p3_erreicht_das_lokale_modell(self) -> None:
        """Der Gegentest. Ohne ihn wäre nicht gezeigt, dass der Schutz den
        Normalfall durchlässt — und ein Schutz, der das nicht tut, wird
        abgeschaltet."""
        gateway, provider = _gateway(LOKAL)
        ergebnis = await gateway.complete(_anfrage(), data_class=DataClass.P3)

        assert ergebnis.text == "fertig"
        assert len(provider["ollama"].gesehen) == 1

    async def test_p2_erreicht_kein_p1_modell(self) -> None:
        gateway, provider = _gateway(CLOUD_P1)
        with pytest.raises(ModelNotPermitted) as abgelehnt:
            await gateway.complete(_anfrage("cloud-fast"), data_class=DataClass.P2)
        assert abgelehnt.value.code == "data-class-exceeded"
        assert provider["anbieter_a"].gesehen == []


class TestFailClosed:
    async def test_unbekanntes_modell_wird_abgewiesen(self) -> None:
        """Der Katalog entscheidet, was zugelassen ist — nicht die Anfrage."""
        gateway, _ = _gateway(LOKAL)
        with pytest.raises(ModelNotPermitted) as abgelehnt:
            await gateway.complete(_anfrage("gibt-es-nicht"), data_class=DataClass.P0)
        assert abgelehnt.value.code == "model-unknown"

    async def test_fehlender_anbieter_faellt_nicht_zurueck(self) -> None:
        """Kein „nimm halt ein anderes": Ein fehlender Adapter ist ein Fehler,
        keine Gelegenheit zur Ersatzwahl. Die Modellwahl gehört dem Router."""
        gateway = ModelGateway({}, [LOKAL])
        with pytest.raises(ModelNotPermitted) as abgelehnt:
            await gateway.complete(_anfrage(), data_class=DataClass.P1)
        assert abgelehnt.value.code == "provider-missing"

    def test_die_anfrage_traegt_keinen_sicherheitskontext(self) -> None:
        """``CompletionRequest`` hat weder Datenklasse noch Taint.

        Wäre beides ein Feld, könnte der Aufrufer seine eigene Obergrenze
        setzen — derselbe Fehler wie beim früheren ``allowed_data_class``, der
        auf die Werkzeugklasse zurückfiel.
        """
        felder = set(CompletionRequest.model_fields)
        assert "data_class" not in felder
        assert "taint" not in felder
        assert "allowed_data_class" not in felder


class TestKontamination:
    @pytest.mark.invariant("taint-monotonic")
    async def test_ein_kontaminierter_lauf_kontaminiert_die_antwort(self) -> None:
        """Ein Adapter kann nicht wissen, was im Kontext des Aufrufs stand.

        Meldet er ``taints_context=False``, während der Lauf kontaminiert ist,
        gilt trotzdem der Lauf — sonst wäre der Modellaufruf die Waschmaschine,
        die die Agentenkette nicht sein durfte.
        """
        sauber_gemeldet = CompletionResult(text="harmlos", taints_context=False)
        gateway = ModelGateway(
            {"ollama": NotierenderProvider("ollama", antwort=sauber_gemeldet)}, [LOKAL]
        )

        ergebnis = await gateway.complete(
            _anfrage(), data_class=DataClass.P2, taint=TaintLevel.TAINTED
        )
        assert ergebnis.taints_context is True
        assert ergebnis.taint_level is TaintLevel.TAINTED

    def test_antworten_gelten_standardmaessig_als_fremdinhalt(self) -> None:
        """Die vorsichtige Richtung: Wer ``False`` setzt, behauptet, den
        gesamten Kontext zu kennen."""
        assert CompletionResult().taints_context is True


class TestWerkzeugvorschlaege:
    @pytest.mark.invariant("model-tool-calls-are-proposals")
    def test_ein_vorschlag_traegt_keine_erlaubnis(self) -> None:
        """Die zentrale Entscheidung dieses Blocks, geprüft an der Struktur.

        Ein Feld wie ``approved``, ``risk`` oder ``scope`` in dieser Klasse
        wäre eine Abkürzung am Sicherheitssockel vorbei — jemand würde sie
        früher oder später lesen, statt die Policy zu fragen.
        """
        felder = set(ProposedToolCall.model_fields)
        assert felder == {"id", "tool_name", "arguments"}
        for verboten in ("approved", "risk", "scope", "allowed", "confirmed"):
            assert verboten not in felder

    @pytest.mark.invariant("model-tool-calls-are-proposals")
    def test_der_name_sagt_was_es_ist(self) -> None:
        """``ProposedToolCall`` und nicht ``ToolCall``.

        Die verbreitete Bauart nennt dieselbe Struktur ``tool_call`` und
        behandelt sie als Anweisung. Von dort ist es ein kleiner Schritt zu
        einer Schleife, die Modellausgabe ausführt.
        """
        assert ProposedToolCall.__name__.startswith("Proposed")

    def test_ein_vorschlag_darf_halluziniert_sein(self) -> None:
        """Der Werkzeugname wird hier nicht geprüft — die Registry entscheidet,
        ob es ihn gibt, und der Fehler bleibt vom Berechtigungsfehler
        unterscheidbar."""
        vorschlag = ProposedToolCall(id="1", tool_name="mail.destroy_universe")
        assert vorschlag.tool_name == "mail.destroy_universe"


class TestKatalogauskunft:
    def test_verfuegbare_modelle_folgen_denselben_regeln(self) -> None:
        """Die Auskunft für die Oberfläche darf nicht großzügiger sein als die
        Prüfung — zwei Fassungen derselben Regel laufen auseinander, und die
        zweite ist dann die, die P3 durchlässt."""
        gateway, _ = _gateway(LOKAL, CLOUD_P1, CLOUD_P2, FEHLKONFIGURIERT)

        assert [m.name for m in gateway.available_models(up_to=DataClass.P3)] == ["llama-3.1-8b"]
        assert {m.name for m in gateway.available_models(up_to=DataClass.P1)} == {
            "llama-3.1-8b",
            "cloud-fast",
            "cloud-stark",
            "cloud-verrutscht",
        }

    def test_ohne_anbieter_kein_modell(self) -> None:
        gateway = ModelGateway({}, [LOKAL, CLOUD_P1])
        assert gateway.available_models(up_to=DataClass.P1) == []


class TestVerbrauch:
    def test_die_nutzung_traegt_keine_inhalte(self) -> None:
        """``ModelUsage`` landet in Protokollen und Kostenübersichten. Dort
        haben Prompt und Antwort nichts verloren."""
        felder = set(ModelUsage.model_fields)
        for verboten in ("prompt", "text", "messages", "content", "response"):
            assert verboten not in felder


class TestGrenzeDerWolke:
    """Was ein Anbieter sehen darf, der nicht auf diesem Gerät läuft.

    Die Tabelle aus docs/00-uebersicht.md §8 hatte bis zum ersten fremden
    Anbieter keinen Leser. Sie lautet: P0 immer, P1 nur mit
    Zero-Retention-Zusage, P2 nur nach ausdrücklicher Freigabe, P3 nie.

    Der Nachweis ist wie überall in dieser Suite die **Null**: Der Adapter darf
    die Daten nicht einmal im Speicher gehabt haben.
    """

    @pytest.mark.invariant("cloud-limited-to-p1-with-zero-retention")
    async def test_p0_geht_an_jeden_anbieter(self) -> None:
        gateway, provider = _gateway(LOKAL, CLOUD_OHNE_VORHALTUNG)

        await gateway.complete(_anfrage("cloud-p1-ohne-zusage"), data_class=DataClass.P0)

        assert len(provider["anbieter_a"].gesehen) == 1

    @pytest.mark.invariant("cloud-limited-to-p1-with-zero-retention")
    async def test_p1_ohne_zusage_erreicht_den_anbieter_nicht(self) -> None:
        """Der Fall, für den ``zero_retention`` im Vertrag steht.

        Ohne diese Prüfung war das Feld eine Absichtserklärung — dasselbe
        Muster wie ``supports_undo`` vor dem Undo-Weg.
        """
        gateway, provider = _gateway(LOKAL, CLOUD_OHNE_VORHALTUNG)

        with pytest.raises(ModelNotPermitted) as abgelehnt:
            await gateway.complete(_anfrage("cloud-p1-ohne-zusage"), data_class=DataClass.P1)

        assert abgelehnt.value.code == "cloud-needs-zero-retention"
        assert provider["anbieter_a"].gesehen == []

    @pytest.mark.invariant("cloud-limited-to-p1-with-zero-retention")
    async def test_p1_mit_zusage_geht_durch(self) -> None:
        """Die Gegenprobe, und sie ist der wichtigere Test.

        Eine Regel, die den zugesagten Normalfall blockiert, wird abgeschaltet
        — dieselbe Lehre wie beim Sanitization-Gate.
        """
        gateway, provider = _gateway(LOKAL, CLOUD_MIT_VORHALTUNG)

        await gateway.complete(_anfrage("cloud-p1-mit-zusage"), data_class=DataClass.P1)

        assert len(provider["anbieter_a"].gesehen) == 1

    @pytest.mark.invariant("cloud-limited-to-p1-with-zero-retention")
    async def test_p2_erreicht_keinen_fremden_anbieter(self) -> None:
        """Auch dann nicht, wenn der Katalog es zulässt.

        Das Dokument sieht für P2 eine Freigabe je Domäne vor. Den Weg, sie zu
        erteilen, gibt es nicht — und solange er fehlt, gilt die Vorgabe des
        Dokuments: standardmäßig lokal. Ein Katalogeintrag wäre sonst eine
        Freigabe, die niemand erteilt hat.
        """
        gateway, provider = _gateway(LOKAL, CLOUD_P2)

        with pytest.raises(ModelNotPermitted) as abgelehnt:
            await gateway.complete(_anfrage("cloud-stark"), data_class=DataClass.P2)

        assert abgelehnt.value.code == "cloud-needs-explicit-release"
        assert provider["anbieter_b"].gesehen == []

    @pytest.mark.invariant("cloud-limited-to-p1-with-zero-retention")
    async def test_ein_lokales_modell_bleibt_unberuehrt(self) -> None:
        """Die Regel gilt der Wolke, nicht der Datenklasse.

        Ohne diese Gegenprobe wäre der Test darüber auch dann grün, wenn P2
        überall scheiterte — und der lokale Pfad, für den die
        Klassifikation gebaut ist, wäre zu.
        """
        gateway, provider = _gateway(LOKAL)

        await gateway.complete(_anfrage("llama-3.1-8b"), data_class=DataClass.P3)

        assert len(provider["ollama"].gesehen) == 1

    @pytest.mark.invariant("cloud-limited-to-p1-with-zero-retention")
    async def test_auch_der_strom_prueft_vor_dem_ersten_stueck(self) -> None:
        """Ein Strom, dessen Zulässigkeit sich nach dem dritten Token
        herausstellt, hat die Daten schon übertragen."""
        gateway, provider = _gateway(LOKAL, CLOUD_OHNE_VORHALTUNG)

        with pytest.raises(ModelNotPermitted):
            async for _ in gateway.stream(
                _anfrage("cloud-p1-ohne-zusage"), data_class=DataClass.P1
            ):
                pass

        assert provider["anbieter_a"].gesehen == []
