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
    RunBudget,
    StreamChunk,
    TaintLevel,
)
from jarvis_core.orchestrator.budget import BudgetTracker
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
    cost_per_1m_out=Decimal("1.50"),
)

CLOUD_P2 = ModelCapability(
    name="cloud-stark",
    provider="anbieter_b",
    max_data_class=DataClass.P2,
    context_window=1_000_000,
    cost_per_1m_in=Decimal("3.00"),
    cost_per_1m_out=Decimal("15.00"),
)

FEHLKONFIGURIERT = ModelCapability(
    name="cloud-verrutscht",
    provider="anbieter_b",
    max_data_class=DataClass.P3,
    context_window=200_000,
    cost_per_1m_in=Decimal("3.00"),
    cost_per_1m_out=Decimal("15.00"),
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
    cost_per_1m_in=Decimal("0.30"),
    cost_per_1m_out=Decimal("1.50"),
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
    cost_per_1m_in=Decimal("0.30"),
    cost_per_1m_out=Decimal("1.50"),
    cost_per_1m_cached_in=Decimal("0.03"),
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


class TestKostenrechnung:
    """Was ein Aufruf kostet — und wer es ausrechnet.

    Die Rechnung steht im Katalogeintrag und wird vom Gateway angewandt. Nicht
    im Adapter: Ein Adapter mit Preisliste führte eine zweite Wahrheit über
    Preise, und sie veraltete beim nächsten Anbieterrundbrief. Nicht im
    Budget-Tracker: Der kennt die Preise nicht.
    """

    async def test_der_verbrauch_bekommt_seinen_preis(self) -> None:
        antwort = CompletionResult(
            text="fertig",
            provider="anbieter_a",
            usage=ModelUsage(tokens_in=1_000_000, tokens_out=1_000_000),
        )
        gateway = ModelGateway(
            {"anbieter_a": NotierenderProvider("anbieter_a", antwort=antwort)}, [CLOUD_P1]
        )

        ergebnis = await gateway.complete(_anfrage("cloud-fast"), data_class=DataClass.P0)

        # 0,30 € je Million ein, 1,50 € je Million aus.
        assert ergebnis.usage.cost_eur == Decimal("1.80")

    async def test_aus_dem_cache_gelesene_tokens_haben_ihren_eigenen_preis(self) -> None:
        """Getrennt geführt, weil sie anders abgerechnet werden."""
        antwort = CompletionResult(
            text="fertig",
            provider="anbieter_a",
            usage=ModelUsage(tokens_in=0, cached_tokens_in=1_000_000, tokens_out=0),
        )
        gateway = ModelGateway(
            {"anbieter_a": NotierenderProvider("anbieter_a", antwort=antwort)},
            [CLOUD_MIT_VORHALTUNG],
        )

        ergebnis = await gateway.complete(_anfrage("cloud-p1-mit-zusage"), data_class=DataClass.P1)

        assert ergebnis.usage.cost_eur == Decimal("0.03")

    async def test_ohne_eigenen_cachepreis_gilt_der_volle_eingabepreis(self) -> None:
        """Die vorsichtige Richtung: zu früh anhalten ist ärgerlich, zu spät
        kostet Geld."""
        antwort = CompletionResult(
            text="fertig",
            provider="anbieter_a",
            usage=ModelUsage(cached_tokens_in=1_000_000),
        )
        gateway = ModelGateway(
            {"anbieter_a": NotierenderProvider("anbieter_a", antwort=antwort)}, [CLOUD_P1]
        )

        ergebnis = await gateway.complete(_anfrage("cloud-fast"), data_class=DataClass.P0)

        assert ergebnis.usage.cost_eur == Decimal("0.30")

    async def test_ein_lokales_modell_kostet_nichts(self) -> None:
        """Keine Schönfärberei: Der Kostenzähler begrenzt Ausgaben an Dritte.
        Ihn mit geschätzten Stromkosten zu füllen, machte das Budget
        unschärfer, nicht ehrlicher."""
        antwort = CompletionResult(
            text="fertig", provider="ollama", usage=ModelUsage(tokens_in=500, tokens_out=500)
        )
        gateway = ModelGateway({"ollama": NotierenderProvider("ollama", antwort=antwort)}, [LOKAL])

        ergebnis = await gateway.complete(_anfrage(), data_class=DataClass.P3)

        assert ergebnis.usage.cost_eur == Decimal("0")

    async def test_was_ein_adapter_ueber_kosten_meldet_gilt_nicht(self) -> None:
        """Überschrieben, nicht addiert — wie bei ``taints_context``.

        Ein Adapter, der Preise erfindet, kann damit weder das Budget
        aufblähen noch es leerlaufen lassen.
        """
        antwort = CompletionResult(
            text="fertig",
            provider="anbieter_a",
            usage=ModelUsage(tokens_in=1_000_000, cost_eur=Decimal("99.99")),
        )
        gateway = ModelGateway(
            {"anbieter_a": NotierenderProvider("anbieter_a", antwort=antwort)}, [CLOUD_P1]
        )

        ergebnis = await gateway.complete(_anfrage("cloud-fast"), data_class=DataClass.P0)

        assert ergebnis.usage.cost_eur == Decimal("0.30")


class TestOhnePreisKeinAufruf:
    """Ein Aufruf, dessen Preis niemand kennt, verletzt kein Budget — und hält
    damit auch keines ein."""

    async def test_ein_fremder_anbieter_ohne_preis_wird_abgewiesen(self) -> None:
        ohne_preis = ModelCapability(
            name="cloud-ohne-preis",
            provider="anbieter_a",
            max_data_class=DataClass.P0,
            context_window=200_000,
            is_local=False,
        )
        gateway, provider = _gateway(LOKAL, ohne_preis)

        with pytest.raises(ModelNotPermitted) as abgelehnt:
            await gateway.complete(_anfrage("cloud-ohne-preis"), data_class=DataClass.P0)

        assert abgelehnt.value.code == "model-has-no-price"
        assert provider["anbieter_a"].gesehen == []

    async def test_ein_halber_preis_genuegt_nicht(self) -> None:
        """Eingabe ohne Ausgabe ist eine Rechnung, die nur die Hälfte zählt."""
        halb = ModelCapability(
            name="cloud-halb",
            provider="anbieter_a",
            max_data_class=DataClass.P0,
            context_window=200_000,
            cost_per_1m_in=Decimal("0.30"),
            is_local=False,
        )
        gateway, _ = _gateway(LOKAL, halb)

        with pytest.raises(ModelNotPermitted) as abgelehnt:
            await gateway.complete(_anfrage("cloud-halb"), data_class=DataClass.P0)

        assert abgelehnt.value.code == "model-has-no-price"

    async def test_das_lokale_modell_braucht_keinen(self) -> None:
        """Die Gegenprobe, und sie ist die wichtigere: Eine Preispflicht, die
        den lokalen Pfad sperrt, schlösse genau den Weg, für den die
        Datenklassifikation gebaut ist."""
        gateway, provider = _gateway(LOKAL)

        await gateway.complete(_anfrage(), data_class=DataClass.P3)

        assert len(provider["ollama"].gesehen) == 1


class StroemenderProvider:
    """Ein Adapter, der Stücke liefert — samt Verbrauch im letzten."""

    def __init__(self, name: str, *, usage: ModelUsage) -> None:
        self._name = name
        self._usage = usage

    @property
    def name(self) -> str:
        return self._name

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities()

    async def complete(self, request: CompletionRequest) -> CompletionResult:  # pragma: no cover
        raise NotImplementedError

    async def stream(self, request: CompletionRequest):
        yield StreamChunk(delta="Es ist ")
        yield StreamChunk(delta="14 Uhr.")
        yield StreamChunk(usage=self._usage)

    async def count_tokens(self, request: CompletionRequest) -> int:  # pragma: no cover
        return 0


class TestDerStromKostetAuch:
    async def test_das_verbrauchsstueck_bekommt_seinen_preis(self) -> None:
        """Der Antwortschritt streamt seit ``c17d112`` **immer**.

        Ohne diese Zeile wäre ausgerechnet der Aufruf umsonst, bei dem ein
        Mensch zusieht — und das Kostenbudget zählte nur die Argumentaufrufe.
        """
        gateway = ModelGateway(
            {
                "anbieter_a": StroemenderProvider(
                    "anbieter_a", usage=ModelUsage(tokens_in=1_000_000, tokens_out=1_000_000)
                )
            },
            [CLOUD_P1],
        )

        stuecke = [s async for s in gateway.stream(_anfrage("cloud-fast"), data_class=DataClass.P0)]

        assert "".join(s.delta for s in stuecke) == "Es ist 14 Uhr."
        assert stuecke[-1].usage is not None
        assert stuecke[-1].usage.cost_eur == Decimal("1.80")


class TestDieKetteBisZumBudget:
    """Die Zusage aus docs/04-orchestrator.md §7: „Überschreitung beendet den
    Lauf sauber mit Teilergebnis."

    Sie hat drei Glieder — Preis im Katalog, Rechnung im Gateway, Zähler im
    Tracker —, und bis zu diesem Block fehlte das erste. Der Zähler zählte,
    und er zählte immer null.
    """

    async def test_ein_teurer_aufruf_reisst_die_kostengrenze(self) -> None:
        antwort = CompletionResult(
            text="fertig",
            provider="anbieter_a",
            usage=ModelUsage(tokens_in=1_000_000, tokens_out=1_000_000),
        )
        gateway = ModelGateway(
            {"anbieter_a": NotierenderProvider("anbieter_a", antwort=antwort)}, [CLOUD_P1]
        )
        # Das Token-Budget wird hochgesetzt, damit die **Kosten**grenze
        # gemessen wird: ``exceeds()`` meldet die erste gerissene Schranke, und
        # zwei Millionen Tokens rissen sonst zuerst die Tokengrenze — der Test
        # wäre grün gewesen, ohne die Rechnung zu prüfen.
        tracker = BudgetTracker(RunBudget(max_tokens=10_000_000, max_cost_eur=Decimal("0.50")))
        assert tracker.exceeded() is None

        ergebnis = await gateway.complete(_anfrage("cloud-fast"), data_class=DataClass.P0)
        tracker.record_model_call(
            tokens_in=ergebnis.usage.tokens_in,
            tokens_out=ergebnis.usage.tokens_out,
            cost_eur=ergebnis.usage.cost_eur,
        )

        grund = tracker.exceeded()
        assert grund is not None and "Kostengrenze" in grund

    async def test_derselbe_aufruf_ohne_preis_haette_nichts_gemerkt(self) -> None:
        """Die Gegenprobe misst, was vorher galt.

        Ohne Preis im Katalog kostete derselbe Verbrauch null, und die
        Kostengrenze blieb unberührt — die Grenze war eine Statistik.
        """
        tracker = BudgetTracker(RunBudget(max_tokens=10_000_000, max_cost_eur=Decimal("0.50")))
        tracker.record_model_call(tokens_in=1_000_000, tokens_out=1_000_000)

        grund = tracker.exceeded()
        assert grund is None or "Kostengrenze" not in grund
