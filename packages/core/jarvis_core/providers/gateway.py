"""Model Gateway — die Stelle, an der P3 das Gerät nicht verlässt.

Der Router (``orchestrator/router.py``) wählt ein Modell und filtert dabei
bereits hart nach Datenklasse. Warum dann hier noch einmal?

Weil zwischen Wahl und Aufruf etwas liegt. Der Router entscheidet einmal pro
Turn; der Aufruf geschieht danach, oft mehrfach, aus Agentenketten heraus, mit
einem Kontext, der inzwischen P2-Inhalte gesehen hat. Eine Prüfung, die nur
bei der Wahl stattfindet, prüft den Zustand von vorhin.

Dieselbe Überlegung wie beim Ausführungs-Gate der Werkzeuge — und dieselbe
Lehre aus zwei gefundenen Bypässen:

* **Der Sicherheitskontext ist kein Feld der Anfrage.** ``CompletionRequest``
  trägt weder Datenklasse noch Taint. Beides kommt getrennt herein, damit kein
  Aufrufer seine eigene Obergrenze mitbringt.
* **Fail closed.** Ein unbekanntes Modell, ein fehlender Anbieter, eine
  Datenklasse ohne passenden Kandidaten — jeder dieser Fälle endet in einer
  Ausnahme, nicht in einem Rückfall auf irgendetwas Verfügbares.
* **Nominal, nicht strukturell.** Die Zulassung hängt am Katalogeintrag des
  Modells, nicht an dem, was die Anfrage über sich behauptet.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence

from jarvis_contracts import (
    CompletionRequest,
    CompletionResult,
    DataClass,
    ModelCapability,
    ModelUsage,
    StreamChunk,
    TaintLevel,
)
from jarvis_core.ports.llm import LLMProvider

__all__ = ["ModelGateway", "ModelNotPermitted"]


class ModelNotPermitted(Exception):
    """Dieses Modell darf diese Anfrage nicht sehen.

    Ausnahme und kein Rückgabewert, aus demselben Grund wie bei
    ``ExecutionDenied``: Ein Aufrufer, der einen Rückgabewert übersieht, würde
    sonst trotzdem senden — und „senden" heißt hier, dass die Daten das Haus
    verlassen haben. Das lässt sich nicht zurücknehmen.
    """

    def __init__(self, reason: str, *, code: str) -> None:
        self.reason = reason
        self.code = code
        super().__init__(f"[{code}] {reason}")


class ModelGateway:
    """Der einzige Weg zu einem Sprachmodell."""

    def __init__(
        self,
        providers: Mapping[str, LLMProvider],
        catalog: Sequence[ModelCapability],
    ) -> None:
        self._providers = dict(providers)
        self._catalog = {model.name: model for model in catalog}

    async def complete(
        self,
        request: CompletionRequest,
        *,
        data_class: DataClass,
        taint: TaintLevel = TaintLevel.CLEAN,
    ) -> CompletionResult:
        """Ruft ein Modell auf — nach der Zulassungsprüfung.

        ``data_class`` ist die Klasse der Daten, die in dieser Anfrage stecken,
        und sie stammt vom Aufrufer aus dem persistierten Lauf. ``taint`` wird
        durchgereicht, weil eine kontaminierte Antwort kontaminiert bleiben
        muss — ein sauberer Lauf, der ein Modell mit Fremdinhalt befragt, ist
        danach nicht mehr sauber.
        """
        modell = self._zugelassen(request.model, data_class)
        provider = self._providers.get(modell.provider)
        if provider is None:
            raise ModelNotPermitted(
                f"Für {modell.name!r} ist kein Anbieter eingerichtet ({modell.provider}).",
                code="provider-missing",
            )

        ergebnis = await provider.complete(request)
        return ergebnis.model_copy(
            update={
                "taints_context": self._kontaminiert(request, taint),
                "usage": self._bepreist(modell, ergebnis.usage),
            }
        )

    async def stream(
        self,
        request: CompletionRequest,
        *,
        data_class: DataClass,
        taint: TaintLevel = TaintLevel.CLEAN,
    ) -> AsyncIterator[StreamChunk]:
        """Dieselbe Zulassungsprüfung wie ``complete()`` — Antwort in Stücken.

        **Der Weg fehlte in der Mitte.** Der Ollama-Adapter kann seit jeher
        streamen und der Vertrag kennt ``StreamChunk``; das Gateway konnte es
        nicht. Wer Tokens fließen sehen wollte, hätte am Gate vorbeigemusst —
        und damit an der Prüfung, ob dieses Modell diese Datenklasse überhaupt
        sehen darf.

        **Die Prüfung steht vor dem ersten Stück und nicht daneben.** Ein
        Strom, dessen Zulässigkeit sich erst nach dem dritten Token
        herausstellt, hat die Daten schon übertragen.

        **Werkzeugvorschläge kommen hier nicht vor** — der Vertrag schließt sie
        aus, weil sie stückweise ankommen und ein halb übertragener Aufruf kein
        Vorschlag ist. Dieser Weg ist deshalb für den Antwortschritt gedacht,
        dem ohnehin kein Werkzeug angeboten wird.

        Die Kontamination beantwortet ``kontaminiert()`` — sie hängt an der
        Anfrage und nicht am Ergebnis, und ein Strom hat kein Ergebnis, an das
        sich etwas anheften ließe.
        """
        modell = self._zugelassen(request.model, data_class)
        provider = self._providers.get(modell.provider)
        if provider is None:
            raise ModelNotPermitted(
                f"Für {modell.name!r} ist kein Anbieter eingerichtet ({modell.provider}).",
                code="provider-missing",
            )

        async for stueck in provider.stream(request):
            # **Auch der Strom kostet.** Der Antwortschritt streamt seit
            # ``c17d112`` immer; ohne diese Zeile wäre ausgerechnet der Aufruf
            # umsonst, bei dem ein Mensch zusieht.
            if stueck.usage is None:
                yield stueck
            else:
                yield stueck.model_copy(update={"usage": self._bepreist(modell, stueck.usage)})

    @staticmethod
    def _bepreist(modell: ModelCapability, verbrauch: ModelUsage) -> ModelUsage:
        """Schreibt die Kosten in den Verbrauch.

        **Hier und nicht im Adapter**, aus demselben Grund wie die
        Kontamination: Das Gateway kennt den Katalogeintrag, der Adapter kennt
        nur Text und Zahlen. Ein Adapter mit Preisliste führte eine zweite
        Wahrheit über Preise, und sie veraltete beim nächsten Anbieterrundbrief.

        Ein bereits gesetzter Wert wird **überschrieben** und nicht addiert —
        wie bei ``taints_context``: Was ein Adapter darüber meldet, kann so
        weder zu viel noch zu wenig anrichten.
        """
        return verbrauch.model_copy(
            update={
                "cost_eur": modell.cost_for(
                    tokens_in=verbrauch.tokens_in,
                    tokens_out=verbrauch.tokens_out,
                    cached_tokens_in=verbrauch.cached_tokens_in,
                    cache_write_tokens_in=verbrauch.cache_write_tokens_in,
                )
            }
        )

    @staticmethod
    def kontaminiert(request: CompletionRequest, taint: TaintLevel) -> bool:
        """Erbt eine Antwort auf diese Anfrage die Kontamination ihres Kontexts?

        Öffentlich, seit es das Streamen gibt: Dort entsteht kein
        ``CompletionResult``, an das sich die Auskunft anheften ließe, und der
        Aufrufer muss sie trotzdem bekommen. Eine zweite Fassung derselben
        Regel neben dieser wäre die zweite Wahrheit über Kontamination.
        """
        return ModelGateway._kontaminiert(request, taint)

    @staticmethod
    def _kontaminiert(request: CompletionRequest, taint: TaintLevel) -> bool:
        """Erbt die Antwort die Kontamination ihres Kontexts?

        Die naheliegende Regel wäre „jede Modellantwort ist Fremdinhalt". Sie
        ist falsch, und zwar auf eine Weise, die schon einmal teuer war: Nach
        dem ersten Modellaufruf wäre dann *jeder* Lauf kontaminiert, und
        ``mail.send`` nie wieder möglich. Ein Sicherheitsmechanismus, der den
        Normalfall blockiert, wird abgeschaltet — genau der Widerspruch aus
        V1.0, den das Sanitization-Gate aufgelöst hat.

        Richtig ist: Die Antwort erbt, was im Kontext stand. Ein Modell gibt
        wieder, was es gelesen hat; hat es nichts Fremdes gelesen, kann es
        nichts Fremdes wiedergeben.

        Entschieden wird das **hier** und nicht im Adapter. Das Gateway sieht
        die Anfrage und damit die Herkunftsmarkierungen; der Adapter sieht nur
        Text. Und es wird in beide Richtungen überschrieben: Ein Adapter, der
        etwas anderes meldet, kann damit nichts kaputt machen — weder zu viel
        noch zu wenig.
        """
        return taint.is_tainted or any(nachricht.is_untrusted for nachricht in request.messages)

    def _zugelassen(self, model_name: str, data_class: DataClass) -> ModelCapability:
        """Darf dieses Modell diese Daten sehen?

        Zwei Prüfungen, und die zweite ist nicht redundant: ``max_data_class``
        ist Konfiguration und kann falsch gesetzt sein. ``is_local`` ist eine
        Eigenschaft des Deployments. P3 bleibt strukturell auf dem Gerät —
        ein Tippfehler in einer YAML-Datei darf daran nichts ändern.
        """
        modell = self._catalog.get(model_name)
        if modell is None:
            raise ModelNotPermitted(
                f"Unbekanntes Modell: {model_name!r}. Der Katalog entscheidet, was "
                "zugelassen ist — nicht die Anfrage.",
                code="model-unknown",
            )

        if not modell.accepts(data_class):
            raise ModelNotPermitted(
                f"{modell.name!r} ist für {data_class} nicht zugelassen "
                f"(zulässig bis {modell.max_data_class}).",
                code="data-class-exceeded",
            )

        if data_class is DataClass.P3 and not modell.is_local:
            raise ModelNotPermitted(
                f"{data_class} wird ausschließlich lokal verarbeitet; {modell.name!r} "
                f"läuft bei {modell.provider}.",
                code="p3-must-stay-local",
            )

        if not modell.is_local:
            self._grenze_der_wolke(modell, data_class)

        return modell

    @staticmethod
    def _grenze_der_wolke(modell: ModelCapability, data_class: DataClass) -> None:
        """Was ein Anbieter sehen darf, der nicht auf diesem Gerät läuft.

        Die Tabelle in docs/00-uebersicht.md §8 ist eindeutig, und bis zu
        diesem Block hatte sie keinen Leser — es gab schlicht keinen fremden
        Anbieter:

        * **P0** — jeder Anbieter.
        * **P1** — nur mit Zero-Retention-Vereinbarung.
        * **P2** — nur nach ausdrücklicher Freigabe je Domäne.
        * **P3** — nie (steht darüber, strukturell und ohne diese Prüfung).

        **``zero_retention`` war ein Vertragsfeld ohne Leser.** Es stand seit
        dem ersten Entwurf in ``ModelCapability`` und wurde von nichts geprüft
        — dasselbe Muster wie ``ToolSpec.supports_undo`` vor dem Undo-Weg und
        ``ToolSpec.parameters`` vor der Schemaprüfung. Die brauchbare Frage bei
        jeder deklarierten Einschränkung ist nicht „steht sie da?", sondern
        **„wer liest sie, und wer prüft dagegen?"**. Ab hier: dieser Block.

        **P2 wird abgewiesen, obwohl das Dokument eine Freigabe vorsieht.** Den
        Weg, sie zu erteilen, gibt es nicht: keine Tabelle, keine Route, kein
        Bildschirm. Ein Katalogeintrag, der P2 behauptet, wäre damit eine
        Freigabe, die niemand erteilt hat — und die Vorgabe des Dokuments ist
        „standardmäßig lokal". Wer die Freigabe baut, hebt diese Zeile auf und
        setzt an ihre Stelle die Prüfung, ob sie vorliegt.

        Die Prüfung steht **hier** und nicht nur im Katalog, aus demselben
        Grund wie bei P3: Der Katalog ist Konfiguration und kann falsch gesetzt
        sein; ein Tippfehler darf keine Daten außer Haus geben.

        **Und eine Prüfung, die keine Datenklasse betrifft, steht ebenfalls
        hier:** ohne hinterlegten Preis kein Aufruf. Sie gehört an dieselbe
        Stelle, weil sie dieselbe Form hat — eine Zusage des Systems, die ohne
        Konfiguration leer läuft, statt laut zu scheitern.
        """
        if not modell.is_priced:
            # **Ein Aufruf, dessen Preis niemand kennt, verletzt kein Budget —
            # und hält damit auch keines ein.** Das Budget eines Laufs ist eine
            # Zusage (docs/04-orchestrator.md §7: „Überschreitung beendet den
            # Lauf sauber"); ohne Preis zählt der Tracker bei jedem
            # Cloud-Aufruf null, und die Kostengrenze schlägt nie an. Genau
            # dieser Fall — eine fehlerhafte Agentenschleife — ist laut
            # Dokument „ein finanzielles Risiko, kein Bug".
            #
            # Für lokale Modelle gilt die Prüfung nicht: Sie kosten Strom,
            # keine Rechnung, und ein erfundener Preis machte das Budget
            # unschärfer statt ehrlicher.
            raise ModelNotPermitted(
                f"Für {modell.name!r} ist kein Preis hinterlegt; ohne ihn kann das "
                "Kostenbudget nicht gelten.",
                code="model-has-no-price",
            )

        if data_class is DataClass.P0:
            return

        if data_class is DataClass.P2:
            raise ModelNotPermitted(
                f"{data_class} geht nur nach ausdrücklicher Freigabe an einen fremden "
                f"Anbieter, und es gibt keinen Weg, sie zu erteilen; {modell.name!r} "
                f"läuft bei {modell.provider}.",
                code="cloud-needs-explicit-release",
            )

        if not modell.zero_retention:
            raise ModelNotPermitted(
                f"{data_class} geht an einen fremden Anbieter nur mit "
                f"Zero-Retention-Zusage; für {modell.name!r} ist keine hinterlegt.",
                code="cloud-needs-zero-retention",
            )

    def capabilities_of(self, model_name: str) -> tuple[ModelCapability, LLMProvider] | None:
        """Katalogeintrag und Adapter — für die Oberfläche, nicht für Entscheidungen."""
        modell = self._catalog.get(model_name)
        if modell is None:
            return None
        provider = self._providers.get(modell.provider)
        return (modell, provider) if provider is not None else None

    def available_models(self, *, up_to: DataClass) -> list[ModelCapability]:
        """Welche Modelle kämen für diese Datenklasse infrage?

        Dieselben Regeln wie in ``_zugelassen``, nur als Frage statt als
        Prüfung. Bewusst hier und nicht beim Aufrufer nachgebaut: Zwei Fassungen
        derselben Regel laufen auseinander, und die zweite ist dann die, die
        P3 durchlässt.
        """
        return [
            modell
            for modell in self._catalog.values()
            if modell.accepts(up_to)
            and (up_to is not DataClass.P3 or modell.is_local)
            and modell.provider in self._providers
        ]
