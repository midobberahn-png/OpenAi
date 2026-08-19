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

from collections.abc import Mapping, Sequence

from jarvis_contracts import (
    CompletionRequest,
    CompletionResult,
    DataClass,
    ModelCapability,
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
        return ergebnis.model_copy(update={"taints_context": self._kontaminiert(request, taint)})

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

        return modell

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
