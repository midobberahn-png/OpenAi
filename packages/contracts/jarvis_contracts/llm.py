"""Sprachmodelle — Anfrage, Antwort, Werkzeugvorschlag.

Siehe ADR-009 und docs/07-security-permissions.md §4.

Ein Satz prägt dieses Modul, und er steckt schon im Namen des wichtigsten
Typs: **``ProposedToolCall``**. Was ein Modell an Werkzeugaufrufen zurückgibt,
ist ein *Vorschlag* — kein Auftrag, keine Entscheidung, keine Erlaubnis. Er
durchläuft anschließend Policy Engine, Approval Gateway und Ausführungs-Gate
wie jede andere Absicht auch.

Das ist keine sprachliche Feinheit. Die verbreitete Bauart nennt dieselbe
Struktur ``tool_call`` und behandelt sie als Anweisung; von dort ist es ein
kleiner Schritt zu einer Schleife, die Modellausgabe direkt ausführt. In einem
System mit Mail- und Kalenderzugriff ist dieser Schritt der ganze Unterschied
zwischen einem Assistenten und einer Fernsteuerung für jeden, der dem Modell
Text unterschieben kann.

Zwei weitere Festlegungen:

* **Antworten erben den Taint ihres Kontexts.** Ein Modell gibt wieder, was es
  gelesen hat: Stand Fremdinhalt im Kontext, kann die Antwort dessen
  Anweisungen wiederholen. Stand keiner darin, kann sie es nicht. Entschieden
  wird das im Model Gateway, das die Herkunftsmarkierungen sieht — nicht im
  Adapter, der nur Text sieht.
* **Prompts gehören nicht ins Protokoll.** Kein Feld dieses Moduls ist zum
  Loggen gedacht; ``ModelUsage`` trägt Zahlen, nicht Inhalte.
"""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .classification import TaintLevel

__all__ = [
    "CompletionRequest",
    "CompletionResult",
    "FinishReason",
    "Message",
    "MessageRole",
    "ModelUsage",
    "ProposedToolCall",
    "ProviderCapabilities",
    "StreamChunk",
]


class MessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"

    def __str__(self) -> str:
        return self.value


class Message(BaseModel):
    """Eine Nachricht im Gesprächsverlauf."""

    model_config = ConfigDict(frozen=True)

    role: MessageRole
    content: str = ""
    tool_call_id: str | None = None
    """Bei ``role=tool``: auf welchen Vorschlag sich das Ergebnis bezieht."""

    name: str | None = None

    is_untrusted: bool = False
    """Enthält diese Nachricht Fremdinhalt?

    Wird von der Context Engine gesetzt und beim Rendern zur Kennzeichnung
    verwendet. Die eigentliche Verteidigung ist das Taint-Tracking; die
    Auszeichnung im Prompt ist eine zusätzliche Linie, keine Ersatzlinie.
    """


class ProposedToolCall(BaseModel):
    """Ein vom Modell **vorgeschlagener** Werkzeugaufruf.

    Der Name ist die Entscheidung. Diese Struktur ist die Stelle, an der ein
    kompromittiertes Modell — oder ein Modell, das eine präparierte Mail
    gelesen hat — seine Absicht äußert. Sie enthält deshalb ausdrücklich
    nichts, was einer Erlaubnis ähnelt: kein Risiko, keinen Scope, keine
    Bestätigung, kein ``approved``-Feld.

    Was hier ankommt, geht denselben Weg wie jede andere Absicht:
    ``PolicyEngine.decide()`` → gegebenenfalls Bestätigung →
    ``ExecutionGrant``. Ein Feld, das diesen Weg abkürzen könnte, wäre die
    Umgehung des gesamten Sicherheitssockels.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1, max_length=120)
    """Kennung des Providers — nur zur Zuordnung des Ergebnisses."""

    tool_name: str = Field(min_length=1, max_length=80)
    """Der *behauptete* Werkzeugname. Kann halluziniert sein; die Auflösung
    über die Registry entscheidet, ob es ihn gibt."""

    arguments: dict[str, Any] = Field(default_factory=dict)
    """Ungeprüft. Die Validierung gegen das JSON-Schema des Werkzeugs und die
    Prüfung durch die Policy Engine kommen beide danach."""


class FinishReason(StrEnum):
    STOP = "stop"
    LENGTH = "length"
    TOOL_CALLS = "tool_calls"
    CONTENT_FILTER = "content_filter"
    ERROR = "error"

    def __str__(self) -> str:
        return self.value


class ModelUsage(BaseModel):
    """Verbrauch eines Modellaufrufs — Zahlen, keine Inhalte.

    Bewusst ohne Prompt- oder Antworttext: Dieses Objekt landet in
    Protokollen und Kostenübersichten, und dort haben P2- und P3-Daten nichts
    verloren.
    """

    model_config = ConfigDict(frozen=True)

    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    cached_tokens_in: int = Field(default=0, ge=0)
    """Prompt-Caching (Anthropic, OpenAI). Getrennt geführt, weil es anders
    abgerechnet wird — sonst stimmt die Kostenrechnung nicht."""

    cost_eur: Decimal = Decimal("0")
    latency_ms: int = Field(default=0, ge=0)

    @property
    def tokens_total(self) -> int:
        return self.tokens_in + self.tokens_out


class ProviderCapabilities(BaseModel):
    """Was ein Adapter kann — sichtbar gemacht statt versteckt (ADR-009).

    Die Unterschiede zwischen den Anbietern werden hier ausgewiesen, damit der
    Orchestrator sie berücksichtigen kann, statt sie hinter einer
    Kompatibilitätsfassade zu verlieren.
    """

    model_config = ConfigDict(frozen=True)

    streaming: bool = True
    tool_calling: bool = True
    structured_output: bool = False
    prompt_caching: bool = False
    vision: bool = False
    token_counting: bool = False
    """Kann der Adapter Tokens *vor* dem Aufruf zählen? Ohne das ist die
    Budgetprüfung eine Schätzung."""

    temperature_control: bool = True
    """Wird ``CompletionRequest.temperature`` tatsächlich übertragen?

    Ergänzt, als der Anthropic-Adapter entstand: Dessen Messages-API kennt
    keinen Temperaturparameter mehr. Ohne dieses Feld wäre der Wert ein Wunsch,
    den ein Aufrufer äußert und der unterwegs verschwindet — und ``plan_arguments``
    äußert ihn mit Absicht (``0.0``, damit Werkzeugargumente bestimmt sind).

    ``True`` als Vorgabe, weil das der Normalfall ist und ein Adapter, der es
    nicht kann, es sagen muss — nicht umgekehrt."""


class CompletionRequest(BaseModel):
    """Anfrage an ein Modell.

    Enthält **keine** Datenklasse und keinen Taint-Zustand. Das ist Absicht:
    Der Sicherheitskontext gehört nicht in die Anfrage, sondern um sie herum —
    das Model Gateway nimmt ihn getrennt entgegen und entscheidet damit, ob
    diese Anfrage diesen Provider überhaupt erreichen darf. Ein Feld in der
    Anfrage wäre ein Wert, den der Aufrufer selbst setzt, und ein Aufrufer,
    der seine eigene Obergrenze bestimmt, hat keine.
    """

    model_config = ConfigDict(frozen=True)

    model: str = Field(min_length=1)
    messages: list[Message] = Field(min_length=1)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    """Werkzeugschemata — bereits verengt durch
    ``PolicyEngine.effective_tools()``. Was hier fehlt, sieht das Modell nicht
    und kann es nicht einmal vorschlagen."""

    max_tokens: int = Field(default=4096, gt=0)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    stop: list[str] = Field(default_factory=list)
    response_format: Literal["text", "json"] = "text"
    timeout_s: float = Field(default=60.0, gt=0, le=600)

    @model_validator(mode="after")
    def _tools_need_a_name(self) -> CompletionRequest:
        for tool in self.tools:
            if not tool.get("name"):
                raise ValueError("Jedes Werkzeugschema braucht einen Namen.")
        return self


class CompletionResult(BaseModel):
    """Antwort eines Modells — Fremdinhalt, bis das Gegenteil gezeigt ist."""

    model_config = ConfigDict(frozen=True)

    text: str = ""
    tool_calls: list[ProposedToolCall] = Field(default_factory=list)
    """**Vorschläge.** Siehe ``ProposedToolCall``."""

    finish_reason: FinishReason = FinishReason.STOP
    model: str = ""
    provider: str = ""
    usage: ModelUsage = Field(default_factory=ModelUsage)

    taints_context: bool = True
    """Standardmäßig ``True`` — die vorsichtige Richtung für jeden, der dieses
    Objekt selbst baut.

    Maßgeblich ist der Wert aber nicht: Das Model Gateway setzt ihn nach jedem
    Aufruf neu, aus dem Taint-Zustand des Laufs und den Herkunftsmarkierungen
    der Anfrage. Ein Adapter kann das nicht entscheiden — er sieht Text, nicht
    Herkunft.

    Die Regel dort lautet: Die Antwort erbt, was im Kontext stand. Nicht „jede
    Modellantwort ist Fremdinhalt" — diese Fassung würde nach dem ersten
    Modellaufruf jeden Lauf kontaminieren und den Normalfall blockieren.
    """

    @property
    def taint_level(self) -> TaintLevel:
        return TaintLevel.TAINTED if self.taints_context else TaintLevel.CLEAN

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


class StreamChunk(BaseModel):
    """Ein Stück einer laufenden Antwort.

    Werkzeugvorschläge kommen bei allen Anbietern stückweise an. Sie werden
    deshalb erst im vollständigen ``CompletionResult`` geführt — ein halb
    übertragener Aufruf ist kein Vorschlag, sondern ein Fragment.
    """

    model_config = ConfigDict(frozen=True)

    delta: str = ""
    finish_reason: FinishReason | None = None
    usage: ModelUsage | None = None
    """Nur im letzten Stück gesetzt."""
