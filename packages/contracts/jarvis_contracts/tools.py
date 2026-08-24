"""Werkzeugvertrag: Spezifikation, Aufruf, Ergebnis.

Siehe docs/06-agenten-tools.md §4.

Werkzeuge kennen ihre Risikoklasse, entscheiden aber nie über ihre eigene
Ausführung — das tut ausschließlich die Policy Engine.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .classification import DataClass
from .permissions import PolicyEffect, RiskLevel, ScopeName

__all__ = [
    "SAFE_WHEN_TAINTED_MAX_RISK",
    "UNDO_TTL",
    "InvocationStatus",
    "PayloadInspectability",
    "SanitizedPayload",
    "Source",
    "TaintGateOutcome",
    "ToolInvocation",
    "ToolResult",
    "ToolSpec",
]


SAFE_WHEN_TAINTED_MAX_RISK = RiskLevel.LOW
"""Höchste Risikoklasse, die in einem kontaminierten Kontext noch zulässig ist,
wenn ein Werkzeug ``forbidden_when_tainted`` nicht ausdrücklich setzt."""


class PayloadInspectability(StrEnum):
    """Kann ein Mensch diesen Payload vollständig prüfen?

    Entscheidet, ob eine Bestätigung Kontamination aufheben darf
    (docs/16-v1.1-review.md §1). Eine Bestätigung ist nur dann eine echte
    Sicherheitsprüfung, wenn der Mensch tatsächlich sieht, was er freigibt.
    """

    STRUCTURED = "structured"
    """Kurze, typisierte Felder — Datum, Zeit, ID, Titel. In Sekunden erfassbar.
    Beispiel: ``calendar.create``."""

    FREEFORM = "freeform"
    """Enthält Freitext mit Außenwirkung. Eine um eine Ziffer veränderte IBAN
    oder eine ausgetauschte URL im Fließtext übersieht auch ein aufmerksamer
    Leser — genau darauf zielen reale Angriffe. Beispiel: ``send_email``."""

    OPAQUE = "opaque"
    """Nicht sinnvoll darstellbar: Binärdaten, Skripte, Befehle.
    Beispiel: ``shell.exec``."""

    @property
    def clearable_by_confirmation(self) -> bool:
        """Nur strukturierte Payloads dürfen Kontamination aufheben."""
        return self is PayloadInspectability.STRUCTURED


class TaintGateOutcome(StrEnum):
    """Ergebnis der Taint-Prüfung eines Werkzeugaufrufs."""

    PERMITTED = "permitted"
    """Nicht kontaminiert oder Werkzeug unbedenklich — normale Ausführung."""

    SANITIZABLE = "sanitizable"
    """Kontaminiert, aber der Payload ist vollständig prüfbar. Nach Bestätigung
    wird ein neuer, sauberer Lauf mit eingefrorenem Payload gestartet."""

    BLOCKED = "blocked"
    """Kontaminiert und nicht sanierbar. Der Nutzer muss die Aktion selbst
    anstoßen — dann entsteht von Anfang an ein sauberer Lauf."""


class Source(BaseModel):
    """Quellenbeleg. Pflicht bei Recherche- und Dokumentergebnissen."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["web", "document", "email", "calendar", "memory"]
    title: str
    ref: str
    """URL, Dokument-ID oder Message-ID."""

    locator: str | None = None
    """Seite, Abschnitt oder Zeilenbereich innerhalb der Quelle."""

    retrieved_at: datetime | None = None


class ToolSpec(BaseModel):
    """Vollständige Beschreibung eines Werkzeugs.

    Aus dieser Spezifikation entstehen: das JSON-Schema für das Modell, die
    Laufzeitvalidierung und die generierte Werkzeugdokumentation.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$", max_length=80)
    description: str = Field(min_length=10, max_length=1000)
    """Was das Modell sieht. Ungenaue Beschreibungen sind die häufigste
    Ursache für falsch gewählte Werkzeuge."""

    parameters: dict[str, Any]
    """JSON Schema, aus der Funktionssignatur abgeleitet."""

    returns: dict[str, Any] | None = None

    scopes: list[ScopeName] = Field(default_factory=list)
    risk: RiskLevel
    data_class: DataClass = DataClass.P1

    idempotent: bool = False
    """Steuert, ob nach einem Timeout wiederholt werden darf."""

    requires_preview: bool = False
    """Erzwingt ein Vorschauobjekt vor der Ausführung."""

    forbidden_when_tainted: bool = True
    """Gesperrt, sobald der Lauf Fremdinhalt verarbeitet hat.

    Standard ist ``True`` — Werkzeuge müssen sich ausdrücklich als
    unbedenklich erklären, nicht umgekehrt (docs/07-security §4).
    """

    reads_untrusted_content: bool = False
    """Setzt den Lauf auf ``tainted``, sobald dieses Werkzeug ausgeführt wurde."""

    rate_limit: str | None = Field(default=None, pattern=r"^\d+/(second|minute|hour|day)$")
    timeout_s: float = Field(default=30.0, gt=0, le=600)
    supports_undo: bool = False

    payload_inspectability: PayloadInspectability = PayloadInspectability.FREEFORM
    """Kann ein Mensch den Payload vollständig prüfen?

    Standard ist ``FREEFORM`` — die sichere Annahme. Werkzeuge müssen sich
    ausdrücklich als vollständig prüfbar erklären, nicht umgekehrt.

    Achtung: Dies ist die *statische* Einstufung. Die tatsächlich gültige
    ergibt sich aus ``effective_inspectability()`` und kann je Aufruf strenger
    ausfallen — siehe ``outbound_fields``.
    """

    outbound_fields: list[str] = Field(default_factory=list)
    """Felder, deren Befüllung eine Nachricht an Dritte auslöst.

    Hintergrund: Ein Kalendereintrag *ohne* Teilnehmer ist eine private Notiz
    und vollständig prüfbar. Derselbe Eintrag *mit* Teilnehmern verschickt
    Einladungen — das ist Außenwirkung, unabhängig davon, wie strukturiert der
    Payload aussieht. Eine Einstufung allein auf Werkzeugebene wäre hier zu
    grob und würde genau den Angriff durchlassen, bei dem eine präparierte
    Mail einen zusätzlichen Teilnehmer einschmuggelt.

    Beispiel: ``calendar.create`` → ``["attendees"]``.
    """

    model_visible_fields: list[str] = Field(default_factory=list)
    """Felder des Ergebnisses, die ein Modell im Prompt sehen darf.

    **Die Vorgabe ist leer, und das ist die Zusage.** Wer nichts erklärt, gibt
    nichts preis. Dieselbe Beweislast wie bei ``payload_inspectability`` und
    ``forbidden_when_tainted``: Werkzeuge öffnen sich ausdrücklich, nicht
    ausdrücklich zu.

    Der Anlass: Ohne diese Deklaration wäre ``ToolResult.data`` — ein
    ``dict[str, Any]`` ohne Grenze — der Weg, auf dem jedes künftige Werkzeug
    stillschweigend mitentscheidet, was in einem Prompt landet. Sichtbar wäre
    das in keinem Diff.

    Gemeint ist **nicht**, was das Werkzeug zurückgibt (das steht in
    ``returns``), sondern was ein Modell davon lesen soll. Für ``files.read``
    ist das ``["text"]`` — ``bytes_read`` und ``truncated`` braucht ein Modell
    nicht, und was es nicht sieht, kann es nicht zitieren.

    **Was diese Deklaration nicht leistet:** Sie macht Fremdinhalt nicht
    harmlos. Der gelesene Text bleibt Fremdinhalt, der Lauf bleibt
    kontaminiert, und ein Modell kann einer darin untergeschobenen Anweisung
    folgen — nachgemessen, dreimal von dreimal. Folgenlos macht das nicht diese
    Liste, sondern das Taint-Gate.
    """

    plugin: str | None = None
    """Herkunftsplugin, falls das Werkzeug nicht eingebaut ist."""

    def model_visible(self, data: dict[str, Any] | None) -> dict[str, Any]:
        """Der Teil eines Ergebnisses, den ein Modell sehen darf.

        Reine Auswahl, keine Formatierung: *welche* Felder gehört zum Vertrag
        des Werkzeugs, *wie sie im Prompt stehen* gehört zum Kontextbau. Zwei
        Fragen, zwei Schichten.

        Ein deklariertes Feld, das im konkreten Ergebnis fehlt, wird
        übersprungen statt beanstandet: Ein Werkzeug darf im Fehlerfall weniger
        liefern, und eine Ausnahme dafür wäre ein Absturz auf einem Weg, der
        ohnehin schon schiefging.
        """
        if not data:
            return {}
        return {feld: data[feld] for feld in self.model_visible_fields if feld in data}

    @model_validator(mode="after")
    def _risk_consistency(self) -> ToolSpec:
        if self.risk.needs_confirmation and not self.requires_preview:
            raise ValueError(
                f"Werkzeug {self.name!r}: Risiko {self.risk} verlangt requires_preview=True — "
                "eine Bestätigung ohne Vorschau ist wertlos."
            )
        if self.risk is not RiskLevel.LOW and not self.scopes:
            raise ValueError(
                f"Werkzeug {self.name!r}: Risiko {self.risk} ohne Scope ist unzulässig."
            )
        if (
            self.payload_inspectability is PayloadInspectability.STRUCTURED
            and not self.requires_preview
            and self.risk is not RiskLevel.LOW
        ):
            raise ValueError(
                f"Werkzeug {self.name!r}: 'structured' erlaubt Taint-Sanierung und "
                "verlangt deshalb requires_preview=True — ohne Vorschau gäbe es "
                "nichts zu prüfen."
            )
        return self

    def is_blocked_by_taint(self) -> bool:
        """Ist dieses Werkzeug in einem kontaminierten Kontext gesperrt?"""
        if self.forbidden_when_tainted:
            return True
        return self.risk > SAFE_WHEN_TAINTED_MAX_RISK

    def effective_inspectability(
        self, arguments: dict[str, Any] | None = None
    ) -> PayloadInspectability:
        """Prüfbarkeit für *diesen konkreten* Aufruf.

        Ohne Argumente wird die statische Einstufung zurückgegeben. Sind
        Argumente vorhanden und ist mindestens ein ``outbound_fields``-Feld
        belegt, gilt der Aufruf als ``FREEFORM`` — er wirkt nach außen.
        """
        if self.payload_inspectability is not PayloadInspectability.STRUCTURED:
            return self.payload_inspectability
        if arguments is None:
            return self.payload_inspectability

        for field in self.outbound_fields:
            value = arguments.get(field)
            if value:  # nicht None, nicht leere Liste, nicht leerer String
                return PayloadInspectability.FREEFORM
        return PayloadInspectability.STRUCTURED

    def taint_gate(
        self, *, tainted: bool, arguments: dict[str, Any] | None = None
    ) -> TaintGateOutcome:
        """Entscheidet über die Behandlung in einem kontaminierten Lauf.

        Siehe docs/16-v1.1-review.md §1. Diese Methode löst den Widerspruch
        aus V1.0 auf: Ohne sie wäre der häufigste Alltagsablauf — Mails lesen
        und daraus einen Termin anlegen — dauerhaft gesperrt. Ein
        Sicherheitsmechanismus, der den Normalfall blockiert, wird abgeschaltet
        und ist damit wirkungslos.

        Die Sanierung ist eng gefasst: Sie setzt voraus, dass der Mensch den
        Payload tatsächlich vollständig prüfen kann.
        """
        if not tainted or not self.is_blocked_by_taint():
            return TaintGateOutcome.PERMITTED

        # Irreversibles wird nie saniert — dort ist der Preis eines Fehlers
        # zu hoch, um ihn gegen Komfort abzuwägen.
        if self.risk is RiskLevel.CRITICAL:
            return TaintGateOutcome.BLOCKED

        # Bewusst die *effektive* Einstufung: Ein Kalendereintrag mit
        # eingeschmuggeltem Teilnehmer ist keine private Notiz mehr.
        if self.effective_inspectability(arguments).clearable_by_confirmation:
            return TaintGateOutcome.SANITIZABLE

        return TaintGateOutcome.BLOCKED

    def effective_risk(self, declared: RiskLevel | None = None) -> RiskLevel:
        """Ein Plugin darf seine eigene Risikoeinstufung nicht senken.

        Siehe docs/12-plugins.md §4. Der Kern nimmt immer den höheren Wert.
        """
        if declared is None:
            return self.risk
        return max(self.risk, declared)


class SanitizedPayload(BaseModel):
    """Ein vom Nutzer bestätigter, eingefrorener Werkzeug-Payload.

    Grundlage des sanierten Laufs (docs/16-v1.1-review.md §1). Vier
    Invarianten machen das Gate zur Ergänzung des Taint-Schutzes statt zu
    seiner Umgehung:

    1. **Eingefroren** — ``frozen=True``; was bestätigt wurde, wird ausgeführt.
    2. **Keine Kontextvererbung** — der saubere Lauf sieht den Herkunftslauf
       nicht, auch nicht dessen Zusammenfassung.
    3. **Genau ein Aufruf** — der sanierte Lauf plant nicht und delegiert nicht.
    4. **Verknüpft im Audit** — ``origin_run_id`` erhält die Nachvollziehbarkeit.
    """

    model_config = ConfigDict(frozen=True)

    tool_name: str
    arguments: dict[str, Any]
    """Byte-identisch das, was der Nutzer in der Vorschau gesehen hat."""

    origin_run_id: UUID
    """Der kontaminierte Lauf, aus dem der Payload stammt. Nur für das Audit —
    der saubere Lauf greift nicht darauf zu."""

    approved_at: datetime
    approved_by: UUID
    payload_hash: str = Field(min_length=64, max_length=64)
    """SHA-256 über die kanonisierten Argumente. Der Executor prüft ihn vor der
    Ausführung erneut: Ohne diese Prüfung könnte zwischen Bestätigung und
    Ausführung etwas anderes eingeschleust werden."""


class InvocationStatus(StrEnum):
    """Lebenszyklus eines Werkzeugaufrufs."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    """Endgültig **ohne** Wirkung: Das Gate hat vor dem Handler abgewiesen, oder
    das Werkzeug hat selbst ``ok=False`` gemeldet."""

    EFFECT_UNKNOWN = "effect_unknown"
    """Der Handler wurde betreten, und niemand weiß, was daraus wurde.

    **Der Name ist die Zusage.** Er behauptet nicht, dass etwas schiefging,
    sondern dass es sich nicht feststellen lässt — und das ist für eine
    Wiederaufnahme die wichtigere Auskunft.

    Zuvor stand hier ``FAILED``, und zwar für zwei entgegengesetzte Lagen: „das
    Werkzeug hat abgelehnt" und „der Handler ist geflogen". Für den Betrieb war
    das gleichgültig; für die Frage „darf ich das wiederholen?" ist es der
    Unterschied zwischen *ja* und *auf keinen Fall*.
    """

    UNDONE = "undone"
    """Der Aufruf wurde ausgeführt und anschließend zurückgenommen.

    **Der Zustand sagt: Der Rückgängig-Weg ist verbraucht** — ein zweites Undo
    trifft diese Zeile nicht mehr. Ob die Rücknahme auch gewirkt hat, steht im
    Ergebnis: Ein Handler, der dabei scheitert, hinterlässt hier trotzdem
    ``undone``, und das ist die unangenehme, aber richtige Auskunft. Der
    Anspruch wird **vor** der Rücknahme verbraucht, aus demselben Grund wie
    beim Grant: Zwei gleichzeitige Rücknahmen desselben Aufrufs dürfen nicht
    beide durchgehen.
    """

    EXPIRED = "expired"
    BLOCKED = "blocked"
    """Von der Policy Engine gesperrt — z. B. durch Taint."""

    @property
    def is_settled(self) -> bool:
        """Steht das Ergebnis fest?

        ``EFFECT_UNKNOWN`` ausdrücklich **nicht**: Ein Zustand, der als
        erledigt zählt, käme nie zur Wiederaufnahme — und genau dorthin gehört
        er.
        """
        return self in {
            InvocationStatus.EXECUTED,
            InvocationStatus.FAILED,
            InvocationStatus.BLOCKED,
            InvocationStatus.REJECTED,
            InvocationStatus.EXPIRED,
            InvocationStatus.UNDONE,
        }

    @property
    def may_retry(self) -> bool:
        """Darf ein Aufruf in diesem Zustand automatisch wiederholt werden?

        Die Zusage steht am Vertrag und nicht in der Wiederaufnahme: Wer später
        entscheidet, was wiederholt wird, soll die Frage nicht neu beantworten
        müssen — und sie nicht anders beantworten können.

        ``FAILED`` steht hier bewusst **nicht** drin. „Das Werkzeug hat
        abgelehnt" heißt nicht „es ist nichts geschehen": Ein Werkzeug kann
        halb gewirkt und dann ``ok=False`` gemeldet haben. Ob ein solcher
        Aufruf wiederholbar ist, hängt am Werkzeug (``ToolSpec.idempotent``)
        und nicht am Protokolleintrag.
        """
        return self in {InvocationStatus.BLOCKED, InvocationStatus.REJECTED}

    def __str__(self) -> str:
        return self.value


UNDO_TTL = timedelta(minutes=15)
"""Wie lange sich ein ausgeführter Aufruf zurücknehmen lässt.

Eine Eigenschaft des Weges und keine des Tokens — deshalb steht sie hier und
nicht am Feld.

**Warum überhaupt eine Frist.** Ein Rückgängig-Weg ohne Ende ist ein zweites
Löschrecht durch die Hintertür: Wer ein Konto Wochen später übernimmt, nähme
alles zurück, was je angelegt wurde. Fünfzehn Minuten decken den Fall ab, für
den Undo gedacht ist — „das war falsch, das wollte ich nicht" —, und decken
den anderen nicht ab.

Gemessen wird sie an ``executed_at`` und in der Datenbank, nicht in Python:
dieselbe Überlegung wie bei der Frist auf dem Anspruch."""


class ToolResult(BaseModel):
    """Ergebnis einer Werkzeugausführung."""

    ok: bool
    data: dict[str, Any] | None = None
    display: str = ""
    """Kurzfassung für die Oberfläche."""

    error: str | None = None
    undo_token: str | None = None
    """Womit **dieses Werkzeug** seinen eigenen Aufruf zurücknehmen kann.

    Für ``calendar.create`` die Kennung des angelegten Termins. Was darin steht,
    versteht nur der Undo-Handler desselben Werkzeugs; für alle anderen ist es
    eine undurchsichtige Zeichenkette.

    **Kein Inhaberpapier.** Der Wert wird im Werkzeugprotokoll abgelegt und
    **nicht** an den Client herausgegeben. Wer zurücknehmen will, nennt die
    Kennung des *Aufrufs*; woraufhin die Zugehörigkeit über den Lauf geprüft
    wird und der Token aus der Datenbank kommt. Andersherum — Token an den
    Client, Client schickt ihn zurück — wäre er eine Fähigkeit: Wer einen
    fremden erriete oder abfinge, löschte einen fremden Termin.

    Die Frist von 15 Minuten steht nicht hier, sondern in ``UNDO_TTL``: Sie ist
    eine Eigenschaft des Weges und keine des Tokens.
    """

    sources: list[Source] = Field(default_factory=list)
    produced_data_class: DataClass = DataClass.P1
    """Klassifikation des Ergebnisses — propagiert in den Lauf."""

    taints_context: bool = False
    """Hat dieses Ergebnis Fremdinhalt eingebracht?"""

    @model_validator(mode="after")
    def _error_when_not_ok(self) -> ToolResult:
        if not self.ok and not self.error:
            raise ValueError("Fehlgeschlagene Werkzeugaufrufe müssen 'error' setzen.")
        return self


class ToolInvocation(BaseModel):
    """Ein konkreter Werkzeugaufruf innerhalb eines Laufs."""

    id: UUID
    run_id: UUID
    step_seq: int | None = None
    """Der Planschritt, zu dem dieser Aufruf gehört — oder ``None``.

    Ersetzt ein ``step_id: UUID``, das niemand setzte und das auch nicht passte:
    Ein Planschritt trägt eine Nummer, keine UUID.

    ``None`` ist keine Lücke, sondern die richtige Auskunft für
    ``POST /runs/{id}/steps`` — dort nennt der Aufrufer das Werkzeug, und der
    Aufruf gehört zu keinem geplanten Schritt. Die Wiederaufnahme darf ihn
    deshalb auch keinem zuordnen.
    """
    tool_name: str
    arguments: dict[str, Any]
    risk_level: RiskLevel
    policy_decision: PolicyEffect
    decision_reason: str
    idempotency_key: str | None = None
    status: InvocationStatus = InvocationStatus.PENDING
    result: ToolResult | None = None
    created_at: datetime
    executed_at: datetime | None = None
