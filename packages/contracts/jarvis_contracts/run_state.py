"""Typisierter Laufzustand.

Siehe docs/04-orchestrator.md §6 und docs/16-v1.1-review.md (Beschluss 8).

V1.0 hielt den Zustand in untypisiertem JSONB. Der Zustandsautomat war damit
spezifiziert, aber nicht durchgesetzt: Ein Tippfehler in einem Schlüsselnamen
wäre erst zur Laufzeit aufgefallen, und zwar an der Stelle, an der der Lauf
nach einem Neustart wiederaufgenommen wird — also im schlechtestmöglichen
Moment.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = ["Correction", "RunState", "StepOutcome"]


class StepOutcome(BaseModel):
    """Ergebnis eines abgeschlossenen Planschritts.

    Bleibt bei einer Korrektur erhalten — genau das ist der Unterschied
    zwischen Korrektur und Abbruch (docs/16-v1.1-review.md §5).
    """

    model_config = ConfigDict(frozen=True)

    seq: int = Field(ge=1)
    ok: bool
    summary: str = Field(max_length=2000)
    """Für Menschen — die Anzeigezeile des Werkzeugs."""

    model_view: str = Field(default="", max_length=8000)
    """Für Modelle — der deklarierte, gekappte, ausgezeichnete Teil des
    Ergebnisses.

    Getrennt von ``summary``, weil die Empfänger verschieden sind: Die
    Zusammenfassung sieht ein Mensch in der Oberfläche, diese Sicht ein Modell
    im Prompt. Ein Feld für beide hieße, die Kappung für den einen am Bedarf
    des anderen auszurichten.

    **Warum das hier steht und nicht das rohe Ergebnis.** ``ToolResult.data``
    fasst bei ``files.read`` bis 256.000 Bytes und ist untypisiert. Es je Lauf
    in den Zustand zu schreiben, hieße unbegrenzte Fremddaten in die
    Laufpersistenz zu legen — mit allem, was daran hängt: Sicherungen,
    Löschfristen, Größe. Was hier liegt, ist bereits das, was ein Modell sehen
    darf, und nicht mehr.
    """

    finished_at: datetime


class Correction(BaseModel):
    """Eine Nutzerkorrektur während des Laufs."""

    model_config = ConfigDict(frozen=True)

    text: str = Field(min_length=1, max_length=2000)
    at: datetime
    invalidated_steps: list[int] = Field(default_factory=list)
    """Schritte, die wegen der geänderten Randbedingung neu laufen müssen."""


class RunState(BaseModel):
    """Vollständiger Zwischenzustand eines Laufs.

    Wird nach jedem Schritt persistiert. Aus dieser Struktur allein muss ein
    Worker-Neustart den Lauf fortsetzen können — sie darf keine Verweise auf
    Objekte im Speicher enthalten.
    """

    completed_steps: list[StepOutcome] = Field(default_factory=list)
    current_step: int | None = None
    """Welcher Planschritt gerade läuft — und zugleich der Anspruch darauf.

    Zwei Bedeutungen in einem Feld, und das ist bewusst so knapp: *Welcher
    Schritt ist fachlich dran?* und *wer darf ihn ausführen?* fallen hier
    zusammen, weil immer höchstens einer läuft.
    """

    claim_id: UUID | None = None
    """Wem der Anspruch gehört — das Fencing-Token.

    ``current_step`` allein sagt, **dass** ein Schritt beansprucht ist, nicht
    **von wem**. Solange nur der Anspruchsinhaber freigibt, trägt das. Sobald
    eine Wiederaufnahme hinzukommt — ein hängender Lauf wird nach einer Frist
    neu vergeben —, gibt es zwei Anwärter auf denselben Schritt, und dann ist
    „ist beansprucht?" die falsche Frage. Die richtige lautet „ist es noch
    *mein* Anspruch?".

    Ohne dieses Feld könnte ein alter Arbeiter, der nach seinem Ablauf
    aufwacht, den Anspruch eines neueren freigeben oder sein Ergebnis
    überschreiben — und der Statusvergleich fiele nicht auf, weil beide Läufe
    in ``executing`` stehen.

    Eingeführt **vor** der Wiederaufnahme und nicht danach: Ein Token
    nachzurüsten, während bereits Ansprüche in der Datenbank stehen, hieße,
    laufenden Zustand zu wandern.
    """

    claimed_at: datetime | None = None
    """Seit wann der Anspruch gilt — die Frist.

    Ein Lauf in ``executing`` mit belegtem ``current_step`` ist entweder gerade
    in Arbeit oder hängengeblieben, und **von außen sind die beiden nicht
    unterscheidbar**. Ohne einen Zeitpunkt bleibt nur die Wahl zwischen blind
    wiederholen (der doppelte Seiteneffekt) und gar nichts tun (der dauerhaft
    blockierte Lauf).

    **Die Zeit stammt aus der Datenbank und nicht aus dem Arbeitsspeicher des
    Anspruchstellers.** Wer die Frist misst, muss dieselbe Uhr lesen wie der,
    der sie gesetzt hat; bei zwei Prozessen auf zwei Rechnern ist das nicht die
    lokale. ``_CLAIM`` schreibt deshalb ``now()`` in derselben Anweisung, die
    den Anspruch begründet.

    **``None`` heißt „Anspruch ohne Frist" und ist nicht dasselbe wie „lange
    her".** Solche Ansprüche stammen aus der Zeit vor diesem Feld. Sie werden
    nicht automatisch neu vergeben — die Frist ist die einzige Grundlage für
    diese Entscheidung, und ohne sie gibt es keine.
    """

    unresolved_step: int | None = None
    """Gesetzt, wenn ein Mensch entscheiden muss, wie es mit diesem Schritt
    weitergeht — die Frist ist abgelaufen und der Schritt hat **möglicherweise
    gewirkt**.

    **Warum das persistiert wird und nicht bei Bedarf errechnet.** Aus der
    Zeile allein ist der Zustand nicht ablesbar: Ein Schritt, der gerade läuft,
    trägt denselben Protokolleintrag wie einer, der mitten in der Wirkung
    abgestürzt ist — der Eintrag entsteht *vor* dem Handler. Unterscheidbar
    macht sie allein die Frist, und die rechnet die Datenbank in derselben
    Anweisung, die übernimmt. Der Befund gehört deshalb dorthin, wo er
    festgestellt wurde, und nicht in eine Vermutung des Lesers.

    Gesetzt wird er ausschließlich nach einer **erfolgreichen Übernahme**
    (``Recovery.take_over``). Das ist die Bedingung, die ihn tragfähig macht:
    Wer ihn sieht, weiß, dass die Frist abgelaufen *war* und dass der Anspruch
    daneben **uns** gehört — und nur gegen dieses Fencing-Token ist eine
    Entscheidung sicher.

    Ein Automat räumt ihn nicht ab. Er fällt mit der Entscheidung eines
    Menschen (``jarvis_core.orchestrator.resolution``) oder gar nicht.
    """

    awaiting_action_id: UUID | None = None
    """Gesetzt, solange auf eine Bestätigung gewartet wird."""

    partial_output: str = Field(default="", max_length=200_000)
    """Bisher erzeugter Text. Bei Budgetüberschreitung wird er als
    Teilergebnis ausgeliefert statt verworfen."""

    corrections: list[Correction] = Field(default_factory=list)
    replan_count: int = Field(default=0, ge=0)
    """Genau ein Replan ist zulässig (docs/04-orchestrator.md §8); mehr führt
    erfahrungsgemäß zu Schleifen ohne Qualitätsgewinn."""

    interrupted_at: datetime | None = None
    sanitized_payload_hash: str | None = None
    """Bei sanierten Läufen: der eingefrorene Payload-Hash. Der Executor
    vergleicht ihn vor der Ausführung erneut."""

    @model_validator(mode="after")
    def _consistent(self) -> RunState:
        seqs = [s.seq for s in self.completed_steps]
        if len(seqs) != len(set(seqs)):
            raise ValueError("Ein Schritt darf nicht zweimal als abgeschlossen geführt werden.")
        if self.current_step is not None and self.current_step in seqs:
            raise ValueError(
                f"Schritt {self.current_step} ist gleichzeitig laufend und abgeschlossen."
            )
        # Anspruch und Kennung gehören zusammen. Ein ``current_step`` ohne
        # ``claim_id`` wäre ein Anspruch ohne Inhaber — niemand könnte ihn
        # freigeben, ohne einen fremden zu treffen. Eine ``claim_id`` ohne
        # ``current_step`` wäre ein Inhaber ohne Anspruch.
        if (self.current_step is None) != (self.claim_id is None):
            raise ValueError(
                "current_step und claim_id gelten gemeinsam: Ein Anspruch ohne Inhaber "
                "lässt sich nicht sicher freigeben, ein Inhaber ohne Anspruch bindet nichts."
            )
        # ``claimed_at`` steht bewusst **nicht** in derselben Bedingung, und
        # zwar in beide Richtungen:
        #
        # *Ein Anspruch ohne Frist ist zulässig.* Er ist der Altbestand aus der
        # Zeit vor diesem Feld. Ihn zurückzuweisen hieße, ihn beim Laden
        # unlesbar zu machen — und damit genau den Lauf zu verlieren, der
        # wiederaufgenommen werden soll.
        #
        # *Eine Frist ohne Anspruch wird stillschweigend fallen gelassen* statt
        # zurückgewiesen. Das ist die einzige Stelle dieser Prüfung, an der
        # nicht laut gescheitert wird, und der Grund ist ein Rollout: Eine
        # ältere Prozessversion gibt einen Anspruch frei, ohne das Feld zu
        # kennen, und ließe die Frist stehen. Ein ``ValueError`` machte den Lauf
        # dann dauerhaft **unladbar** — im schlechtestmöglichen Moment, nämlich
        # dem, in dem eine Wiederaufnahme ihn braucht. Eine Frist, die an
        # nichts hängt, ist dagegen bedeutungslos: Übernommen wird nur, wo ein
        # ``claim_id`` steht.
        if self.claimed_at is not None and self.claim_id is None:
            self.claimed_at = None
        # ``unresolved_step`` hängt am Anspruch, gegen den entschieden wird.
        # Ohne ihn — oder an einem anderen Schritt — ist der Vermerk veraltet
        # und wird fallen gelassen, aus demselben Rollout-Grund wie oben.
        #
        # **Und die Richtung stimmt.** Ein verlorener Vermerk heißt: Die
        # Oberfläche bietet keine Entscheidung an, und der Schritt bleibt
        # gesperrt. Das ist die unbequeme Seite, nicht die gefährliche — die
        # gefährliche wäre ein Vermerk, der einen fremden oder längst
        # abgelösten Anspruch auflösen ließe.
        if self.unresolved_step is not None and (
            self.claim_id is None or self.unresolved_step != self.current_step
        ):
            self.unresolved_step = None
        return self

    @property
    def completed_seqs(self) -> set[int]:
        return {s.seq for s in self.completed_steps}

    def with_step_done(self, outcome: StepOutcome) -> RunState:
        """Schritt abschließen. Erzeugt einen neuen Zustand, statt zu mutieren —
        der alte bleibt für das Aktivitätsprotokoll erhalten.

        Gibt den Anspruch mit frei: Ein erledigter Schritt braucht keinen mehr,
        und ``claim_id`` muss mit ``current_step`` fallen — sonst schlägt die
        Konsistenzprüfung zu, und zwar zu Recht.
        """
        return self.model_copy(
            update={
                "completed_steps": [*self.completed_steps, outcome],
                "current_step": None,
                "claim_id": None,
                "claimed_at": None,
                "unresolved_step": None,
            }
        )

    def with_correction(self, correction: Correction) -> RunState:
        """Korrektur einarbeiten: betroffene Schritte fallen weg, der Rest bleibt.

        Ein Abbruch mit Neustart verwürfe alles und kostete die volle Latenz
        erneut.

        **Ein laufender Schritt bleibt beansprucht.** Diese Methode setzte
        früher ``current_step=None`` und ließ ``claim_id`` stehen — einen
        Zustand, den der Validator oben ausdrücklich verbietet. Aufgefallen ist
        das niemandem, weil ``model_copy(update=...)`` nicht erneut prüft: Der
        Fehler entsteht beim Schreiben und schlägt beim Lesen zu, also nach
        einem Neustart und damit genau dann, wenn eine Wiederaufnahme den Lauf
        braucht. Gemeldet aus einer externen Prüfung.

        Die naheliegende Reparatur wäre gewesen, ``claim_id`` mit zu löschen.
        Sie wäre intern konsistent und fachlich falsch: Ein Wertobjekt im
        Arbeitsspeicher eines Aufrufers kann keinen Arbeiter anhalten, der
        gerade ein Werkzeug ausführt. Es könnte ihm nur den Anspruch unter den
        Füßen wegziehen — und damit denselben doppelten Seiteneffekt öffnen,
        gegen den der Anspruch gebaut wurde.

        Eine Korrektur wird deshalb **vermerkt** und hebt keinen Anspruch auf.
        Wer einen laufenden Schritt tatsächlich abbrechen will, braucht einen
        gefencten Übergang mit der Anspruchskennung; den gibt es noch nicht,
        und solange er fehlt, ist „vermerken und weiterlaufen lassen" die
        einzige Antwort, die nichts kaputt macht.
        """
        invalidated = set(correction.invalidated_steps)
        kept = [s for s in self.completed_steps if s.seq not in invalidated]
        return self.model_copy(
            update={
                "completed_steps": kept,
                "corrections": [*self.corrections, correction],
            }
        )
