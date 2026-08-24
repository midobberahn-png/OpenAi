"""Wiederaufnahme: Was ist aus einem hängenden Schritt geworden?

Ein Lauf in ``executing`` mit belegtem ``current_step`` ist entweder gerade in
Arbeit oder hängengeblieben — **von außen sind die beiden nicht
unterscheidbar**. Genau daran hing die Wiederaufnahme, und die beiden
naheliegenden Auswege sind beide falsch: blind wiederholen öffnet den doppelten
Seiteneffekt, gar nichts tun blockiert den Lauf dauerhaft.

Zwei Stücke machen den Unterschied, und beide stehen inzwischen:

* **Die Frist** (``RunState.claimed_at``) trennt „in Arbeit“ von
  „hängengeblieben“. Sie ist eine Obergrenze für die Dauer eines Schrittes und
  kein Timeout — dazu unten mehr.
* **Das Werkzeugprotokoll** (``InvocationStore.for_step``) trennt
  „nachweislich nichts geschehen“ von „Wirkung möglich“. Es wird **vor** dem
  Handler geschrieben und in eigener Transaktion committet; genau deshalb ist
  es im Absturzfall da.

Dieses Modul fällt daraus ein Urteil und **wirkt selbst nicht**. Es legt nichts
an, es wiederholt nichts, es bricht nichts ab. Der Grund ist derselbe wie beim
Rest des Orchestrators: Wer entscheidet, soll nicht zugleich ausführen — sonst
gibt es keine Stelle, an der die Entscheidung geprüft werden kann.

**Was die Übernahme leistet und was nicht.** Sie sperrt den alten Arbeiter vom
*Schreiben* aus: Sein Fencing-Token gilt nicht mehr, sein ``save()`` trifft
keine Zeile. Sie hält ihn nicht davon ab, zu *wirken* — ein Prozess, der im
Handler steht, legt den Termin an, gleichgültig, wem der Anspruch inzwischen
gehört. Kooperativ abbrechen ließe er sich nur, wenn er noch läuft; der Fall,
für den die Wiederaufnahme gebaut ist, ist der, in dem er das nicht tut.

Daraus folgt die Bedeutung der Frist: Sie muss länger sein als der längste
mögliche Schritt. Wer sie knapp wählt, übernimmt Schritte, die noch laufen —
und dann entscheidet allein das Protokoll darüber, ob doppelt gewirkt wird.
Deshalb wird nach jeder Übernahme **erneut** nachgesehen (``take_over``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from uuid import UUID

from jarvis_contracts import Run, RunStatus, ToolInvocation
from jarvis_core.ports.invocations import InvocationStore
from jarvis_core.ports.runs import RunStore
from jarvis_core.tools.registry import ToolRegistry

__all__ = ["DEFAULT_IDLE", "DEFAULT_LEASE", "Recovery", "RecoveryVerdict", "StepAssessment"]


DEFAULT_LEASE = timedelta(minutes=15)
"""Wie lange ein Anspruch gilt, bevor er übernommen werden darf.

Großzügig, und das ist die richtige Richtung. Die Frist ist die Obergrenze für
die Dauer eines Schrittes: Ein Modellaufruf über ein lokales 8-B-Modell
braucht Sekunden, ein Schritt, der auf eine Bestätigung wartet, steht gar nicht
unter dieser Frist (der Lauf steht dann in ``awaiting_confirmation``). Fünfzehn
Minuten sind daher weit jenseits des Normalfalls — und genau das sollen sie
sein: Zu kurz gewählt, übernimmt die Wiederaufnahme Schritte, die noch laufen,
und der Schutz vor dem doppelten Seiteneffekt hängt allein am Protokoll.

Zu lang gewählt kostet es Wartezeit, und Wartezeit ist die billigere Seite.
"""


DEFAULT_IDLE = timedelta(minutes=2)
"""Wie lange ein **begonnener** Lauf liegen darf, bevor ihn jemand aufgreift.

Eine zweite Frist neben ``DEFAULT_LEASE``, und ausdrücklich nicht dieselbe
Zahl: Die eine beantwortet „wie lange darf ein Schritt dauern", diese hier
„wie lange darf ein Lauf zwischen zwei Schritten stillstehen". Ein Wert für
beides sähe sparsam aus und wäre die Verwechslung zweier Fragen — wer eine
davon ändert, änderte stillschweigend die andere mit.

**Warum es diese Frist überhaupt braucht.** Ein Lauf mitten im Plan hat
*keinen* Anspruch — er wird nach jedem Schritt freigegeben. Wer den Browser
schließt, während Schritt zwei von vier fällig ist, hinterlässt einen Lauf, den
niemand aufgreift: kein Anspruch, also kein Fund; kein Zuschauer, also kein
``advance``. Aufgefallen erst mit dem Chat, der einen Plan tatsächlich zu Ende
treibt.

Zwei Minuten sind großzügig gegenüber dem Normalfall (die Oberfläche treibt in
Sekunden) und knapp genug, dass ein geschlossener Browser nicht in eine
Stunde Stillstand führt.
"""


class RecoveryVerdict(StrEnum):
    """Was mit einem beanspruchten Schritt geschehen darf."""

    NICHT_BEANSPRUCHT = "unclaimed"
    """Kein Anspruch offen — es gibt nichts wiederaufzunehmen."""

    IN_ARBEIT = "in_progress"
    """Die Frist läuft noch. Der Schritt gilt als in Arbeit, auch wenn niemand
    mehr an ihm arbeitet: Ein Arbeiter, der vor einer Sekunde abgestürzt ist,
    ist von einem, der gerade rechnet, nicht zu unterscheiden — und die
    Vermutung zugunsten des Laufenden ist die einzige, die keinen zweiten
    Termin anlegt."""

    NEU_VERGEBBAR = "reassignable"
    """Die Frist ist abgelaufen, und das Protokoll sagt: nichts ist geschehen.

    „Nichts geschehen“ ist hier nachgewiesen und nicht vermutet — entweder gibt
    es zu diesem Schritt keinen Aufruf (der Handler wurde nie betreten), oder
    jeder vorhandene trägt einen Zustand, den ``InvocationStatus.may_retry``
    ausdrücklich als wiederholbar führt."""

    ENTSCHEIDUNG_NOETIG = "needs_decision"
    """Die Frist ist abgelaufen, aber der Schritt hat möglicherweise gewirkt.

    Kein Automat vergibt das neu. Der Zustand ist unbequem und ehrlich: Ein
    Termin, der vielleicht im Kalender steht, ist keine Lage, die sich durch
    Nachdenken auflösen lässt — es muss jemand nachsehen. Der Weg dorthin ist
    ``ToolInvocation`` mit Argumenten, Zeit und Zustand."""

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class StepAssessment:
    """Das Urteil über den beanspruchten Schritt eines Laufs."""

    verdict: RecoveryVerdict
    seq: int | None
    reason: str
    """Für Menschen. Steht in der Ablehnung von ``advance`` und ist dort die
    einzige Auskunft, die ein Aufrufer über einen fremden Anspruch bekommt —
    deshalb nennt sie den Grund und keine Kennungen."""

    invocations: tuple[ToolInvocation, ...] = ()
    """Was das Protokoll zu diesem Schritt weiß. Leer bei
    ``NICHT_BEANSPRUCHT``; bei ``ENTSCHEIDUNG_NOETIG`` ist es das Material, aus
    dem ein Mensch entscheidet."""

    claim_id: UUID | None = None
    """Bei einer erfolgreichen Übernahme das **neue** Fencing-Token.

    Es steht auch dann hier, wenn das Urteil nach der Übernahme
    ``ENTSCHEIDUNG_NOETIG`` lautet — der Anspruch wird dann gehalten und nicht
    freigegeben. Ihn zurückzugeben hieße, den Schritt für den nächsten
    Anwärter zu öffnen, während unklar ist, ob er schon gewirkt hat."""


class Recovery:
    """Beurteilt hängende Schritte und übernimmt sie, wo es nachweislich geht."""

    def __init__(
        self,
        *,
        runs: RunStore,
        invocations: InvocationStore,
        tools: ToolRegistry,
        lease: timedelta = DEFAULT_LEASE,
    ) -> None:
        self._runs = runs
        self._invocations = invocations
        self._tools = tools
        self._lease = lease

    async def assess(self, run: Run) -> StepAssessment:
        """Was ist mit dem beanspruchten Schritt dieses Laufs?

        Folgenlos: Diese Methode schreibt nichts. Sie darf deshalb auch dann
        aufgerufen werden, wenn noch offen ist, was aus dem Urteil folgt.

        **Die Frist wird nicht in Python gerechnet.** ``claimed_at`` stammt aus
        der Datenbankuhr; ein Vergleich gegen die lokale Uhr wäre bei zwei
        Rechnern eine andere Messung als die, die ``reclaim_step`` anstellt.
        Hier wird deshalb nur beurteilt, *ob* das Protokoll eine Wirkung
        ausschließt — ob die Frist abgelaufen ist, entscheidet die Datenbank in
        derselben Anweisung, die den Anspruch übernimmt.
        """
        seq = run.state.current_step
        if seq is None:
            return StepAssessment(
                RecoveryVerdict.NICHT_BEANSPRUCHT,
                None,
                "Kein Schritt ist beansprucht.",
            )

        if run.state.claimed_at is None:
            # Ein Anspruch ohne Frist. Die Datenbank vergibt ihn nicht neu, und
            # das Urteil sagt hier dasselbe: Ohne Zeitpunkt gibt es keine
            # Grundlage für „lange genug her“.
            return StepAssessment(
                RecoveryVerdict.ENTSCHEIDUNG_NOETIG,
                seq,
                f"Schritt {seq} ist ohne Frist beansprucht — er stammt aus der Zeit vor "
                "der Fristmessung und wird nicht automatisch übernommen.",
                await self._protokoll(run, seq),
            )

        eintraege = await self._protokoll(run, seq)
        wirkung = self._wirkung_moeglich(run, seq, eintraege)
        if wirkung is not None:
            return StepAssessment(RecoveryVerdict.ENTSCHEIDUNG_NOETIG, seq, wirkung, eintraege)

        return StepAssessment(
            RecoveryVerdict.NEU_VERGEBBAR,
            seq,
            f"Schritt {seq} hat nachweislich nicht gewirkt und darf nach Ablauf der "
            "Frist übernommen werden.",
            eintraege,
        )

    async def take_over(self, run: Run) -> StepAssessment:
        """Übernimmt den Schritt, wenn die Frist es hergibt — und urteilt danach.

        **Die Reihenfolge ist die Aussage dieser Methode, und sie war einmal
        andersherum.** Zuerst wurde das Protokoll gefragt und bei einer
        möglichen Wirkung sofort zurückgegangen; die Datenbank kam in diesem
        Fall gar nicht vor. Das ist an zwei Stellen falsch, und beide fallen
        erst auf, seit ein Mensch den Zustand zu sehen bekommt:

        * **Ein laufender Schritt sah aus wie ein hängender.** Der
          Protokolleintrag entsteht *vor* dem Handler; ``pending`` ist nicht
          wiederholbar. Am Protokoll allein sind die beiden nicht zu
          unterscheiden — unterscheidbar macht sie allein die Frist.
        * **Die Frist wurde nie erneuert.** Wer nicht übernimmt, lässt
          ``claimed_at`` alt stehen, und der Arbeiter findet denselben Lauf in
          jedem Durchgang wieder. Für immer.

        Jetzt gilt:

        1. **Übernehmen** — atomar, mit der Frist in derselben Anweisung. Die
           Datenbank entscheidet, ob überhaupt etwas hängt; sie liest dieselbe
           Uhr, die den Anspruch gesetzt hat. Gelingt es nicht, läuft die
           Frist noch: *in Arbeit*.
        2. **Beurteilen** — jetzt, mit dem Anspruch in der Hand. Was das
           Protokoll sagt, gilt für den Zustand *nach* der Übernahme, und
           genau darauf kommt es an: Zwischen einer Beurteilung davor und der
           Übernahme verginge Zeit, in der der alte Arbeiter den Handler
           betreten haben kann.

        Fällt ② ungünstig aus, **bleibt der Anspruch beim Übernehmer** und der
        Schritt bekommt einen Vermerk. Ihn freizugeben wäre die schlechtere
        Wahl: Der Schritt stünde dem nächsten Anwärter offen, während unklar
        ist, ob er bereits gewirkt hat. Der Vermerk ist die Gegenrichtung dazu
        — ohne ihn wäre „gehalten" von „gesperrt" nicht zu unterscheiden, und
        der Lauf hätte keinen Ausgang mehr.

        **Übernehmen heißt hier nicht wiederholen.** Der Anspruch wird
        gehalten, nicht verbraucht; gewirkt wird nichts. Das bleibt der
        Grundsatz dieses Moduls: Wer entscheidet, führt nicht aus.
        """
        seq = run.state.current_step
        if seq is None:
            return StepAssessment(
                RecoveryVerdict.NICHT_BEANSPRUCHT, None, "Kein Schritt ist beansprucht."
            )
        if run.state.claimed_at is None:
            # Ein Anspruch ohne Frist. ``_RECLAIM`` gibt ihn ohnehin nicht her,
            # aber die Auskunft darüber soll die richtige sein: Er wird nicht
            # übernommen, und der Grund gehört genannt.
            return await self.assess(run)

        kennung = await self._runs.reclaim_step(
            run.id, seq, erwarteter_status=run.status, frist=self._lease
        )
        if kennung is None:
            return StepAssessment(
                RecoveryVerdict.IN_ARBEIT,
                seq,
                f"Schritt {seq} wurde nicht übernommen: Die Frist läuft noch, "
                "oder ein anderer war schneller.",
            )

        eintraege = await self._protokoll(run, seq)
        wirkung = self._wirkung_moeglich(run, seq, eintraege)
        if wirkung is not None:
            await self._runs.mark_unresolved(run.id, seq, kennung)
            return StepAssessment(
                RecoveryVerdict.ENTSCHEIDUNG_NOETIG,
                seq,
                f"{wirkung} Der Anspruch wurde übernommen und wird gehalten — der "
                "Schritt bleibt gesperrt, bis jemand entschieden hat, wie es weitergeht.",
                eintraege,
                claim_id=kennung,
            )

        return StepAssessment(
            RecoveryVerdict.NEU_VERGEBBAR,
            seq,
            f"Schritt {seq} war hängengeblieben und ist übernommen.",
            eintraege,
            claim_id=kennung,
        )

    async def _protokoll(self, run: Run, seq: int) -> tuple[ToolInvocation, ...]:
        return tuple(await self._invocations.for_step(run.id, seq))

    def _wirkung_moeglich(
        self, run: Run, seq: int, eintraege: tuple[ToolInvocation, ...]
    ) -> str | None:
        """Der Grund, falls eine Wirkung nicht ausgeschlossen ist — sonst ``None``.

        **Die Frage wird nicht hier beantwortet, sondern nachgeschlagen.**
        ``InvocationStatus.may_retry`` trägt die Zusage am Vertrag, damit
        niemand sie zweimal — und dann verschieden — beantwortet. Dieses Modul
        liest sie und ergänzt genau zwei Dinge, die der Protokolleintrag nicht
        wissen kann: um welches Werkzeug es geht und was der Plan an dieser
        Stelle vorsah.
        """
        if not eintraege:
            return None

        idempotent = self._ist_idempotent(run, seq)
        heikel = [e for e in eintraege if not e.status.may_retry]
        if not heikel or idempotent:
            # ``idempotent`` ist die Erlaubnis des Werkzeugs, ein zweites Mal
            # gerufen zu werden. Sie steht in ``ToolSpec`` und nicht im
            # Protokoll, weil sie eine Eigenschaft des Werkzeugs ist und keine
            # dieses Aufrufs.
            return None

        zustaende = ", ".join(sorted({str(e.status) for e in heikel}))
        return (
            f"Schritt {seq} hat möglicherweise gewirkt: Das Protokoll führt {len(heikel)} "
            f"Aufruf(e) im Zustand {zustaende}, und {self._werkzeugname(run, seq) or 'das Werkzeug'} "
            "darf nicht ohne Nachsehen wiederholt werden."
        )

    def _werkzeugname(self, run: Run, seq: int) -> str | None:
        if run.plan is None:
            return None
        for schritt in run.plan.steps:
            if schritt.seq == seq and schritt.kind == "tool":
                return schritt.target
        return None

    def _ist_idempotent(self, run: Run, seq: int) -> bool:
        """Darf dieser Schritt ein zweites Mal laufen, ohne doppelt zu wirken?

        Der Vorgabewert ist **nein**, und er gilt in jedem Zweifelsfall: kein
        Plan, kein Werkzeugschritt, ein Werkzeug, das der Katalog nicht mehr
        kennt. Ein unbekanntes Werkzeug für wiederholbar zu halten wäre die
        Annahme, die genau dann falsch ist, wenn sie teuer wird.
        """
        name = self._werkzeugname(run, seq)
        if name is None:
            return False
        spec = self._tools.get(name)
        return spec is not None and spec.idempotent


def ist_haengend(run: Run) -> bool:
    """Kandidat für eine Wiederaufnahme?

    Bewusst großzügig und ohne Frist: Ob die Frist abgelaufen ist, entscheidet
    die Datenbank. Diese Funktion beantwortet nur, ob es sich überhaupt lohnt
    nachzusehen.

    **Der Anspruch ist der Marker, nicht der Status.** ``queued`` gehört dazu,
    weil ein Anspruch *vor* dem Übergang nach ``executing`` entsteht: Ein
    Arbeiter, der dazwischen abstürzt, hinterlässt einen beanspruchten Lauf in
    ``queued``. Wer hier nur ``executing`` gelten ließe, übersähe genau den
    Fall, für den die Wiederaufnahme gebaut ist — gemessen an einem
    Durchgang, der nichts fand.

    Ein Lauf ohne Anspruch ist dagegen keiner: Niemand hat begonnen, und ihn
    von sich aus anzustoßen wäre etwas anderes als eine Wiederaufnahme.
    """
    return run.state.current_step is not None and run.status in {
        RunStatus.QUEUED,
        RunStatus.EXECUTING,
    }
