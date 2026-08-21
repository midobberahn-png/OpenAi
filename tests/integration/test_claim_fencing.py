"""Das Fencing-Token: Nur der Anspruchsinhaber gibt frei und schreibt.

**Herkunft: externer Prüfbericht.** ``release_step`` setzte ``current_step``
bedingungslos zurück — ohne zu prüfen, welcher Schritt freigegeben wird, wer
den Anspruch erworben hat und ob er noch gilt.

Solange nur der Inhaber freigibt, trägt das. Der Prüfer nennt die Lage, in der
es nicht mehr trägt, und sie steht auf der Roadmap: **Wiederaufnahme
abgebrochener Läufe.** Ein hängender Lauf wird nach einer Frist neu vergeben,
und ab da gibt es zwei Anwärter auf denselben Schritt.

Dann ist „ist beansprucht?" die falsche Frage. Die richtige lautet „ist es noch
*mein* Anspruch?" — und die kann ``current_step`` allein nicht beantworten.

**Warum jetzt und nicht mit der Wiederaufnahme.** Ein Token nachzurüsten,
während bereits Ansprüche in der Datenbank stehen, hieße laufenden Zustand zu
wandern. Vorher kostet es ein Feld.

Der Statusvergleich hilft dabei nicht: Beide Anwärter sehen ``executing``, und
ein Vergleich, der für beide gilt, unterscheidet sie nicht.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.run_store import PostgresRunStore
from jarvis_contracts import Run, RunStatus, RunTrigger
from jarvis_core.orchestrator import utc_now

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]


async def _lauf(engine: AsyncEngine) -> tuple[PostgresRunStore, Run]:
    """Ein angelegter Lauf ohne HTTP — hier geht es um den Speicher."""
    nutzer = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Fencing')"),
            {"i": nutzer, "m": f"fencing-{nutzer}@example.test"},
        )
    speicher = PostgresRunStore(engine)
    lauf = Run(
        id=uuid.uuid4(),
        user_id=nutzer,
        trigger=RunTrigger.USER,
        status=RunStatus.EXECUTING,
        trace_id=uuid.uuid4().hex,
        started_at=utc_now(),
    )
    await speicher.create(lauf)
    return speicher, lauf


@pytest.fixture(autouse=True)
async def _aufraeumen(engine: AsyncEngine):
    yield
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users WHERE email LIKE 'fencing-%'"))


class TestAnspruchUndKennung:
    async def test_der_anspruch_liefert_eine_kennung(self, engine: AsyncEngine) -> None:
        """Ohne Rückgabewert gäbe es nichts, womit man sich ausweisen könnte."""
        speicher, lauf = await _lauf(engine)
        kennung = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert isinstance(kennung, uuid.UUID)

    async def test_ein_zweiter_anspruch_bekommt_keine(self, engine: AsyncEngine) -> None:
        speicher, lauf = await _lauf(engine)
        assert await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING) is None

    async def test_kennung_und_schritt_stehen_im_zustand(self, engine: AsyncEngine) -> None:
        speicher, lauf = await _lauf(engine)
        kennung = await speicher.claim_step(lauf.id, 2, erwarteter_status=RunStatus.EXECUTING)
        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        assert geladen.state.current_step == 2
        assert geladen.state.claim_id == kennung


class TestNurDerInhaberGibtFrei:
    @pytest.mark.invariant("plan-step-claim-is-fenced")
    async def test_eine_fremde_kennung_gibt_nichts_frei(self, engine: AsyncEngine) -> None:
        """**Der Kern des Befunds.**

        Der Fall, den die Wiederaufnahme erzeugt: Ein alter Arbeiter wacht auf
        und räumt auf. Sein Anspruch ist längst neu vergeben — die Freigabe
        träfe den fremden.
        """
        speicher, lauf = await _lauf(engine)
        echt = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert echt is not None

        await speicher.release_step(lauf.id, uuid.uuid4())

        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        assert geladen.state.current_step == 1, "Der fremde Aufräumer hat den Anspruch gelöscht."
        assert geladen.state.claim_id == echt

    @pytest.mark.invariant("plan-step-claim-is-fenced")
    async def test_der_inhaber_gibt_frei(self, engine: AsyncEngine) -> None:
        """Die Gegenprobe. Eine Sperre, die niemand lösen kann, ist keine
        Absicherung, sondern ein blockierter Lauf."""
        speicher, lauf = await _lauf(engine)
        kennung = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert kennung is not None

        await speicher.release_step(lauf.id, kennung)

        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        assert geladen.state.current_step is None
        assert geladen.state.claim_id is None
        # Und danach ist der Schritt wieder zu haben.
        assert await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)


class TestNurDerInhaberSchreibt:
    """Das Token schützt nicht nur die Freigabe, sondern das Ergebnis.

    Ein Fencing-Token, das nur die Freigabe absichert, lässt die schlimmere
    Möglichkeit offen: Der abgelaufene Arbeiter schreibt sein Ergebnis über das
    des neuen. Der Statusvergleich fängt das nicht — beide Läufe stehen in
    ``executing``.
    """

    @pytest.mark.invariant("plan-step-claim-is-fenced")
    async def test_ein_abgelaufener_anspruch_schreibt_nicht_mehr(self, engine: AsyncEngine) -> None:
        from jarvis_core.ports.runs import RunStateConflict

        speicher, lauf = await _lauf(engine)
        alt = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert alt is not None

        # Die Wiederaufnahme vergibt neu — hier von Hand, weil es sie noch
        # nicht gibt. Der Ablauf ist derselbe: Anspruch weg, Anspruch neu.
        await speicher.release_step(lauf.id, alt)
        neu = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert neu is not None and neu != alt

        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        with pytest.raises(RunStateConflict):
            await speicher.save(geladen, erwarteter_status=RunStatus.EXECUTING, claim_id=alt)

    async def test_der_inhaber_schreibt(self, engine: AsyncEngine) -> None:
        speicher, lauf = await _lauf(engine)
        kennung = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert kennung is not None
        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        await speicher.save(geladen, erwarteter_status=RunStatus.EXECUTING, claim_id=kennung)

    async def test_ohne_kennung_schreibt_der_anspruchslose_pfad_weiter(
        self, engine: AsyncEngine
    ) -> None:
        """``POST /runs/{id}/steps`` hat keinen Anspruch und braucht keinen.

        ``claim_id=None`` heißt „ich berufe mich auf keinen" — und darf deshalb
        nicht an einem fremden scheitern. Sonst wäre der direkte Werkzeugschritt
        blockiert, sobald irgendein Planschritt läuft.
        """
        speicher, lauf = await _lauf(engine)
        await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        await speicher.save(geladen, erwarteter_status=RunStatus.EXECUTING)


class TestEinFremderSchreiberLoeschtDenAnspruchNicht:
    """**Selbst gefunden, beim Abwägen der nächsten Reihenfolge.**

    Der Anspruch lag in ``RunState`` — und ``save()`` schreibt das **ganze**
    ``state``-Dokument aus dem Arbeitsspeicher. Ein Aufrufer, der den Lauf vor
    dem Anspruch geladen hat und ohne Anspruch speichert, überschrieb ihn
    damit. Gemessen: nach einem anspruchslosen ``save()`` war Schritt 1 wieder
    frei, obwohl der Inhaber noch arbeitete.

    Das ist derselbe Race wie zuvor, nur über eine andere Tür:

        A: /advance beansprucht Schritt 1, Modellaufruf läuft Sekunden
        B: /steps führt irgendein Werkzeug aus und speichert → Anspruch weg
        C: /advance beansprucht Schritt 1 erneut → führt aus
        A: kommt zurück → führt ebenfalls aus
        ⇒ zwei Wirkungen aus einem geplanten Schritt

    **Die Lehre ist allgemeiner als der Fehler.** Ein Anspruch, der in einem
    Dokument liegt, das andere im Ganzen schreiben, ist kein Anspruch. Die
    Fencing-Bedingung im ``WHERE`` schützte nur den, der sich auf ihn *berief* —
    wer ihn gar nicht erwähnte, ging daran vorbei.
    """

    @pytest.mark.invariant("plan-step-claim-is-fenced")
    async def test_ein_save_ohne_anspruch_laesst_den_fremden_stehen(
        self, engine: AsyncEngine
    ) -> None:
        speicher, lauf = await _lauf(engine)
        anspruch = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert anspruch is not None

        # Der anspruchslose Pfad (``POST /runs/{id}/steps``) speichert einen
        # Lauf, den er **vor** dem Anspruch geladen hat.
        await speicher.save(lauf, erwarteter_status=RunStatus.EXECUTING)

        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        assert geladen.state.current_step == 1, (
            "Ein Schreiber ohne Anspruch hat den fremden gelöscht — der Race von "
            "vorhin ist damit über eine andere Tür wieder offen."
        )
        assert geladen.state.claim_id == anspruch

    @pytest.mark.invariant("plan-step-claim-is-fenced")
    async def test_der_schritt_bleibt_danach_belegt(self, engine: AsyncEngine) -> None:
        """Die Wirkung, nicht nur das Feld: Ein zweiter Anwärter darf nicht
        zum Zuge kommen."""
        speicher, lauf = await _lauf(engine)
        assert await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        await speicher.save(lauf, erwarteter_status=RunStatus.EXECUTING)
        assert await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING) is None

    async def test_der_inhaber_gibt_beim_speichern_weiterhin_frei(
        self, engine: AsyncEngine
    ) -> None:
        """Die Gegenprobe, und sie ist die wichtigere Hälfte.

        Würde der Anspruch **immer** erhalten, gäbe ihn der Erfolgsweg nicht
        mehr frei — und jeder Lauf bliebe nach seinem ersten Schritt stehen.
        Wer sich ausweist, darf ihn ändern.
        """
        speicher, lauf = await _lauf(engine)
        anspruch = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert anspruch is not None

        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        freigegeben = geladen.model_copy(
            update={
                "state": geladen.state.model_copy(update={"current_step": None, "claim_id": None})
            }
        )
        await speicher.save(freigegeben, erwarteter_status=RunStatus.EXECUTING, claim_id=anspruch)

        danach = await speicher.load(lauf.id)
        assert danach is not None and danach.state.current_step is None
        assert await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
