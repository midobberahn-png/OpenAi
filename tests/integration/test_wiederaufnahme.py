"""Die Frist auf dem Anspruch — gemessen an der Uhr, die sie setzt.

Der Anspruch verhindert den doppelten Seiteneffekt, und er hat einen Preis:
Stürzt der Arbeiter zwischen Anspruch und Ausführung ab, bleibt der Schritt
belegt und der Lauf steht. Bisher endete der Weg dort — ``409``, und zwar für
immer.

Die Frist ist der Ausgang, und sie ist **keine** Zeitüberschreitung. Der
Unterschied entscheidet über den doppelten Termin: Die Übernahme sperrt den
alten Arbeiter vom *Schreiben* aus, sie hält ihn nicht davon ab, zu *wirken*.
Wer sie zu knapp wählt, übernimmt Schritte, die noch laufen. Sie ist deshalb
eine Obergrenze für die Dauer eines Schrittes.

**Warum das hier steht und nicht in einem Unit-Test.** Gemessen wird eine
Bedingung in einer ``WHERE``-Klausel gegen ``now()`` der Datenbank. Ein Nachbau
in Python läse eine andere Uhr — und damit nicht die, die in Betrieb
entscheidet. Zwei Arbeiter auf zwei Rechnern sind kein Sonderfall, sondern der
Grund, warum die Zeit überhaupt aus der Datenbank kommt.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.run_store import PostgresRunStore
from jarvis_contracts import Run, RunStatus, RunTrigger
from jarvis_core.orchestrator import utc_now
from jarvis_core.ports.runs import RunStateConflict
from tests.integration.test_http_runs import _angemeldet, _mit_kalenderrecht
from tests.integration.test_step_claim import _lauf_mit_terminschritt

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

FRIST = timedelta(minutes=15)
TERMIN = {
    "title": "Fokuszeit",
    "start": "2026-09-02T09:00:00+00:00",
    "end": "2026-09-02T10:00:00+00:00",
}


async def _termine(engine: AsyncEngine, user_id: uuid.UUID) -> int:
    """Gezählt wird die **Wirkung**, nicht die Antwort des Endpunkts.

    Was er zurückgibt, könnte höflich sein und trotzdem doppelt gewirkt haben.
    """
    async with engine.begin() as conn:
        return int(
            (
                await conn.execute(
                    text("SELECT count(*) FROM calendar_events WHERE user_id = :u"),
                    {"u": user_id},
                )
            ).scalar_one()
        )


async def _lauf(engine: AsyncEngine) -> tuple[PostgresRunStore, Run]:
    nutzer = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Frist')"),
            {"i": nutzer, "m": f"frist-{nutzer}@example.test"},
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


async def _altern_lassen(engine: AsyncEngine, run_id: uuid.UUID, um: timedelta) -> None:
    """Setzt ``claimed_at`` zurück — ein Absturz vor einer Stunde, ohne zu warten.

    Die Zeit wird **in der Datenbank** gerechnet (``now() - interval``) und
    nicht in Python: Sonst prüfte der Test eine Behauptung über die lokale Uhr,
    während die Bedingung eine über die der Datenbank ist.
    """
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE runs SET state = state || jsonb_build_object("
                "  'claimed_at', to_jsonb(now() - CAST(:um AS interval))"
                ") WHERE id = :id"
            ),
            {"id": run_id, "um": um},
        )


@pytest.fixture(autouse=True)
async def _aufraeumen(engine: AsyncEngine):
    yield
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users WHERE email LIKE 'frist-%'"))


class TestDerAnspruchTraegtEineFrist:
    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    async def test_die_zeit_kommt_aus_der_datenbank(self, engine: AsyncEngine) -> None:
        """Nicht aus dem Arbeitsspeicher des Anspruchstellers.

        Wer die Frist misst, muss dieselbe Uhr lesen wie der, der sie gesetzt
        hat. Eine um Minuten falsch gehende Uhr gäbe sonst entweder einen
        laufenden Schritt frei oder ließe einen hängenden liegen.
        """
        speicher, lauf = await _lauf(engine)
        vorher = utc_now()

        await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)

        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        assert geladen.state.claimed_at is not None
        assert abs((geladen.state.claimed_at - vorher).total_seconds()) < 60

    async def test_ein_erledigter_schritt_laesst_keine_frist_zurueck(
        self, engine: AsyncEngine
    ) -> None:
        """``with_step_done`` gibt alle drei Felder gemeinsam frei.

        Eine Frist, die einen abgeschlossenen Schritt überlebt, wäre eine
        Einladung an die Wiederaufnahme, ihn erneut zu vergeben.
        """
        speicher, lauf = await _lauf(engine)
        kennung = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert kennung is not None

        await speicher.release_step(lauf.id, kennung)

        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        assert geladen.state.claimed_at is None


class TestUebernahme:
    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    async def test_solange_die_frist_laeuft_uebernimmt_niemand(self, engine: AsyncEngine) -> None:
        """Der wichtigste Test dieser Datei.

        Ein Arbeiter, der vor einer Sekunde abgestürzt ist, ist von einem, der
        gerade rechnet, nicht zu unterscheiden. Die Vermutung zugunsten des
        Laufenden ist die einzige, die keinen zweiten Termin anlegt.
        """
        speicher, lauf = await _lauf(engine)
        echt = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)

        uebernommen = await speicher.reclaim_step(
            lauf.id, 1, erwarteter_status=RunStatus.EXECUTING, frist=FRIST
        )

        assert uebernommen is None
        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        assert geladen.state.claim_id == echt, "Der laufende Arbeiter behält seinen Anspruch."

    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    async def test_nach_ablauf_wird_uebernommen(self, engine: AsyncEngine) -> None:
        speicher, lauf = await _lauf(engine)
        alt = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        await _altern_lassen(engine, lauf.id, timedelta(hours=1))

        neu = await speicher.reclaim_step(
            lauf.id, 1, erwarteter_status=RunStatus.EXECUTING, frist=FRIST
        )

        assert neu is not None and neu != alt
        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        assert geladen.state.current_step == 1, (
            "Der Schritt bleibt belegt — nur von wem, ändert sich."
        )
        assert geladen.state.claim_id == neu

    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    async def test_die_uebernahme_setzt_die_frist_neu(self, engine: AsyncEngine) -> None:
        """Sonst wäre der Übernehmer im selben Augenblick selbst überfällig —
        und der nächste Anwärter nähme ihm den Schritt sofort wieder ab."""
        speicher, lauf = await _lauf(engine)
        await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        await _altern_lassen(engine, lauf.id, timedelta(hours=1))
        assert await speicher.reclaim_step(
            lauf.id, 1, erwarteter_status=RunStatus.EXECUTING, frist=FRIST
        )

        nochmal = await speicher.reclaim_step(
            lauf.id, 1, erwarteter_status=RunStatus.EXECUTING, frist=FRIST
        )

        assert nochmal is None

    async def test_ein_anspruch_ohne_frist_wird_nicht_uebernommen(
        self, engine: AsyncEngine
    ) -> None:
        """Altbestand aus der Zeit vor dem Feld.

        „Keine Angabe" als „lange her" zu lesen hieße, mitten in einem Rollout
        den Schritt eines gerade arbeitenden Prozesses zu übernehmen. Der
        Vergleich gegen ``NULL`` ist nicht wahr, und das ist der sichere
        Ausgang — nicht ein Versehen.
        """
        speicher, lauf = await _lauf(engine)
        await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        async with engine.begin() as conn:
            await conn.execute(
                text("UPDATE runs SET state = state - 'claimed_at' WHERE id = :id"),
                {"id": lauf.id},
            )

        uebernommen = await speicher.reclaim_step(
            lauf.id, 1, erwarteter_status=RunStatus.EXECUTING, frist=timedelta(0)
        )

        assert uebernommen is None

    async def test_ein_freier_schritt_wird_nicht_uebernommen(self, engine: AsyncEngine) -> None:
        """``reclaim_step`` ist kein Ersatz für ``claim_step``.

        Beides in einer Anweisung zusammenzufassen — „frei **oder**
        abgelaufen" — gäbe jedem Anspruchsteller stillschweigend das Recht zur
        Übernahme. Sie soll eine benannte Entscheidung bleiben.
        """
        speicher, lauf = await _lauf(engine)

        uebernommen = await speicher.reclaim_step(
            lauf.id, 1, erwarteter_status=RunStatus.EXECUTING, frist=timedelta(0)
        )

        assert uebernommen is None

    async def test_ein_anderer_schritt_wird_nicht_uebernommen(self, engine: AsyncEngine) -> None:
        """Übernommen wird ein *bestimmter* Schritt.

        Steht der Lauf inzwischen bei einem anderen, beruht die Übernahme auf
        einer veralteten Beurteilung — und der Übernehmer führte einen Schritt
        aus, für den er keinen Anspruch hat.
        """
        speicher, lauf = await _lauf(engine)
        await speicher.claim_step(lauf.id, 2, erwarteter_status=RunStatus.EXECUTING)
        await _altern_lassen(engine, lauf.id, timedelta(hours=1))

        uebernommen = await speicher.reclaim_step(
            lauf.id, 1, erwarteter_status=RunStatus.EXECUTING, frist=FRIST
        )

        assert uebernommen is None


class TestDerAlteArbeiterIstAusgesperrt:
    """Wozu die Übernahme überhaupt ein neues Token vergibt."""

    @pytest.mark.invariant("plan-step-claim-is-fenced")
    async def test_er_gibt_den_uebernommenen_anspruch_nicht_frei(self, engine: AsyncEngine) -> None:
        speicher, lauf = await _lauf(engine)
        alt = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert alt is not None
        await _altern_lassen(engine, lauf.id, timedelta(hours=1))
        neu = await speicher.reclaim_step(
            lauf.id, 1, erwarteter_status=RunStatus.EXECUTING, frist=FRIST
        )

        await speicher.release_step(lauf.id, alt)

        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        assert geladen.state.claim_id == neu, "Der alte Arbeiter hat den fremden Anspruch gelöst."

    @pytest.mark.invariant("plan-step-claim-is-fenced")
    async def test_er_schreibt_sein_ergebnis_nicht_mehr(self, engine: AsyncEngine) -> None:
        """Die schlimmere Hälfte: Nicht die Freigabe, das **Ergebnis**.

        Beide Arbeiter sehen ``executing``; ein Statusvergleich unterscheidet
        sie nicht.
        """
        speicher, lauf = await _lauf(engine)
        alt = await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        assert alt is not None
        await _altern_lassen(engine, lauf.id, timedelta(hours=1))
        await speicher.reclaim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING, frist=FRIST)

        with pytest.raises(RunStateConflict):
            await speicher.save(
                lauf.model_copy(update={"status": RunStatus.COMPLETED}),
                erwarteter_status=RunStatus.EXECUTING,
                claim_id=alt,
            )

    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    async def test_zwei_uebernehmer_und_genau_einer_gewinnt(self, engine: AsyncEngine) -> None:
        """Dieselbe Zusage wie beim Anspruch selbst — die Übernahme erbt sie
        nicht, sie muss sie eigenständig tragen."""
        speicher, lauf = await _lauf(engine)
        await speicher.claim_step(lauf.id, 1, erwarteter_status=RunStatus.EXECUTING)
        await _altern_lassen(engine, lauf.id, timedelta(hours=1))

        ergebnisse = await asyncio.gather(
            *[
                speicher.reclaim_step(
                    lauf.id, 1, erwarteter_status=RunStatus.EXECUTING, frist=FRIST
                )
                for _ in range(6)
            ]
        )

        gewonnen = [e for e in ergebnisse if e is not None]
        assert len(gewonnen) == 1, f"{len(gewonnen)} Übernehmer statt einem: {gewonnen}"
        geladen = await speicher.load(lauf.id)
        assert geladen is not None
        assert geladen.state.claim_id == gewonnen[0]


class TestUeberHttp:
    """Der Durchstich: Ein hängengebliebener Lauf läuft wieder an.

    Bis hierher war die Frist eine Aussage über eine ``WHERE``-Klausel. Hier
    steht die Wirkung, die sie haben soll — und sie ist die eigentliche
    Verbesserung für den Nutzer: Vor diesem Block war ein Lauf, dessen Arbeiter
    abgestürzt ist, **dauerhaft** blockiert. Jede weitere Anfrage bekam 409,
    und es gab keinen Weg zurück.
    """

    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    async def test_ein_haengender_lauf_wird_uebernommen_und_ausgefuehrt(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)

        # Ein Arbeiter beansprucht den Schritt — und stürzt ab, bevor er wirkt.
        # Nachgestellt und nicht simuliert: Der Anspruch steht danach genauso in
        # der Datenbank wie nach einem echten Absturz, und das Werkzeugprotokoll
        # ist leer, weil der Handler nie in Sicht war.
        speicher = PostgresRunStore(engine)
        # ``queued``: Ein frisch geplanter Lauf hat noch nicht angefangen. Den
        # Übergang nach ``executing`` vollzieht erst der Schritt selbst — und
        # genau deshalb ist auch die Übernahme auf diesen Status bedingt.
        haengend = await speicher.claim_step(
            uuid.UUID(run_id), 1, erwarteter_status=RunStatus.QUEUED
        )
        assert haengend is not None

        blockiert = await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})
        assert blockiert.status_code == 409, blockiert.text
        assert await _termine(engine, user_id) == 0

        await _altern_lassen(engine, uuid.UUID(run_id), timedelta(hours=1))

        wieder = await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})

        assert wieder.status_code == 200, wieder.text
        assert wieder.json()["status"] == "executed", wieder.json()
        assert await _termine(engine, user_id) == 1, (
            "Genau einer — die Übernahme darf keinen zweiten Termin erzeugen."
        )

    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    async def test_ein_schritt_mit_moeglicher_wirkung_wird_nicht_uebernommen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Gegenprobe, und sie ist die wichtigere.

        Derselbe hängende Lauf, aber das Werkzeugprotokoll führt einen Aufruf,
        der den Handler betreten hat. Was daraus wurde, weiß niemand — und
        deshalb wiederholt ihn auch niemand. Die Ablehnung trägt eine eigene
        Kennung: Ein Aufrufer, der ``409`` mit dieser Begründung sieht, weiß,
        dass Wiederholen hier nicht die Lösung ist.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)

        speicher = PostgresRunStore(engine)
        assert await speicher.claim_step(uuid.UUID(run_id), 1, erwarteter_status=RunStatus.QUEUED)
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO tool_invocations (id, run_id, step_seq, tool_name, arguments, "
                    "risk_level, policy_decision, decision_reason, status, created_at) VALUES "
                    "(:i, :r, 1, 'calendar.create', CAST(:a AS jsonb), 'medium', 'allow', "
                    "'Test', 'effect_unknown', now())"
                ),
                {"i": uuid.uuid4(), "r": uuid.UUID(run_id), "a": json.dumps(TERMIN)},
            )
        await _altern_lassen(engine, uuid.UUID(run_id), timedelta(hours=1))

        antwort = await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})

        assert antwort.status_code == 409, antwort.text
        assert "möglicherweise gewirkt" in antwort.json()["detail"], antwort.json()
        assert await _termine(engine, user_id) == 0, "Kein zweiter Termin aus einem unklaren."
