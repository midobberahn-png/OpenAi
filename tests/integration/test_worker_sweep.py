"""Der Durchgang gegen echte Datenbank — und die Grenze eines Prozesses ohne Mensch.

Bis hierher hatte die Wiederaufnahme genau einen Auslöser: den nächsten
``advance`` auf denselben Lauf. Wer ihn nicht schickte, hatte einen Lauf, der
für immer stand. Hier läuft der Arbeiter, der von sich aus nachsieht.

**Der Nachweis, auf den es ankommt, ist der zweite Test.** Ein Arbeiter, der
hängende Läufe fortsetzt, ist ein Prozess mit Außenwirkung und ohne Menschen.
Er darf deshalb keine Bestätigung erzeugen: Eine Anfrage ist an die Sitzung
gebunden, in der ihre Vorschau erschien, und eine ohne Sitzung könnte niemand
einlösen. Sie stünde in der Übersicht des Nutzers, ließe sich nicht beantworten
und den Lauf endgültig stehen — das Gegenteil dessen, wofür der Arbeiter
gebaut ist.

Das Modell ist hier ein Drehbuch und kein laufendes Ollama: Der Arbeiter
formuliert die Argumente über die Argumentquelle, und ein Test, der dafür einen
4,9-GB-Dienst voraussetzt, liefe in keiner Pipeline. Alles andere ist echt —
Datenbank, Berechtigungen, Policy, Gate, Kalender.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.run_store import PostgresRunStore
from jarvis_api.models import model_catalog
from jarvis_api.settings import Settings, get_settings
from jarvis_api.worker import worker_for
from jarvis_contracts import (
    CompletionRequest,
    CompletionResult,
    ProposedToolCall,
    ProviderCapabilities,
    RunStatus,
)
from jarvis_core.providers import ModelGateway
from tests.integration.test_http_runs import _angemeldet
from tests.integration.test_step_claim import _lauf_mit_terminschritt
from tests.integration.test_wiederaufnahme import _altern_lassen

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

FRIST = timedelta(minutes=15)
TERMIN = {
    "title": "Fokuszeit",
    "start": "2026-09-03T09:00:00+00:00",
    "end": "2026-09-03T10:00:00+00:00",
}


class Drehbuchmodell:
    """Ein Anbieter, der immer denselben Werkzeugvorschlag macht.

    Der Adapter wird ersetzt, **nicht** das Gateway: Katalog, Datenklassenprüfung
    und Kontaminationsregeln laufen echt. Ersetzt ist nur der Dienst am anderen
    Ende der Leitung.
    """

    def __init__(self, argumente: dict[str, Any]) -> None:
        self._argumente = argumente
        self.anfragen: list[CompletionRequest] = []

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(tool_calling=True)

    async def complete(self, request: CompletionRequest) -> CompletionResult:
        self.anfragen.append(request)
        if not request.tools:
            # Der abschließende ``llm``-Schritt bekommt kein Werkzeug angeboten
            # — und schlägt dann auch keines vor.
            return CompletionResult(text="Erledigt.")
        return CompletionResult(
            tool_calls=[
                ProposedToolCall(
                    id="a1", tool_name=request.tools[0]["name"], arguments=self._argumente
                )
            ]
        )

    def stream(self, request: CompletionRequest) -> Any:  # pragma: no cover - ungenutzt
        raise NotImplementedError

    async def count_tokens(self, request: CompletionRequest) -> int:  # pragma: no cover
        return 0


@pytest.fixture
def drehbuch(monkeypatch: pytest.MonkeyPatch) -> Drehbuchmodell:
    modell = Drehbuchmodell(TERMIN)

    def gateway(settings: Settings) -> ModelGateway:
        return ModelGateway({"ollama": modell}, model_catalog(settings))

    monkeypatch.setattr("jarvis_api.worker.model_gateway", gateway)
    return modell


async def _kalenderrecht(engine: AsyncEngine, *, user_id: uuid.UUID, mode: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO scopes (name, description, default_mode, risk_level) "
                "VALUES ('calendar.create', 'Termine anlegen', 'allow', 'medium') "
                "ON CONFLICT (name) DO NOTHING"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO permissions (id, user_id, scope, mode, granted_at) "
                "VALUES (:i, :u, 'calendar.create', :m, now() - interval '1 day')"
            ),
            {"i": uuid.uuid4(), "u": user_id, "m": mode},
        )


async def _haengender_lauf(client: AsyncClient, engine: AsyncEngine) -> str:
    """Ein Lauf, dessen Schritt beansprucht ist und dessen Arbeiter nicht mehr lebt."""
    run_id = await _lauf_mit_terminschritt(client, engine)
    speicher = PostgresRunStore(engine)
    assert await speicher.claim_step(uuid.UUID(run_id), 1, erwarteter_status=RunStatus.QUEUED)
    await _altern_lassen(engine, uuid.UUID(run_id), timedelta(hours=1))
    return run_id


async def _termine(engine: AsyncEngine, user_id: uuid.UUID) -> int:
    async with engine.begin() as conn:
        return int(
            (
                await conn.execute(
                    text("SELECT count(*) FROM calendar_events WHERE user_id = :u"),
                    {"u": user_id},
                )
            ).scalar_one()
        )


async def _offene_bestaetigungen(engine: AsyncEngine, user_id: uuid.UUID) -> int:
    async with engine.begin() as conn:
        return int(
            (
                await conn.execute(
                    text("SELECT count(*) FROM pending_actions WHERE user_id = :u"),
                    {"u": user_id},
                )
            ).scalar_one()
        )


class TestDerArbeiterFindetVonSelbst:
    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    async def test_ein_haengender_lauf_wird_ohne_zutun_fortgesetzt(
        self, client: AsyncClient, engine: AsyncEngine, drehbuch: Drehbuchmodell
    ) -> None:
        """Der Durchstich: Niemand ruft ``advance``, und der Lauf geht trotzdem weiter."""
        user_id = await _angemeldet(client, engine)
        await _kalenderrecht(engine, user_id=user_id, mode="allow")
        run_id = await _haengender_lauf(client, engine)

        bericht = await worker_for(engine, get_settings(), lease=FRIST).sweep()

        gemeldet = [e for e in bericht.ergebnisse if e.run_id == run_id]
        assert gemeldet and gemeldet[0].outcome == "executed", bericht.ergebnisse
        assert await _termine(engine, user_id) == 1
        assert drehbuch.anfragen, "Die Argumente kamen aus der Argumentquelle."


class TestOhneMenschKeineBestaetigung:
    """Die Grenze des Arbeiters, und sie ist der Kern dieses Blocks."""

    @pytest.mark.invariant("unattended-step-has-no-approval-channel")
    async def test_ein_bestaetigungspflichtiger_schritt_wird_nicht_ausgefuehrt(
        self, client: AsyncClient, engine: AsyncEngine, drehbuch: Drehbuchmodell
    ) -> None:
        user_id = await _angemeldet(client, engine)
        await _kalenderrecht(engine, user_id=user_id, mode="confirm")
        run_id = await _haengender_lauf(client, engine)

        bericht = await worker_for(engine, get_settings(), lease=FRIST).sweep()

        gemeldet = [e for e in bericht.ergebnisse if e.run_id == run_id]
        assert gemeldet and gemeldet[0].outcome == "blocked", bericht.ergebnisse
        assert await _termine(engine, user_id) == 0

    @pytest.mark.invariant("unattended-step-has-no-approval-channel")
    async def test_und_er_hinterlaesst_keine_bestaetigung_die_niemand_einloesen_kann(
        self, client: AsyncClient, engine: AsyncEngine, drehbuch: Drehbuchmodell
    ) -> None:
        """Die wichtigere Hälfte.

        Eine Anfrage ohne Sitzung stünde in der Übersicht des Nutzers, ließe
        sich nicht beantworten und den Lauf endgültig stehen — der Arbeiter
        hätte dann genau das angerichtet, wogegen er gebaut ist.
        """
        user_id = await _angemeldet(client, engine)
        await _kalenderrecht(engine, user_id=user_id, mode="confirm")
        await _haengender_lauf(client, engine)

        await worker_for(engine, get_settings(), lease=FRIST).sweep()

        assert await _offene_bestaetigungen(engine, user_id) == 0

    async def test_der_schritt_bleibt_fuer_den_nutzer_wiederholbar(
        self, client: AsyncClient, engine: AsyncEngine, drehbuch: Drehbuchmodell
    ) -> None:
        """Was der Arbeiter nicht kann, kann der Nutzer weiterhin.

        Der Protokolleintrag steht auf ``blocked`` — laut Vertrag wiederholbar
        —, der Anspruch ist freigegeben, und derselbe Schritt läuft angemeldet
        bis zur Bestätigung.
        """
        user_id = await _angemeldet(client, engine)
        await _kalenderrecht(engine, user_id=user_id, mode="confirm")
        run_id = await _haengender_lauf(client, engine)
        await worker_for(engine, get_settings(), lease=FRIST).sweep()

        antwort = await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})

        assert antwort.status_code == 200, antwort.text
        assert antwort.json()["status"] == "awaiting_confirmation", antwort.json()
        assert await _offene_bestaetigungen(engine, user_id) == 1


class TestWenSuchtDerArbeiterUeberhaupt:
    async def test_ein_frisch_beanspruchter_lauf_ist_nicht_dabei(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Sonst nähme der Arbeiter Schritte auf, an denen gearbeitet wird."""
        user_id = await _angemeldet(client, engine)
        await _kalenderrecht(engine, user_id=user_id, mode="allow")
        run_id = await _lauf_mit_terminschritt(client, engine)
        speicher = PostgresRunStore(engine)
        assert await speicher.claim_step(uuid.UUID(run_id), 1, erwarteter_status=RunStatus.QUEUED)

        gefunden = await speicher.stale_runs(frist=FRIST, idle=FRIST, limit=20)

        assert uuid.UUID(run_id) not in {lauf.id for lauf in gefunden}

    async def test_ein_lauf_ohne_anspruch_ist_nicht_dabei(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Ein Lauf, den niemand begonnen hat, ist keine Wiederaufnahme.

        Ihn von sich aus anzustoßen wäre etwas anderes: Das System handelte
        dann bei einem Lauf, den der Nutzer vielleicht liegen gelassen hat.
        """
        user_id = await _angemeldet(client, engine)
        await _kalenderrecht(engine, user_id=user_id, mode="allow")
        run_id = await _lauf_mit_terminschritt(client, engine)

        gefunden = await PostgresRunStore(engine).stale_runs(
            frist=timedelta(0), idle=timedelta(0), limit=20
        )

        assert uuid.UUID(run_id) not in {lauf.id for lauf in gefunden}

    async def test_ein_lauf_in_menschenhand_ist_nicht_mehr_dabei(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """**Ein Vorgang, über den ein Mensch entscheidet, gehört keinem Arbeiter.**

        Ohne diese Bedingung greift ihn jeder Durchgang nach Ablauf der Frist
        erneut auf: Er urteilt wieder ``ENTSCHEIDUNG NÖTIG``, vergibt ein
        **neues** Fencing-Token und meldet erneut ``step-unresolved``. Zwei
        Folgen, und die zweite ist die ärgerlichere — die Seite, auf der jemand
        gerade die Entscheidung liest, hält danach ein veraltetes Token und
        wird abgewiesen.

        Verloren geht dabei nichts: Der Arbeiter kann diesen Zustand ohnehin
        nicht auflösen. Genau deshalb gibt es ihn.
        """
        user_id = await _angemeldet(client, engine)
        await _kalenderrecht(engine, user_id=user_id, mode="allow")
        run_id = await _lauf_mit_terminschritt(client, engine)
        speicher = PostgresRunStore(engine)
        anspruch = await speicher.claim_step(
            uuid.UUID(run_id), 1, erwarteter_status=RunStatus.QUEUED
        )
        assert anspruch is not None
        assert await speicher.mark_unresolved(uuid.UUID(run_id), 1, anspruch)

        gefunden = await speicher.stale_runs(frist=timedelta(0), idle=timedelta(0), limit=20)

        assert uuid.UUID(run_id) not in {lauf.id for lauf in gefunden}


class TestEinLiegengebliebenerLauf:
    """**Der Befund, und er ist die Kehrseite einer richtigen Entscheidung.**

    Der Arbeiter sucht bislang ausschließlich Läufe mit einem **überfälligen
    Anspruch** — jemand hat begonnen und ist abgestürzt. Das war richtig
    gedacht: Ein Lauf *ohne* Anspruch ist keine Wiederaufnahme, und einen
    `queued`-Lauf von sich aus anzustoßen hieße, bei etwas zu handeln, das der
    Nutzer vielleicht liegen gelassen hat.

    Die Kehrseite fiel erst mit dem Chat auf: Ein Lauf **mitten im Plan** hat
    keinen Anspruch — er wird nach jedem Schritt freigegeben. Wer den Browser
    schließt, während Schritt zwei von vier fällig ist, hinterlässt einen Lauf,
    den niemand je aufgreift. Kein Anspruch, also kein Fund; kein Zuschauer,
    also kein `advance`.

    Und *dieser* Lauf ist etwas anderes als ein liegengelassener: Es sind
    Schritte gelaufen. Der Nutzer hat nicht nur gefragt, das System hat schon
    gehandelt — und mittendrin aufzuhören ist der eine Zustand, den niemand
    gewollt hat.
    """

    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    async def test_ein_lauf_mitten_im_plan_wird_aufgegriffen(
        self, client: AsyncClient, engine: AsyncEngine, drehbuch: Drehbuchmodell
    ) -> None:
        user_id = await _angemeldet(client, engine)
        await _kalenderrecht(engine, user_id=user_id, mode="allow")
        run_id = await _lauf_mit_terminschritt(client, engine)

        # Ein Schritt läuft — danach ist der Anspruch frei und der Lauf steht
        # mitten im Plan. Genau so sieht ein geschlossener Browser aus.
        erster = await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})
        assert erster.json()["status"] == "executed", erster.json()
        async with engine.begin() as conn:
            zustand = (
                await conn.execute(
                    text("SELECT status, state FROM runs WHERE id = :r"), {"r": uuid.UUID(run_id)}
                )
            ).one()
        assert zustand.status == "executing"
        assert zustand.state.get("claim_id") is None, "Kein Anspruch — und das ist der Punkt."

        # ``idle=0``: Gemessen wird das Aufgreifen, nicht das Warten. Dass die
        # Frist trennt, prüft der Test darunter.
        bericht = await worker_for(engine, get_settings(), lease=FRIST, idle=timedelta(0)).sweep()

        gemeldet = [e for e in bericht.ergebnisse if e.run_id == run_id]
        assert gemeldet, (
            "Der Arbeiter hat einen Lauf mitten im Plan nicht aufgegriffen. "
            f"Gefunden: {bericht.ergebnisse}"
        )

    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    async def test_ein_lauf_der_gerade_getrieben_wird_bleibt_unberuehrt(
        self, client: AsyncClient, engine: AsyncEngine, drehbuch: Drehbuchmodell
    ) -> None:
        """**Die Gegenprobe, und sie ist die wichtigere.**

        Die Oberfläche treibt einen Plan in Sekunden. Griffe der Arbeiter
        sofort mit zu, führten zwei Treiber denselben Lauf — der Anspruch
        verhinderte zwar zwei gleichzeitige Schritte, aber nicht, dass der
        Arbeiter dem Nutzer die Schritte wegnimmt, während er zusieht.

        Die Frist ist das, was „wird getrieben" von „liegt" trennt.
        """
        user_id = await _angemeldet(client, engine)
        await _kalenderrecht(engine, user_id=user_id, mode="allow")
        run_id = await _lauf_mit_terminschritt(client, engine)
        await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})

        bericht = await worker_for(engine, get_settings(), lease=FRIST).sweep()

        assert [e for e in bericht.ergebnisse if e.run_id == run_id] == [], (
            "Der Arbeiter hat einem Lauf zugegriffen, der gerade getrieben wird."
        )
