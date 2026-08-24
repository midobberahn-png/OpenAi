"""Der Ereignisstrom — und vor allem seine Grenze.

Ein Strom ist eine dauerhafte Leitung. Was einmal falsch verbunden ist, bleibt
es, und niemand bemerkt es: Eine Oberfläche, die fremde Ereignisse bekommt,
sieht aus wie eine, die funktioniert. Deshalb prüft diese Suite zuerst die
Trennung und erst danach, dass überhaupt etwas ankommt.

**Was der Strom ausdrücklich nicht trägt**, ist der zweite Gegenstand: keine
Nonce, keine Argumente, kein Werkzeugergebnis. Er sagt, *dass* sich etwas
geändert hat; was gilt, holt die Oberfläche über die API (ADR-016). Ein Strom,
der Inhalte trägt, wäre eine zweite Stelle, an der Fremdinhalt die Oberfläche
erreicht — an den Prüfungen vorbei, die es dafür gibt.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import AsyncClient
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.events import RedisEventBus
from jarvis_contracts import ActionWaiting, RunStarted
from tests.integration.test_http_runs import _angemeldet

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]


@pytest_asyncio.fixture
async def redis() -> AsyncIterator[Redis]:
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    client = Redis.from_url(url, decode_responses=True)
    try:
        await client.ping()
    except Exception as exc:  # pragma: no cover - Umgebungsproblem
        await client.aclose()
        from tests.integration.conftest import _fehlt

        _fehlt("Redis", exc)
    yield client
    await client.aclose()


async def _empfangen(bus: RedisEventBus, user_id: uuid.UUID, *, anzahl: int) -> list[dict]:
    """Lauscht, bis ``anzahl`` Nachrichten da sind — oder die Geduld endet.

    Mit Frist, weil ein Test, der auf ein Ereignis wartet, das nie kommt, sonst
    den ganzen Lauf anhält. Fünf Sekunden sind reichlich für Redis auf
    demselben Rechner; wer länger wartet, wartet auf einen Fehler.
    """
    empfangen: list[dict] = []

    async def lauschen() -> None:
        async for zeile in bus.subscribe(user_id):
            if zeile == "":
                continue
            empfangen.append(json.loads(zeile))
            if len(empfangen) >= anzahl:
                return

    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(lauschen(), timeout=5.0)
    return empfangen


class TestDieGrenzeDesStroms:
    @pytest.mark.invariant("event-stream-is-scoped-and-contentless")
    async def test_ein_fremdes_ereignis_erreicht_niemanden(self, redis: Redis) -> None:
        """**Der wichtigste Test dieser Datei.**

        Der Kanal trägt die Kennung des Nutzers, und sie stammt aus der
        Sitzung. Ohne diese Trennung sähe jedes angemeldete Gerät die Vorgänge
        aller — und weil ein Strom nur zeigt und nichts fordert, fiele es
        niemandem auf.
        """
        bus = RedisEventBus(redis)
        ich, fremder = uuid.uuid4(), uuid.uuid4()

        async def lauschen() -> list[str]:
            gesehen: list[str] = []
            async for zeile in bus.subscribe(ich):
                if zeile != "":
                    gesehen.append(zeile)
                    break
            return gesehen

        aufgabe = asyncio.create_task(lauschen())
        await asyncio.sleep(0.2)
        await bus.publish(fremder, {"t": "run.started", "run_id": str(uuid.uuid4())})
        await asyncio.sleep(0.5)

        assert not aufgabe.done(), "Ein fremdes Ereignis ist im eigenen Strom aufgetaucht."
        aufgabe.cancel()

    @pytest.mark.invariant("event-stream-is-scoped-and-contentless")
    async def test_ohne_anmeldung_kein_strom(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        antwort = await client.get("/events")

        assert antwort.status_code == 401, antwort.text


class TestWasAnkommt:
    async def test_ein_hinweis_kommt_an_und_traegt_eine_nummer(self, redis: Redis) -> None:
        """Die Nummer stammt aus Redis und nicht aus dem Prozess.

        Zwei Prozesse mit eigenen Zählern ergäben zwei Nummernkreise, und die
        Lückenerkennung im Browser meldete Lücken, die keine sind.
        """
        bus = RedisEventBus(redis)
        ich = uuid.uuid4()
        aufgabe = asyncio.create_task(_empfangen(bus, ich, anzahl=2))
        await asyncio.sleep(0.2)

        await bus.publish(ich, {"t": "run.started", "run_id": str(uuid.uuid4())})
        await bus.publish(ich, {"t": "run.started", "run_id": str(uuid.uuid4())})
        empfangen = await aufgabe

        assert len(empfangen) == 2
        assert empfangen[1]["seq"] == empfangen[0]["seq"] + 1, empfangen

    @pytest.mark.invariant("event-stream-is-scoped-and-contentless")
    async def test_der_strom_traegt_keine_nonce(self, redis: Redis) -> None:
        """``ActionWaiting`` statt ``ActionPending`` — und das ist der Grund.

        Eine Bestätigung ist an **eine Sitzung** gebunden; der Strom geht an
        den **Nutzer**, also an jedes seiner Geräte. Die vollständige
        ``PendingAction`` darüber zu schicken hieße, das Geheimnis genau an die
        Sitzungen zu verteilen, denen es nicht gehört.
        """
        nachricht = ActionWaiting(seq=1, run_id=uuid.uuid4(), action_id=uuid.uuid4())

        felder = nachricht.model_dump(mode="json")

        assert "nonce" not in json.dumps(felder)
        assert set(felder) == {"seq", "t", "run_id", "action_id"}, felder


class TestUeberHttp:
    async def test_ein_neuer_lauf_erzeugt_einen_hinweis(
        self, client: AsyncClient, engine: AsyncEngine, redis: Redis
    ) -> None:
        """Der Durchstich: Was über HTTP geschieht, kommt im Strom an.

        Gelauscht wird am Verteiler und nicht am Endpunkt — die Leitung selbst
        prüft der Browsertest. Hier geht es darum, dass die Route überhaupt
        etwas sendet, und zwar an den richtigen Kanal.
        """
        user_id = await _angemeldet(client, engine)
        bus = RedisEventBus(redis)
        aufgabe = asyncio.create_task(_empfangen(bus, user_id, anzahl=1))
        await asyncio.sleep(0.2)

        await client.post("/runs", json={"input": "Wie spät ist es?"})
        empfangen = await aufgabe

        assert empfangen, "Der angelegte Lauf hat keinen Hinweis erzeugt."
        assert empfangen[0]["t"] == RunStarted.model_fields["t"].default
        assert "run_id" in empfangen[0]


class TestTokenFliessen:
    """Der Text erscheint, während er entsteht — nicht, wenn er fertig ist.

    **Das ist der ganze Unterschied zum vorigen Stand.** Die Antwort kam
    bisher am Stück, nachdem der Schritt gelaufen war; für eine Oberfläche
    heißt das: eine Sekunde Stille, dann ein Absatz. Der Strom macht daraus
    einen fließenden Text — und derselbe Kanal trägt ihn, der ohnehin offen
    ist.

    Was sich dabei **nicht** ändert, ist die Prüfung: Der Strom geht durch
    dasselbe Gate wie ein einzelner Aufruf, und die Zulassung fällt vor dem
    ersten Stück.
    """

    @pytest.mark.invariant("event-stream-is-scoped-and-contentless")
    async def test_die_stuecke_kommen_einzeln_und_ergeben_den_text(
        self, client: AsyncClient, engine: AsyncEngine, redis: Redis, monkeypatch
    ) -> None:
        from jarvis_api.models import model_catalog
        from jarvis_contracts import CompletionResult, ModelUsage
        from jarvis_core.providers import ModelGateway
        from tests.integration.test_http_runs import _Drehbuchanbieter

        modell = _Drehbuchanbieter(
            CompletionResult(text="Es ist zwölf Uhr mittags.", usage=ModelUsage())
        )
        monkeypatch.setattr(
            "jarvis_api.deps.model_gateway",
            lambda settings: ModelGateway({"ollama": modell}, model_catalog(settings)),
        )

        user_id = await _angemeldet(client, engine)
        bus = RedisEventBus(redis)
        lauscher = asyncio.create_task(_empfangen(bus, user_id, anzahl=8))
        await asyncio.sleep(0.2)

        lauf = await client.post("/runs", json={"input": "Wie spät ist es?"})
        antwort = await client.post(f"/runs/{lauf.json()['id']}/advance", json={})
        assert antwort.status_code == 200, antwort.text

        empfangen = await lauscher
        stuecke = [n for n in empfangen if n["t"] == "token.delta"]
        assert stuecke, f"Kein einziges Stück im Strom: {[n['t'] for n in empfangen]}"
        assert len(stuecke) > 1, "Ein Stück ist kein Strom."
        assert "".join(s["text"] for s in stuecke).strip() == "Es ist zwölf Uhr mittags."

        # Und der vollständige Text steht im Lauf — die Stücke sind Anzeige,
        # kein Zustand.
        sicht = await client.get(f"/runs/{lauf.json()['id']}")
        assert sicht.json()["output"] == "Es ist zwölf Uhr mittags."
