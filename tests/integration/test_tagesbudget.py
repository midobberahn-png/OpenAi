"""Das Tagesbudget — gezählt über die Läufe, wirksam in der Modellwahl.

Drei Fragen, und alle drei brauchen die echte Datenbank:

* Zählt der Zähler, was tatsächlich ausgegeben wurde — und nur beim richtigen
  Nutzer?
* Sagt der Endpunkt einem Menschen, woran er ist, **bevor** sich etwas ändert?
* Und wirkt die Grenze da, wo sie wirken soll: in der Modellwahl eines neuen
  Laufs?

Die dritte ist die eigentliche. Ein Budget, das man abfragen kann und das
nichts bewirkt, ist eine Statistik.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.settings import get_settings
from tests.integration.test_http_runs import _angemeldet

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]


async def _lauf_mit_kosten(
    engine: AsyncEngine,
    *,
    user_id: uuid.UUID,
    kosten: str,
    gestartet: datetime | None = None,
) -> uuid.UUID:
    """Ein abgeschlossener Lauf mit gebuchten Kosten.

    Direkt in die Datenbank: Kosten entstehen an einem Modellaufruf, und der
    braucht ein Modell. Nachgestellt wird deshalb das **Ergebnis** — der
    Verbrauch, wie ihn der Tracker hinterlässt —, nicht der Weg dorthin. Was
    hier geprüft wird, ist die Summe darüber.
    """
    run_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO runs (id, user_id, trigger, status, budget, usage, trace_id, "
                "started_at) VALUES (:i, :u, 'user', 'completed', CAST(:b AS jsonb), "
                "CAST(:v AS jsonb), :t, :s)"
            ),
            {
                "i": run_id,
                "u": user_id,
                "b": "{}",
                "v": f'{{"cost_eur": "{kosten}", "tokens_in": 10, "tokens_out": 5}}',
                "t": f"trace-{run_id}",
                "s": gestartet or datetime.now(UTC),
            },
        )
    return run_id


class TestDerZaehler:
    async def test_er_summiert_die_eigenen_laeufe(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        nutzer = await _angemeldet(client, engine)
        await _lauf_mit_kosten(engine, user_id=nutzer, kosten="0.12")
        await _lauf_mit_kosten(engine, user_id=nutzer, kosten="0.30")

        antwort = await client.get("/budget")
        assert antwort.status_code == 200, antwort.text
        assert Decimal(antwort.json()["spent_eur"]) == Decimal("0.42")

    async def test_fremde_laeufe_zaehlen_nicht(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Und zwar nicht, weil es verboten wäre, sondern weil die
        Zugehörigkeit in der Abfrage steht.

        Ein Zähler, der fremde Kosten mitrechnete, wäre zugleich eine Auskunft
        darüber, wie viel jemand anderes arbeitet.
        """
        nutzer = await _angemeldet(client, engine)
        fremder = uuid.uuid4()
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Fremd')"),
                {"i": fremder, "m": f"runtest-{fremder}@example.test"},
            )
        await _lauf_mit_kosten(engine, user_id=fremder, kosten="4.00")
        await _lauf_mit_kosten(engine, user_id=nutzer, kosten="0.10")

        antwort = await client.get("/budget")
        assert Decimal(antwort.json()["spent_eur"]) == Decimal("0.10")

    async def test_gestern_zaehlt_nicht_mehr(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Sonst wäre es kein Tagesbudget, sondern ein Gesamtbudget."""
        nutzer = await _angemeldet(client, engine)
        await _lauf_mit_kosten(
            engine,
            user_id=nutzer,
            kosten="9.99",
            gestartet=datetime.now(UTC) - timedelta(days=2),
        )

        antwort = await client.get("/budget")
        assert Decimal(antwort.json()["spent_eur"]) == Decimal("0")


class TestWasDerEndpunktSagt:
    async def test_er_nennt_den_tagesbeginn(self, client: AsyncClient, engine: AsyncEngine) -> None:
        """„Heute" ohne Zeitzone ist keine Auskunft, sondern eine Vermutung."""
        await _angemeldet(client, engine)

        antwort = await client.get("/budget")
        assert antwort.json()["since"] is not None
        assert Decimal(antwort.json()["limit_eur"]) == get_settings().daily_budget_eur

    async def test_die_warnung_kommt_vor_der_wirkung(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Ab 80 %, und die Schwelle steht im Dokument.

        Der Punkt ist die Reihenfolge: Wer erst bei 100 % erfährt, dass es ein
        Budget gibt, erfährt es an einer veränderten Antwort — und sucht den
        Fehler dort, wo keiner ist.
        """
        nutzer = await _angemeldet(client, engine)
        grenze = get_settings().daily_budget_eur
        await _lauf_mit_kosten(engine, user_id=nutzer, kosten=str(grenze * Decimal("0.85")))

        stand = (await client.get("/budget")).json()
        assert stand["warning"] is True
        assert stand["exhausted"] is False

    async def test_erschoepft_wird_nicht_gekappt(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Ein Anteil über 100 % bleibt stehen: „1.0" sähe aus wie eine
        Punktlandung, und die Überschreitung ist die interessantere Zahl."""
        nutzer = await _angemeldet(client, engine)
        grenze = get_settings().daily_budget_eur
        await _lauf_mit_kosten(engine, user_id=nutzer, kosten=str(grenze * 2))

        stand = (await client.get("/budget")).json()
        assert stand["exhausted"] is True
        assert stand["share"] > 1.0

    async def test_es_gibt_keinen_schreibweg(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Ein Endpunkt, über den sich das eigene Limit anheben ließe, wäre
        kein Limit — er wäre eine Bitte."""
        await _angemeldet(client, engine)

        for methode in ("POST", "PUT", "PATCH", "DELETE"):
            antwort = await client.request(methode, "/budget", json={"limit_eur": "999"})
            assert antwort.status_code == 405, f"{methode}: {antwort.status_code}"

    async def test_ohne_anmeldung_keine_auskunft(self, client: AsyncClient) -> None:
        assert (await client.get("/budget")).status_code == 401


class TestDieGrenzeHaelt:
    """Der Befund aus der Codex-Prüfung, nachgestellt.

    Solange nur das **Verbuchte** zählte, war die Tagesgrenze weich: Bei
    4,99 € von 5,00 € durfte jeder weitere Lauf in die Wolke, und zehn davon
    gaben zehn Laufbudgets aus. Ein angelegter Lauf bringt sein Budget jetzt
    sofort in die Rechnung ein.
    """

    async def test_ein_laufender_lauf_zaehlt_mit_seinem_budget(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        nutzer = await _angemeldet(client, engine)
        grenze = get_settings().daily_budget_eur
        # Knapp unter der Grenze verbucht — vorher stand hier „noch nicht
        # erschöpft", und genau das war die Lücke.
        await _lauf_mit_kosten(engine, user_id=nutzer, kosten=str(grenze - Decimal("0.01")))

        vorher = (await client.get("/budget")).json()
        assert vorher["exhausted"] is False, "Ohne laufenden Lauf ist noch Luft."

        lauf = await client.post("/runs", json={"input": "Was gibt es Neues?"})
        assert lauf.status_code == 201, lauf.text

        nachher = (await client.get("/budget")).json()
        assert Decimal(nachher["spent_eur"]) == grenze - Decimal("0.01"), (
            "Verbucht ist nichts dazugekommen — der Lauf hat noch nichts ausgegeben."
        )
        assert Decimal(nachher["committed_eur"]) > Decimal(nachher["spent_eur"]), (
            "Das Budget des laufenden Laufs muss in der Rechnung stehen."
        )
        assert nachher["exhausted"] is True

    async def test_die_anzeige_sagt_dasselbe_wie_die_entscheidung(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Sonst zeigte die Leiste „60 % verbraucht", während das Routing
        bereits lokal bleibt — eine Wirkung ohne Erklärung."""
        nutzer = await _angemeldet(client, engine)
        await _lauf_mit_kosten(
            engine, user_id=nutzer, kosten=str(get_settings().daily_budget_eur * 2)
        )

        stand = (await client.get("/budget")).json()
        assert stand["share"] >= 2.0
        assert stand["exhausted"] is True


class TestDieWirkung:
    async def test_ein_neuer_lauf_wird_lokal_geroutet(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die eigentliche Prüfung: Das Budget wirkt in der Modellwahl.

        Der Katalog dieses Deployments führt ohnehin nur ein lokales Modell —
        gemessen wird deshalb, dass der Lauf **zustande kommt** und lokal
        landet, statt an der Verengung zu scheitern. Dass ein Cloud-Modell
        dabei herausfiele, prüft der Router in ``test_router.py``, wo sich
        eine Flotte hinstellen lässt.
        """
        nutzer = await _angemeldet(client, engine)
        await _lauf_mit_kosten(engine, user_id=nutzer, kosten=str(get_settings().daily_budget_eur))

        lauf = await client.post("/runs", json={"input": "Was gibt es Neues?"})
        assert lauf.status_code == 201, lauf.text

        geladen = (await client.get(f"/runs/{lauf.json()['id']}")).json()
        assert geladen["model"] == get_settings().ollama_model
        # Und der Grund steht daneben — sonst sähe ein Nutzer nur eine
        # schlechtere Antwort und keine Erklärung.
        assert geladen["model_reason"]
