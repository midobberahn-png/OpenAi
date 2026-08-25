"""Das Kostenhauptbuch — Tatsache je Aufruf, nachgerechnet gegen den Lauf.

Ein zweiter Ort für dieselbe Zahl war der Einwand, der dieses Hauptbuch zweimal
verhindert hat. Diese Suite ist die Antwort darauf: Sie rechnet nach, statt zu
behaupten.

Drei Zusagen stehen hier auf dem Prüfstand:

* **Vollständigkeit.** Was ``runs.usage`` als Summe führt, steht im Hauptbuch
  als Posten — sonst wäre die abgeleitete Sicht nicht abgeleitet, sondern eine
  zweite Meinung.
* **Der Tageswechsel.** Kosten fallen auf den Tag ihres **Aufrufs**, nicht auf
  den ihres Laufs. Genau das ging vorher schief.
* **Die Auskunft.** „Wofür ist das Geld draufgegangen?" — die Frage, für die es
  das Hauptbuch überhaupt gibt.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.test_http_runs import _angemeldet

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]


async def _lauf(engine: AsyncEngine, *, user_id: uuid.UUID, kosten: str = "0") -> uuid.UUID:
    """Ein Lauf mit gebuchter Summe — die Sicht, die abgeleitet sein soll."""
    run_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO runs (id, user_id, trigger, status, budget, usage, trace_id) "
                "VALUES (:i, :u, 'user', 'completed', '{}'::jsonb, CAST(:v AS jsonb), :t)"
            ),
            {
                "i": run_id,
                "u": user_id,
                "v": f'{{"cost_eur": "{kosten}"}}',
                "t": f"trace-{run_id}",
            },
        )
    return run_id


async def _posten(
    engine: AsyncEngine,
    *,
    user_id: uuid.UUID,
    run_id: uuid.UUID,
    kosten: str,
    modell: str = "claude-sonnet-5",
    anbieter: str = "anthropic",
    zweck: str = "response",
    wann: datetime | None = None,
) -> None:
    """Eine Zeile im Hauptbuch.

    ``occurred_at`` wird nur gesetzt, wo der Test einen anderen Tag braucht —
    sonst stempelt die Datenbank, und genau darauf kommt es an.
    """
    async with engine.begin() as conn:
        if wann is None:
            await conn.execute(
                text(
                    "INSERT INTO model_calls (user_id, run_id, provider, model, purpose, cost_eur)"
                    " VALUES (:u, :r, :p, :m, :z, :k)"
                ),
                {"u": user_id, "r": run_id, "p": anbieter, "m": modell, "z": zweck, "k": kosten},
            )
        else:
            await conn.execute(
                text(
                    "INSERT INTO model_calls "
                    "(user_id, run_id, provider, model, purpose, cost_eur, occurred_at)"
                    " VALUES (:u, :r, :p, :m, :z, :k, :w)"
                ),
                {
                    "u": user_id,
                    "r": run_id,
                    "p": anbieter,
                    "m": modell,
                    "z": zweck,
                    "k": kosten,
                    "w": wann,
                },
            )


class TestVollstaendigkeit:
    async def test_ein_echter_lauf_steht_im_hauptbuch(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Zusage, die das Hauptbuch tragen muss.

        Gefahren wird der gewöhnliche Weg: Lauf anlegen, Antwortschritt
        treiben. Was der Lauf danach als Summe führt, muss als Posten dastehen
        — sonst ist ``runs.usage`` keine abgeleitete Sicht, sondern eine
        zweite Meinung.

        Ein lokales Modell kostet null; geprüft wird deshalb die
        **Übereinstimmung** und die Anzahl der Posten, nicht ein Betrag.
        """
        nutzer = await _angemeldet(client, engine)
        angelegt = await client.post("/runs", json={"input": "Sag Hallo"})
        run_id = angelegt.json()["id"]

        schritt = await client.post(f"/runs/{run_id}/advance", json={})
        assert schritt.status_code in (200, 409), schritt.text

        async with engine.begin() as conn:
            zeile = (
                await conn.execute(
                    text(
                        "SELECT COALESCE((r.usage ->> 'cost_eur')::numeric, 0) AS lauf, "
                        "  (SELECT COALESCE(SUM(cost_eur), 0) FROM model_calls m "
                        "     WHERE m.run_id = r.id) AS hauptbuch, "
                        "  (SELECT count(*) FROM model_calls m WHERE m.run_id = r.id) AS posten "
                        "FROM runs r WHERE r.id = :r"
                    ),
                    {"r": uuid.UUID(run_id)},
                )
            ).one()

        assert zeile.posten >= 1, "Der Antwortschritt hat ein Modell gefragt — und nichts gebucht."
        assert Decimal(str(zeile.lauf)) == Decimal(str(zeile.hauptbuch)), (
            "Die Summe im Lauf weicht vom Hauptbuch ab — die abgeleitete Sicht driftet."
        )
        assert nutzer is not None

    async def test_der_zweck_wird_mitgeschrieben(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Ohne ihn sieht man, *welches* Modell teuer war, aber nicht *wobei*."""
        await _angemeldet(client, engine)
        angelegt = await client.post("/runs", json={"input": "Sag Hallo"})
        await client.post(f"/runs/{angelegt.json()['id']}/advance", json={})

        async with engine.begin() as conn:
            zwecke = (
                (
                    await conn.execute(
                        text("SELECT DISTINCT purpose FROM model_calls WHERE run_id = :r"),
                        {"r": uuid.UUID(angelegt.json()["id"])},
                    )
                )
                .scalars()
                .all()
            )

        assert set(zwecke) <= {"arguments", "response", "agent"}, zwecke
        assert zwecke, "Kein Posten trägt einen Zweck."


class TestDerTageswechsel:
    async def test_kosten_fallen_auf_den_tag_ihres_aufrufs(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der Befund aus der Codex-Prüfung, jetzt behoben.

        Vorher hing die Zuordnung am **Beginn des Laufs**: Ein Lauf, der über
        Mitternacht weiterrechnete, belastete den Vortag — und zwar mit allem,
        was er danach noch ausgab. Jetzt trägt jeder Aufruf seinen eigenen
        Zeitstempel.
        """
        nutzer = await _angemeldet(client, engine)
        # Ein Lauf von gestern, der heute weiterrechnet.
        gestriger = await _lauf(engine, user_id=nutzer)
        async with engine.begin() as conn:
            await conn.execute(
                text("UPDATE runs SET started_at = now() - interval '2 days' WHERE id = :r"),
                {"r": gestriger},
            )
        await _posten(
            engine,
            user_id=nutzer,
            run_id=gestriger,
            kosten="1.50",
            wann=datetime.now(UTC) - timedelta(days=2),
        )
        await _posten(engine, user_id=nutzer, run_id=gestriger, kosten="0.25")

        stand = (await client.get("/budget")).json()

        assert Decimal(stand["spent_eur"]) == Decimal("0.25"), (
            "Der heutige Aufruf eines gestrigen Laufs muss heute zählen — und nur er."
        )


class TestDieAuskunft:
    async def test_wofuer_das_geld_draufgegangen_ist(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Frage, für die es das Hauptbuch gibt."""
        nutzer = await _angemeldet(client, engine)
        lauf = await _lauf(engine, user_id=nutzer)
        await _posten(engine, user_id=nutzer, run_id=lauf, kosten="0.10", zweck="arguments")
        await _posten(engine, user_id=nutzer, run_id=lauf, kosten="0.40", zweck="response")
        await _posten(
            engine,
            user_id=nutzer,
            run_id=lauf,
            kosten="0.05",
            modell="gpt-test",
            anbieter="openai",
            zweck="response",
        )

        posten = (await client.get("/budget")).json()["by_model"]

        assert [p["cost_eur"] for p in posten] == ["0.400000", "0.100000", "0.050000"], (
            f"Teuerstes zuerst — die Antwort gehört in die erste Zeile: {posten}"
        )
        assert {p["purpose"] for p in posten} == {"arguments", "response"}
        assert {p["provider"] for p in posten} == {"anthropic", "openai"}

    async def test_fremde_posten_erscheinen_nicht(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der Eigentümer steht in der Abfrage, wie überall.

        Eine Kostenaufstellung, die fremde Posten mitführte, wäre zugleich eine
        Auskunft darüber, woran jemand anderes arbeitet.
        """
        nutzer = await _angemeldet(client, engine)
        fremder = uuid.uuid4()
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Fremd')"),
                {"i": fremder, "m": f"runtest-{fremder}@example.test"},
            )
        fremder_lauf = await _lauf(engine, user_id=fremder)
        await _posten(engine, user_id=fremder, run_id=fremder_lauf, kosten="9.99")

        stand = (await client.get("/budget")).json()

        assert stand["by_model"] == []
        assert Decimal(stand["spent_eur"]) == Decimal("0")
        assert nutzer != fremder
