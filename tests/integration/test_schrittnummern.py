"""Schrittnummern: Plan und Einzelaufruf teilen sich einen Zahlenraum.

``RunState.completed_steps`` führt beides — die erledigten Planschritte und die
Aufrufe, die jemand über ``POST /runs/{id}/steps`` selbst ausgelöst hat. Der
Plan liest daraus, was noch fällig ist (``Plan.ready_steps``), und er
unterscheidet dabei nicht, woher eine Nummer stammt.

Solange nur Planschritte liefen, trug das. Ein Einzelaufruf dazwischen bekam
bislang ``max(erledigte) + 1`` — und damit die Nummer des **nächsten
Planschrittes**, sobald der noch nicht gelaufen war. Der galt danach als
erledigt, ohne je gelaufen zu sein.

Hier steht der Nachweis und die Zusicherung danach. Der Befund ist älter als
die Agentenschleife; sie hätte ihn nur vervielfacht, weil ein Agentenschritt
mehrere Werkzeugaufrufe enthält und jeder davon eine Nummer bekommt.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.test_http_runs import _angemeldet, _mit_kalenderrecht
from tests.integration.test_step_claim import _lauf_mit_terminschritt

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

TERMIN = {
    "title": "Fokuszeit",
    "start": "2026-09-04T09:00:00+00:00",
    "end": "2026-09-04T10:00:00+00:00",
}


async def _erledigte(engine: AsyncEngine, run_id: str) -> list[int]:
    async with engine.begin() as conn:
        zustand = (
            await conn.execute(
                text("SELECT state FROM runs WHERE id = :r"), {"r": uuid.UUID(run_id)}
            )
        ).scalar_one()
    return [s["seq"] for s in (zustand or {}).get("completed_steps", [])]


class TestEinEinzelaufrufBelegtKeinenPlanschritt:
    async def test_der_naechste_planschritt_gilt_danach_nicht_als_erledigt(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """**Der Befund.**

        Plan: ① Termin anlegen ② Antwort formulieren. Nach ① ruft der Nutzer ein
        Werkzeug selbst auf. Bekäme dieser Aufruf die Nummer 2, wäre ② erledigt,
        ohne gelaufen zu sein — der Lauf endete ohne Antwort.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)

        erster = await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})
        assert erster.status_code == 200, erster.text
        assert await _erledigte(engine, run_id) == [1]

        einzeln = await client.post(
            f"/runs/{run_id}/steps",
            json={"tool": "calendar.create", "arguments": dict(TERMIN, title="Nebenbei")},
        )
        assert einzeln.status_code == 200, einzeln.text

        erledigt = await _erledigte(engine, run_id)
        sicht = await client.get(f"/runs/{run_id}")
        plan = {s["seq"]: s["status"] for s in sicht.json()["plan"]}

        assert 2 not in erledigt, (
            f"Der Einzelaufruf hat die Nummer eines Planschrittes belegt: {erledigt}. "
            "Planschritt 2 gilt damit als erledigt, ohne gelaufen zu sein."
        )
        assert plan[2] != "done", f"Planschritt 2 gilt als erledigt: {sicht.json()['plan']}"

    async def test_der_planschritt_laeuft_danach_noch(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Wirkung, nicht nur die Zahl: Der Lauf muss zu Ende kommen.

        Ohne diese Prüfung bliebe der Befund eine Aussage über ein Feld. Was
        zählt, ist, dass der abschließende Schritt noch fällig ist — sonst
        endet der Lauf stumm.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)
        await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})
        await client.post(
            f"/runs/{run_id}/steps",
            json={"tool": "calendar.create", "arguments": dict(TERMIN, title="Nebenbei")},
        )

        sicht = await client.get(f"/runs/{run_id}")
        faellig = [s for s in sicht.json()["plan"] if s["status"] == "ready"]

        assert faellig and faellig[0]["seq"] == 2, sicht.json()["plan"]
