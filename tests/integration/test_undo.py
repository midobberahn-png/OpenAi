"""Die Rücknahme — und warum sie kein Löschrecht ist.

`ToolResult.undo_token` war ein Vertragsfeld, das niemand setzte und kein
Endpunkt entgegennahm. Deshalb stand `calendar.create` auf
`supports_undo=False`: Der Wert speist `ActionPreview.reversible`, den Satz
„das kannst du rückgängig machen“, den ein Mensch **vor** seiner Bestätigung
liest.

Der Weg existiert jetzt, und diese Suite prüft vor allem, was er **nicht** kann.
Eine Rücknahme, die einen fremden Termin löscht, wäre schlimmer als gar keine:
Sie wäre ein Löschrecht, das niemand erteilt hat, hinter einem Namen, der
harmlos klingt.

Fünf Verengungen, jede mit einem Test:

* nur ein **eigener** Aufruf,
* nur ein **ausgeführter**,
* nur innerhalb der **Frist**,
* nur **einmal**,
* und nur an dem Punkt, den das **Werkzeug selbst** notiert hat — nie an einem,
  den der Aufrufer mitbringt.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.test_http_runs import _angemeldet, _mit_kalenderrecht

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

TERMIN = {
    "title": "Fokuszeit",
    "start": "2026-09-08T09:00:00+00:00",
    "end": "2026-09-08T10:00:00+00:00",
}


async def _termin_anlegen(client: AsyncClient) -> tuple[str, str]:
    """Legt einen Termin über den normalen Weg an.

    Rückgabe: Lauf und **Aufrufkennung** — die zweite ist es, die eine
    Rücknahme adressiert.
    """
    lauf = await client.post("/runs", json={"input": "Blockier mir eine Stunde"})
    run_id = lauf.json()["id"]
    schritt = await client.post(
        f"/runs/{run_id}/steps",
        json={"tool": "calendar.create", "arguments": TERMIN},
    )
    assert schritt.status_code == 200, schritt.text
    assert schritt.json()["status"] == "executed", schritt.json()
    return str(run_id), await _letzte_invocation(run_id)


async def _letzte_invocation(run_id: str) -> str:
    from jarvis_api.db.session import engine_for
    from jarvis_api.settings import get_settings

    async with engine_for(get_settings().database_url).connect() as conn:
        zeile = (
            await conn.execute(
                text(
                    "SELECT id FROM tool_invocations WHERE run_id = :r "
                    "ORDER BY created_at DESC LIMIT 1"
                ),
                {"r": uuid.UUID(run_id)},
            )
        ).first()
    assert zeile is not None, "Ohne Protokolleintrag gibt es nichts zurückzunehmen."
    return str(zeile.id)


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


async def _status(engine: AsyncEngine, invocation_id: str) -> str:
    async with engine.begin() as conn:
        return str(
            (
                await conn.execute(
                    text("SELECT status FROM tool_invocations WHERE id = :i"),
                    {"i": uuid.UUID(invocation_id)},
                )
            ).scalar_one()
        )


async def _altern_lassen(engine: AsyncEngine, invocation_id: str, minuten: int) -> None:
    """Verschiebt ``executed_at`` zurück — in der Datenbank gerechnet.

    Als ``timedelta`` und nicht als Zeichenkette: asyncpg bindet den Parameter
    typisiert an ``interval`` und weist ``"14 minutes"`` ab.
    """
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE tool_invocations SET executed_at = executed_at - "
                "CAST(:um AS interval) WHERE id = :i"
            ),
            {"i": uuid.UUID(invocation_id), "um": timedelta(minutes=minuten)},
        )


async def _fremder_termin(engine: AsyncEngine) -> tuple[uuid.UUID, str, uuid.UUID]:
    """Ein Termin samt Protokolleintrag, der einem **anderen** Nutzer gehört.

    Direkt in die Datenbank und nicht über eine zweite Sitzung: ``_angemeldet``
    räumt die Nutzertabelle. Erzeugt wird genau die Lage, die eine Rücknahme
    nicht anfassen darf — ausgeführt, innerhalb der Frist, mit Rücknahmepunkt.
    """
    fremder, run_id, invocation_id, event_id = (uuid.uuid4() for _ in range(4))
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Fremd')"),
            {"i": fremder, "m": f"undo-fremd-{fremder}@example.test"},
        )
        await conn.execute(
            text(
                "INSERT INTO runs (id, user_id, trace_id, budget) "
                "VALUES (:r, :u, 'fremd', '{}'::jsonb)"
            ),
            {"r": run_id, "u": fremder},
        )
        await conn.execute(
            text(
                "INSERT INTO calendar_events (id, user_id, title, starts_at, ends_at) "
                "VALUES (:e, :u, 'Fremder Termin', now(), now() + interval '1 hour')"
            ),
            {"e": event_id, "u": fremder},
        )
        await conn.execute(
            text(
                "INSERT INTO tool_invocations (id, run_id, tool_name, arguments, "
                "risk_level, policy_decision, decision_reason, status, result, "
                "created_at, executed_at) VALUES (:i, :r, 'calendar.create', '{}'::jsonb, "
                "'medium', 'allow', 'Fremd', 'executed', "
                "jsonb_build_object('undo_token', CAST(:e AS text)), now(), now())"
            ),
            {"i": invocation_id, "r": run_id, "e": str(event_id)},
        )
    return fremder, str(invocation_id), event_id


class TestDerWegFunktioniert:
    async def test_ein_termin_laesst_sich_zuruecknehmen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der Durchstich — und gemessen wird der Kalender, nicht die Antwort."""
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        _, invocation_id = await _termin_anlegen(client)
        assert await _termine(engine, user_id) == 1

        antwort = await client.post(f"/invocations/{invocation_id}/undo")

        assert antwort.status_code == 200, antwort.text
        assert antwort.json()["undone"] is True, antwort.json()
        assert await _termine(engine, user_id) == 0
        assert await _status(engine, invocation_id) == "undone"

    async def test_die_vorschau_darf_die_ruecknahme_jetzt_versprechen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der Grund, warum ``supports_undo`` so lange auf ``False`` stand.

        Der Wert ist keine Eigenschaft des Termins, sondern eine des Systems:
        Er steht in der Vorschau, die ein Mensch vor seiner Bestätigung liest.
        """
        from jarvis_core.tools.builtin import CALENDAR_CREATE

        assert CALENDAR_CREATE.supports_undo is True


class TestFuenfVerengungen:
    @pytest.mark.invariant("undo-is-bound-to-its-invocation")
    async def test_ein_fremder_aufruf_laesst_sich_nicht_zuruecknehmen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """**Der wichtigste Test dieser Datei.**

        Ohne die Zugehörigkeitsprüfung wäre die Rücknahme ein Löschrecht auf
        fremde Termine — hinter einem Namen, der harmlos klingt. Die Prüfung
        steht in der ``WHERE``-Klausel von ``claim_undo`` und nicht in einer
        Bedingung darüber.

        Der fremde Vorgang wird hier **direkt in die Datenbank** gelegt und
        nicht über eine zweite Sitzung erzeugt: ``_angemeldet`` räumt die
        Nutzertabelle, und ein zweiter Login nähme dem ersten den Termin, statt
        ihn zu schützen. Was zählt, ist die Zeile, die der Angemeldete nicht
        anfassen darf.
        """
        await _angemeldet(client, engine)
        fremder, invocation_id, event_id = await _fremder_termin(engine)

        antwort = await client.post(f"/invocations/{invocation_id}/undo")

        assert antwort.status_code == 409, antwort.text
        assert await _termine(engine, fremder) == 1, "Der fremde Termin steht noch."
        assert await _status(engine, invocation_id) == "executed", (
            "Und der Anspruch ist unverbraucht — ein Fremder darf ihn nicht entwerten."
        )
        assert str(event_id) not in antwort.text, (
            "Die Ablehnung nennt nichts, was dem Fragenden nicht gehört."
        )

    @pytest.mark.invariant("undo-is-bound-to-its-invocation")
    async def test_zweimal_zuruecknehmen_geht_nicht(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der Anspruch wird **vor** der Wirkung verbraucht — wie überall sonst."""
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        _, invocation_id = await _termin_anlegen(client)

        erste = await client.post(f"/invocations/{invocation_id}/undo")
        zweite = await client.post(f"/invocations/{invocation_id}/undo")

        assert erste.status_code == 200, erste.text
        assert zweite.status_code == 409, zweite.text

    @pytest.mark.invariant("undo-is-bound-to-its-invocation")
    async def test_nach_der_frist_nicht_mehr(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Ein Rückgängig-Weg ohne Ende wäre ein zweites Löschrecht.

        Wer ein Konto Wochen später übernimmt, nähme sonst alles zurück, was je
        angelegt wurde. Fünfzehn Minuten decken den Fall ab, für den Undo
        gedacht ist.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        _, invocation_id = await _termin_anlegen(client)
        await _altern_lassen(engine, invocation_id, minuten=16)

        antwort = await client.post(f"/invocations/{invocation_id}/undo")

        assert antwort.status_code == 409, antwort.text
        assert await _termine(engine, user_id) == 1

    async def test_kurz_vor_der_frist_noch(self, client: AsyncClient, engine: AsyncEngine) -> None:
        """Die Gegenprobe. Eine Frist, die schon vorher greift, ist keine."""
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        _, invocation_id = await _termin_anlegen(client)
        await _altern_lassen(engine, invocation_id, minuten=14)

        antwort = await client.post(f"/invocations/{invocation_id}/undo")

        assert antwort.status_code == 200, antwort.text
        assert await _termine(engine, user_id) == 0

    @pytest.mark.invariant("undo-is-bound-to-its-invocation")
    async def test_ein_blockierter_aufruf_hat_nichts_zurueckzunehmen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Nur eine Wirkung lässt sich zurücknehmen.

        Der Aufruf steht im Protokoll, ist aber nie gelaufen — ohne die
        Statusbedingung liefe der Undo-Handler mit leerem Rücknahmepunkt gegen
        irgendetwas.
        """
        user_id = await _angemeldet(client, engine)
        # **Ohne** Kalenderrecht: Die Policy weist ab, der Aufruf wird
        # protokolliert und blockiert.
        lauf = await client.post("/runs", json={"input": "Blockier mir eine Stunde"})
        run_id = lauf.json()["id"]
        schritt = await client.post(
            f"/runs/{run_id}/steps",
            json={"tool": "calendar.create", "arguments": TERMIN},
        )
        assert schritt.json()["status"] in {"blocked", "awaiting_confirmation"}, schritt.json()
        invocation_id = await _letzte_invocation(run_id)

        antwort = await client.post(f"/invocations/{invocation_id}/undo")

        assert antwort.status_code == 409, antwort.text
        assert await _termine(engine, user_id) == 0

    async def test_eine_erfundene_kennung_sagt_dasselbe_wie_eine_fremde(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Ein eigener Statuscode für „gibt es nicht" wäre eine Auskunft.

        Wer eine Kennung durchprobiert, erführe sonst am Unterschied zwischen
        404 und 409, welche Aufrufe existieren.
        """
        await _angemeldet(client, engine)

        antwort = await client.post(f"/invocations/{uuid.uuid4()}/undo")

        assert antwort.status_code == 409, antwort.text
