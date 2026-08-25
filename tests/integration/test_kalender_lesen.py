"""Den eigenen Kalender lesen — und nur den eigenen.

Der Endpunkt schließt eine Lücke, die kein Entwurf gefunden hat, sondern ein
Browserdurchstich: Die Rücknahme meldete „zurückgenommen", und ob der Termin
danach tatsächlich weg war, konnte die Oberfläche nicht sehen. Gemessen wurde
das bis dahin, indem die pytest-Suite Zeilen zählte.

Geprüft wird deshalb hier vor allem, was der Endpunkt **nicht** tut:

* Er zeigt keine fremden Termine — und zwar nicht, weil er sie verbietet,
  sondern weil der Eigentümer in der Abfrage steht und aus der Sitzung kommt.
* Er rät keine Zeitzone.
* Er beantwortet nicht die Frage, die er nicht bekommen hat: Ohne Fenster gibt
  es Kommendes, nicht alles.

Und einmal die Wirkung selbst: anlegen, sehen, zurücknehmen, weg.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.test_http_runs import _angemeldet, _mit_kalenderrecht

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

MORGEN = datetime.now(UTC) + timedelta(days=1)
TERMIN = {
    "title": "Fokuszeit",
    "start": MORGEN.isoformat(),
    "end": (MORGEN + timedelta(hours=1)).isoformat(),
}


async def _termin_anlegen(client: AsyncClient, **abweichend: object) -> str:
    """Legt einen Termin über den normalen Weg an und liefert den Lauf."""
    lauf = await client.post("/runs", json={"input": "Blockier mir eine Stunde"})
    run_id = str(lauf.json()["id"])
    schritt = await client.post(
        f"/runs/{run_id}/steps",
        json={"tool": "calendar.create", "arguments": {**TERMIN, **abweichend}},
    )
    assert schritt.status_code == 200, schritt.text
    assert schritt.json()["status"] == "executed", schritt.json()
    return run_id


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
    assert zeile is not None
    return str(zeile.id)


class TestWasDerEndpunktZeigt:
    async def test_ein_angelegter_termin_ist_danach_sichtbar(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der Fall, für den es den Endpunkt gibt.

        Ohne ihn belegte nur ein ``SELECT count(*)`` im Testcode, dass das
        schreibende Werkzeug gewirkt hat. Jetzt sagt es das System selbst.
        """
        nutzer = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=nutzer)
        await _termin_anlegen(client)

        antwort = await client.get("/calendar")
        assert antwort.status_code == 200, antwort.text
        termine = antwort.json()
        assert [t["title"] for t in termine] == ["Fokuszeit"]
        # Leer heißt: niemand eingeladen. Das Feld steht auch dann in der
        # Antwort — der Unterschied ist sicherheitsrelevant und soll sichtbar
        # sein, statt aus einem fehlenden Feld erschlossen zu werden.
        assert termine[0]["attendees"] == []

    async def test_eine_ruecknahme_ist_danach_zu_sehen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Zusage der Vorschau, zu Ende gemessen.

        ``ActionPreview.reversible`` verspricht „das kannst du rückgängig
        machen". Bis hierher konnte das System die Einlösung nur behaupten;
        jetzt lässt sie sich über denselben Weg nachsehen, über den ein Mensch
        den Kalender sieht.
        """
        nutzer = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=nutzer)
        run_id = await _termin_anlegen(client)
        assert len((await client.get("/calendar")).json()) == 1

        zurueck = await client.post(f"/invocations/{await _letzte_invocation(run_id)}/undo")
        assert zurueck.status_code == 200, zurueck.text

        assert (await client.get("/calendar")).json() == []

    async def test_ein_laufender_termin_faellt_ins_fenster(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Gefragt ist, was im Fenster **liegt**, nicht was darin beginnt.

        Der Termin hat vor einer halben Stunde begonnen und läuft noch. Eine
        Abfrage über ``starts_at >= :von`` verschwiege ihn genau dann, wenn er
        stattfindet — der Fall, in dem die Auskunft am meisten wert ist.
        """
        nutzer = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=nutzer)
        beginn = datetime.now(UTC) - timedelta(minutes=30)
        await _termin_anlegen(
            client,
            start=beginn.isoformat(),
            end=(beginn + timedelta(hours=1)).isoformat(),
        )

        antwort = await client.get("/calendar")
        assert [t["title"] for t in antwort.json()] == ["Fokuszeit"]

    async def test_ohne_fenster_gibt_es_kommendes_und_nicht_alles(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der Vorgabewert ist eine Antwort auf „was kommt".

        Wer Vergangenes will, sagt es — und bekommt es dann auch. Ein
        stillschweigendes „alles" wäre ein Ausschnitt, den niemand benannt hat.
        """
        nutzer = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=nutzer)
        vorbei = datetime.now(UTC) - timedelta(days=3)
        await _termin_anlegen(
            client,
            title="Gewesen",
            start=vorbei.isoformat(),
            end=(vorbei + timedelta(hours=1)).isoformat(),
        )

        assert (await client.get("/calendar")).json() == []

        mit_fenster = await client.get(
            "/calendar", params={"from": (vorbei - timedelta(days=1)).isoformat()}
        )
        assert [t["title"] for t in mit_fenster.json()] == ["Gewesen"]


class TestWasDerEndpunktNichtTut:
    async def test_fremde_termine_sind_nicht_vorhanden(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Eine gültige eigene Sitzung, ein fremder Kalender.

        Direkt in die Datenbank und nicht über eine zweite Sitzung:
        ``_angemeldet`` räumt die Nutzertabelle. Erzeugt wird genau die Lage,
        die der Endpunkt nicht zeigen darf.
        """
        nutzer = await _angemeldet(client, engine)
        fremder = uuid.uuid4()
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Fremd')"),
                {"i": fremder, "m": f"runtest-{fremder}@example.test"},
            )
            await conn.execute(
                text(
                    "INSERT INTO calendar_events "
                    "(id, user_id, title, starts_at, ends_at) "
                    "VALUES (:i, :u, 'Fremder Termin', :a, :e)"
                ),
                {
                    "i": uuid.uuid4(),
                    "u": fremder,
                    "a": MORGEN,
                    "e": MORGEN + timedelta(hours=1),
                },
            )

        assert (await client.get("/calendar")).json() == []
        assert nutzer != fremder

    async def test_es_gibt_keinen_parameter_fuer_einen_anderen_nutzer(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die mitgebrachte Identität — eine Schicht tiefer als im Body.

        ``user_id`` in der Query ist der kürzeste Weg in einen fremden
        Kalender. Er scheitert nicht an einer Prüfung, sondern daran, dass es
        keine Methode gibt, die einen Eigentümer entgegennähme.
        """
        nutzer = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=nutzer)
        await _termin_anlegen(client)

        fremd = await client.get("/calendar", params={"user_id": str(uuid.uuid4())})
        assert fremd.status_code == 200
        assert [t["title"] for t in fremd.json()] == ["Fokuszeit"]

    async def test_ohne_zeitzone_wird_abgelehnt_statt_geraten(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Dieselbe Entscheidung wie beim Anlegen.

        „14 Uhr" ohne Zone ist in einem System, das Termine für Menschen
        führt, keine Angabe, sondern eine Vermutung — und die falsche
        verschiebt die Antwort um Stunden.
        """
        await _angemeldet(client, engine)

        antwort = await client.get("/calendar", params={"from": "2026-09-08T09:00:00"})
        assert antwort.status_code == 422, antwort.text
        assert "Zeitzone" in antwort.json()["detail"]

    async def test_ein_fenster_rueckwaerts_wird_abgelehnt(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        await _angemeldet(client, engine)

        antwort = await client.get(
            "/calendar",
            params={
                "from": MORGEN.isoformat(),
                "to": (MORGEN - timedelta(days=2)).isoformat(),
            },
        )
        assert antwort.status_code == 422, antwort.text

    async def test_das_fenster_wird_auf_den_bruchteil_genau_begrenzt(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """400 Tage heißt 400 Tage.

        Vorher stand hier ``(bis - beginn).days > 400``; das schneidet den
        Bruchteil ab, und 400 Tage plus 23:59:59 gingen durch. Kein
        Sicherheitsproblem, aber eine Zusage, die um fast einen Tag danebenlag
        — gemeldet von einer Prüfung durch Codex.
        """
        await _angemeldet(client, engine)
        beginn = MORGEN

        knapp_drueber = await client.get(
            "/calendar",
            params={
                "from": beginn.isoformat(),
                "to": (beginn + timedelta(days=400, hours=23)).isoformat(),
            },
        )
        genau = await client.get(
            "/calendar",
            params={
                "from": beginn.isoformat(),
                "to": (beginn + timedelta(days=400)).isoformat(),
            },
        )

        assert knapp_drueber.status_code == 422, knapp_drueber.text
        assert genau.status_code == 200, genau.text

    async def test_ohne_anmeldung_gibt_es_keine_auskunft(self, client: AsyncClient) -> None:
        antwort = await client.get("/calendar")
        assert antwort.status_code == 401, antwort.text
