"""Berechtigungen erteilen und zurückziehen — der Weg, den es nicht gab.

Der gesamte Sicherheitssockel steht auf der Aussage „der Nutzer hat das
erteilt". Bis hierher konnte niemand erteilen: Der Speicher las nur, eine Route
gab es nicht, und jede Berechtigung dieses Systems entstand per ``INSERT`` von
Hand — auch in jedem Test dieser Suite. Damit war die Aussage über jede
Berechtigung eine Behauptung über eine Zeile, die irgendwer geschrieben hat.

**Was hier geprüft wird, ist überwiegend, was der Weg nicht kann.** Die
Erteilung ist die gefährliche Richtung: Ein Scope auf ``allow`` nimmt jede
künftige Bestätigung aus dem Weg — genau den Dialog, den ein Mensch liest,
bevor etwas nach außen wirkt.

Und die Wirkung wird am Werkzeug gemessen, nicht an der Antwort des Endpunkts:
Eine Berechtigung, die im Permission Center steht und beim Aufruf nicht gilt,
wäre schlimmer als keine.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_core.clock import utc_now
from tests.integration.test_http_runs import _angemeldet

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

TERMIN = {
    "title": "Fokuszeit",
    "start": "2026-09-10T09:00:00+00:00",
    "end": "2026-09-10T10:00:00+00:00",
}


async def _termin_versuchen(client: AsyncClient) -> str:
    """Legt einen Termin an — und liefert den Ausgang, nicht die Ausrede."""
    lauf = await client.post("/runs", json={"input": "Blockier mir eine Stunde"})
    schritt = await client.post(
        f"/runs/{lauf.json()['id']}/steps",
        json={"tool": "calendar.create", "arguments": TERMIN},
    )
    assert schritt.status_code == 200, schritt.text
    return str(schritt.json()["status"])


class TestDerKatalogIstDieAuskunft:
    async def test_auch_was_nicht_erteilt_ist_steht_in_der_liste(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """„Darf JARVIS Mails senden?" beantwortet der Scope, zu dem **nichts**
        erteilt ist. Eine Liste, die nur Erteiltes führt, kann die Frage nicht
        stellen."""
        await _angemeldet(client, engine)

        antwort = await client.get("/permissions")

        assert antwort.status_code == 200, antwort.text
        eintraege = {e["name"]: e for e in antwort.json()}
        assert "calendar.create" in eintraege
        assert eintraege["calendar.create"]["granted"] is None, "Nichts erteilt heißt nichts."

    async def test_der_vorgabemodus_ist_keine_erteilung(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der Katalogwert ist die Empfehlung für eine Erteilung, nicht die
        Erteilung. Wer beides vermengt, hat Rechte, die niemand vergeben hat."""
        await _angemeldet(client, engine)

        eintraege = {e["name"]: e for e in (await client.get("/permissions")).json()}
        kalender = eintraege["calendar.create"]

        assert kalender["default_mode"] in {"allow", "confirm", "deny"}
        assert kalender["granted"] is None
        assert await _termin_versuchen(client) == "blocked", (
            "Ohne Erteilung läuft nichts — auch wenn der Katalog 'allow' empfiehlt."
        )


class TestErteilenUndZurueckziehen:
    async def test_eine_erteilung_wirkt_sofort_am_werkzeug(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Gemessen an der Wirkung und nicht an der Antwort des Endpunkts."""
        await _angemeldet(client, engine)
        assert await _termin_versuchen(client) == "blocked"

        gesetzt = await client.put("/permissions/calendar.create", json={"mode": "allow"})

        assert gesetzt.status_code == 200, gesetzt.text
        assert gesetzt.json()["mode"] == "allow"
        assert await _termin_versuchen(client) == "executed"

    async def test_zurueckziehen_wirkt_ebenso_sofort(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Policy Engine liest bei jedem Aufruf neu — ein Lauf zwischen zwei
        Schritten findet das Recht beim nächsten nicht mehr vor."""
        await _angemeldet(client, engine)
        await client.put("/permissions/calendar.create", json={"mode": "allow"})
        assert await _termin_versuchen(client) == "executed"

        geloescht = await client.delete("/permissions/calendar.create")

        assert geloescht.status_code == 204, geloescht.text
        assert await _termin_versuchen(client) == "blocked"

    async def test_confirm_erzeugt_den_dialog_statt_der_wirkung(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der mittlere Modus ist der eigentliche Zweck der ganzen Mechanik."""
        await _angemeldet(client, engine)

        await client.put("/permissions/calendar.create", json={"mode": "confirm"})

        assert await _termin_versuchen(client) == "awaiting_confirmation"

    async def test_zurueckziehen_ohne_erteilung_ist_kein_fehler(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Ein ``404`` wäre eine Auskunft darüber, was jemand erteilt hat."""
        await _angemeldet(client, engine)

        antwort = await client.delete("/permissions/calendar.create")

        assert antwort.status_code == 204


class TestWasDerWegNichtDarf:
    async def test_ein_erfundener_scope_wird_abgewiesen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Eine Berechtigung für nichts wäre eine, die ein künftiges Werkzeug
        still vorfände."""
        await _angemeldet(client, engine)

        antwort = await client.put("/permissions/kernwaffen.starten", json={"mode": "allow"})

        assert antwort.status_code == 404, antwort.text
        async with engine.begin() as conn:
            anzahl = (
                await conn.execute(
                    text("SELECT count(*) FROM permissions WHERE scope = 'kernwaffen.starten'")
                )
            ).scalar_one()
        assert anzahl == 0

    async def test_fremde_einschraenkungen_passen_nicht_zum_scope(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Eine ``files.read``-Berechtigung kann keine Empfängerliste tragen.

        Die scope-eigene Klasse verbietet zusätzliche Felder — und das ist der
        Grund, warum eine falsch geschriebene Pfadgrenze hier auffällt und
        nicht erst dann, wenn sie nicht mehr greift.
        """
        await _angemeldet(client, engine)

        antwort = await client.put(
            "/permissions/files.read",
            json={"mode": "allow", "constraints": {"allowed_recipients": ["fremd@example.com"]}},
        )

        assert antwort.status_code == 422, antwort.text

    async def test_einschraenkungen_werden_ersetzt_und_nicht_ergaenzt(
        self, client: AsyncClient, engine: AsyncEngine, tmp_path: Path
    ) -> None:
        """**Der unangenehme Fall.**

        Wer eine Berechtigung ändert, setzt sie neu. Ein Zusammenführen mit dem
        alten Stand wäre die Art von Bequemlichkeit, bei der eine Pfadgrenze
        aus der Vorwoche eine neue Erteilung still erweitert.

        Gemessen an zwei Werten: Die alte Wurzel darf nicht überleben, und die
        abweichende Dateigröße muss auf den Vorgabewert zurückfallen.
        """
        await _angemeldet(client, engine)
        eng, weit = tmp_path / "eng", tmp_path / "weit"
        eng.mkdir()
        weit.mkdir()

        erste = await client.put(
            "/permissions/files.read",
            json={
                "mode": "allow",
                "constraints": {"allowed_roots": [str(eng)], "max_file_size_mb": 7},
            },
        )
        zweite = await client.put(
            "/permissions/files.read",
            json={"mode": "allow", "constraints": {"allowed_roots": [str(weit)]}},
        )

        assert (erste.status_code, zweite.status_code) == (200, 200), zweite.text
        eintraege = {e["name"]: e for e in (await client.get("/permissions")).json()}
        grenzen = eintraege["files.read"]["granted"]["constraints"]
        assert grenzen["allowed_roots"] == [str(weit)], (
            f"Die alte Wurzel hat die neue Erteilung überlebt: {grenzen['allowed_roots']}"
        )
        assert grenzen["max_file_size_mb"] == 50, (
            "Die abweichende Größe von vorhin gilt weiter — das ist ein Zusammenführen "
            "und kein Ersetzen."
        )

    async def test_eine_dateiberechtigung_ohne_pfadgrenze_ist_nicht_darstellbar(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Aufgefallen beim Schreiben des Tests darüber, und die richtige Antwort.

        ``FilesConstraints.allowed_roots`` trägt ``min_length=1`` — ein
        Dateizugriff ohne Pfadgrenze ist keine Berechtigung. Wer sie weglässt,
        bekommt deshalb keine unbegrenzte, sondern gar keine.
        """
        await _angemeldet(client, engine)

        antwort = await client.put("/permissions/files.read", json={"mode": "allow"})

        assert antwort.status_code == 422, antwort.text

    async def test_eine_fremde_berechtigung_bleibt_unberuehrt(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Zugehörigkeit steht in der Anweisung, nicht in einer Prüfung
        darüber — sonst löschte ein Nutzer fremde Rechte."""
        await _angemeldet(client, engine)
        fremder = uuid.uuid4()
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Fremd')"),
                {"i": fremder, "m": f"perm-fremd-{fremder}@example.test"},
            )
            await conn.execute(
                text(
                    "INSERT INTO permissions (id, user_id, scope, mode, granted_at) "
                    "VALUES (:i, :u, 'calendar.create', 'allow', now())"
                ),
                {"i": uuid.uuid4(), "u": fremder},
            )

        await client.delete("/permissions/calendar.create")

        async with engine.begin() as conn:
            uebrig = (
                await conn.execute(
                    text("SELECT mode FROM permissions WHERE user_id = :u"), {"u": fremder}
                )
            ).scalar_one()
        assert uebrig == "allow", "Das fremde Recht wurde mitgelöscht."

    async def test_ohne_anmeldung_geht_gar_nichts(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        antworten = [
            await client.get("/permissions"),
            await client.put("/permissions/calendar.create", json={"mode": "allow"}),
            await client.delete("/permissions/calendar.create"),
        ]

        assert [a.status_code for a in antworten] == [401, 401, 401], [a.text for a in antworten]


class TestAblauf:
    async def test_eine_abgelaufene_berechtigung_gilt_nicht_mehr(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Und sie steht trotzdem in der Liste — als abgelaufen benannt.

        Ausgerechnet dieser Zustand ist der verwirrendste, wenn ihn niemand
        benennt: Der Nutzer sieht eine Erteilung, und nichts funktioniert.
        """
        await _angemeldet(client, engine)
        vergangen = (utc_now() - timedelta(minutes=1)).isoformat()

        await client.put(
            "/permissions/calendar.create",
            json={"mode": "allow", "expires_at": vergangen},
        )

        eintraege = {e["name"]: e for e in (await client.get("/permissions")).json()}
        assert eintraege["calendar.create"]["granted"]["expired"] is True
        assert await _termin_versuchen(client) == "blocked"
