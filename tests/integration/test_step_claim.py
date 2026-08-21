"""Der Anspruch auf einen Planschritt — vor der Wirkung, nicht danach.

**Herkunft: externer Prüfbericht.** Gemeldet als Verdacht, weil dem Prüfer
Postgres fehlte: Bei ``POST /runs/{id}/steps`` und ``POST /runs/{id}/advance``
steht der Statusanspruch (Compare-and-set in ``runs.save``) **nach** der
Werkzeugwirkung. Zwei Requests können denselben Lauf laden, beide ausführen,
und erst danach verliert einer.

Mit laufender Datenbank nachgemessen — und der Verdacht trägt. Zehn parallele
``/steps`` mit ``calendar.create`` (``mode='allow'``, also ohne Bestätigung)
ergaben **zehn Kalendereinträge**, zehn Invocations, zehnmal ``200 executed``.

Der Prüfer nahm an, ``calendar.create`` sei durch die Bestätigung abgeschirmt.
Das hängt an der erteilten Berechtigung: Bei ``allow`` läuft es im sauberen Lauf
direkt durch.

**Das Muster ist bekannt, und zwar aus diesem Projekt.** Die Einmaligkeit hing
schon dreimal einen Schritt zu früh — an der Nonce statt an der Ausführung, an
der Autorisierung statt am Aufruf, an der Ausstellung statt an der Verwendung.
Hier hängt sie einen Schritt zu **spät**: Der Anspruch entsteht, nachdem die
Wirkung eingetreten ist.

**Was hier geprüft wird und was nicht.**

``/advance`` ist der Pfad, an dem „genau einmal" eine Bedeutung hat: Der Plan
sagt, dieser Schritt geschieht *einmal*. Er bekommt deshalb einen Anspruch.

``/steps`` bekommt keinen. Dort nennt der Aufrufer das Werkzeug, und das ist
ein ausdrücklicher Befehl — zweimal „lege den Termin an" ist zweimal ein
Termin, so wie zweimal auf „Senden" zu drücken zweimal sendet. Wer das
zusammenfassen will, braucht einen Idempotency-Key vom Aufrufer, und das ist
eine andere Zusage als ein Anspruch auf einen geplanten Schritt. Ein Test hält
den Unterschied fest, damit er eine Entscheidung bleibt und nicht ein
Versehen wird.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from webauthn.helpers import base64url_to_bytes

from jarvis_api.main import create_app
from tests.authenticator import SoftwareAuthenticator
from tests.integration.test_http_runs import (
    MAIL_PRAEFIX,
    _angemeldet,
    _mit_kalenderrecht,
)

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

TERMIN = {
    "title": "Abstimmung",
    "start": "2026-09-01T10:00:00+00:00",
    "end": "2026-09-01T11:00:00+00:00",
}


async def _mehrere_sitzungen(
    client: AsyncClient, engine: AsyncEngine, *, anzahl: int
) -> tuple[uuid.UUID, list[str]]:
    """Ein Nutzer, ``anzahl`` Sitzungen — und der Grund, warum das nötig ist.

    **Der Befund war lange durch einen Zufall verdeckt.** Jede Sitzungsprüfung
    schreibt ``last_seen_at`` in *dieselbe* Zeile, und zwar in der Transaktion
    des Requests, die bis zu dessen Ende offen bleibt. Das ist ein Zeilen-Lock:
    Zwei Requests derselben Sitzung laufen dadurch hintereinander, ohne dass
    das jemand so entworfen hätte.

    Ein Test mit einem Cookie misst deshalb nicht die Nebenläufigkeit, sondern
    diesen Nebeneffekt — und besteht, solange er hält. Mehrere Sitzungen sind
    kein konstruierter Sonderfall: zwei Geräte, zwei Browserfenster, ein
    Wiederholungsversuch nach erneuter Anmeldung.
    """
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users"))

    start = await client.post(
        "/auth/bootstrap",
        json={"email": f"{MAIL_PRAEFIX}{uuid.uuid4()}@example.test", "display_name": "Läufer"},
    )
    assert start.status_code == 201, start.text
    authenticator = SoftwareAuthenticator()
    fertig = await client.post(
        "/auth/register/finish",
        json={
            "credential": authenticator.register(
                bytes(base64url_to_bytes(start.json()["challenge"]))
            ),
            "challenge": start.json()["challenge"],
            "device_label": "Testgerät",
        },
    )
    assert fertig.status_code == 201, fertig.text

    tokens: list[str] = []
    for _ in range(anzahl):
        anmeldung = await client.post("/auth/login/start", json={})
        ende = await client.post(
            "/auth/login/finish",
            json={
                "credential": authenticator.authenticate(
                    bytes(base64url_to_bytes(anmeldung.json()["challenge"]))
                ),
                "challenge": anmeldung.json()["challenge"],
            },
        )
        assert ende.status_code == 200, ende.text
        tokens.append(str(client.cookies.get("jarvis_session")))
    assert len(set(tokens)) == anzahl, "Jede Anmeldung muss eine eigene Sitzung ergeben."

    ich = await client.get("/auth/me")
    return uuid.UUID(ich.json()["user_id"]), tokens


async def _parallel(run_id: str, tokens: list[str], koerper: dict) -> list:
    """Ein Request je Sitzung, gleichzeitig — jeder mit eigenem Client.

    Eigener Client je Sitzung, damit kein geteilter Cookie-Jar die Token
    überschreibt; die Identität kommt aus dem Bearer-Header.
    """

    async def einer(token: str):
        async with AsyncClient(
            transport=ASGITransport(app=create_app()), base_url="http://test"
        ) as eigener:
            return await eigener.post(
                f"/runs/{run_id}/advance",
                json=koerper,
                headers={"Authorization": f"Bearer {token}"},
            )

    return await asyncio.gather(*(einer(t) for t in tokens), return_exceptions=True)


async def _zaehlung(engine: AsyncEngine, user_id: uuid.UUID, run_id: str) -> tuple[int, int, list]:
    async with engine.begin() as conn:
        termine = (
            await conn.execute(
                text("SELECT count(*) FROM calendar_events WHERE user_id = :u"), {"u": user_id}
            )
        ).scalar_one()
        invocations = (
            await conn.execute(
                text(
                    "SELECT count(*) FROM tool_invocations "
                    "WHERE run_id = :r AND status = 'executed'"
                ),
                {"r": uuid.UUID(run_id)},
            )
        ).scalar_one()
        zustand = (
            await conn.execute(
                text("SELECT state FROM runs WHERE id = :r"), {"r": uuid.UUID(run_id)}
            )
        ).scalar_one()
    return termine, invocations, [s["seq"] for s in (zustand or {}).get("completed_steps", [])]


async def _lauf_mit_terminschritt(client: AsyncClient, engine: AsyncEngine) -> str:
    """Ein Lauf, dessen **erster** fälliger Schritt schreibend ist.

    Nicht ``files.read`` davor: Ein lesender erster Schritt kontaminiert den
    Lauf, und der Termin danach wäre bestätigungspflichtig. Dann prüfte der
    Test die Bestätigung und nicht den Anspruch.
    """
    lauf = await client.post("/runs", json={"input": "Blockier mir eine Stunde am Dienstag"})
    run_id = lauf.json()["id"]
    sicht = await client.get(f"/runs/{run_id}")
    faellig = [s for s in sicht.json()["plan"] if s["status"] == "ready"]
    assert faellig and faellig[0]["target"] == "calendar.create", sicht.json()["plan"]
    return str(run_id)


class TestAnspruchAufEinenPlanschritt:
    @pytest.mark.invariant("plan-step-claimed-before-effect")
    async def test_zehn_parallele_advance_ergeben_einen_termin(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der Kern des Befunds.

        Zehn Requests, ein geplanter Schritt, ein Kalendereintrag. Geprüft wird
        die **Wirkung** und nicht die Antwort: Was der Endpunkt zurückgibt,
        könnte höflich sein und trotzdem doppelt gewirkt haben.
        """
        user_id, tokens = await _mehrere_sitzungen(client, engine, anzahl=6)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)

        antworten = await _parallel(run_id, tokens, {"arguments": TERMIN})

        termine, ausgefuehrt, erledigt = await _zaehlung(engine, user_id, run_id)
        assert termine == 1, (
            f"{termine} Kalendereinträge aus einem geplanten Schritt. Der Anspruch auf "
            "den Schritt muss **vor** der Wirkung stehen, nicht danach."
        )
        assert ausgefuehrt == 1, f"{ausgefuehrt} ausgeführte Invocations für einen Schritt."
        assert erledigt == [1], erledigt

        # Genau ein Gewinner, und die Verlierer sagen, was los war.
        erfolge = [
            a
            for a in antworten
            if not isinstance(a, BaseException)
            and a.status_code == 200
            and a.json()["status"] == "executed"
        ]
        assert len(erfolge) == 1, f"{len(erfolge)} Requests meldeten Erfolg."

    @pytest.mark.invariant("plan-step-claimed-before-effect")
    async def test_der_verlierer_bekommt_einen_grund_und_keinen_serverfehler(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Ein belegter Schritt ist ein Konflikt, kein Absturz.

        409 und nicht 500: Der Aufrufer hat nichts falsch gemacht — er war
        zweiter. Die Meldung muss ihm sagen, was er tun kann.
        """
        user_id, tokens = await _mehrere_sitzungen(client, engine, anzahl=5)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)

        antworten = await _parallel(run_id, tokens, {"arguments": TERMIN})
        for a in antworten:
            assert not isinstance(a, BaseException), a
            assert a.status_code in {200, 409}, (a.status_code, a.text)

    async def test_nach_dem_schritt_geht_der_naechste_wieder(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Gegenprobe.

        Ein Anspruch, der nicht freigegeben wird, ist eine Sperre. Nach dem
        abgeschlossenen Schritt muss der Plan weiterlaufen — sonst hätte der
        Test oben auch mit einem kaputten Lauf bestanden.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)

        erst = await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})
        assert erst.status_code == 200, erst.text
        assert erst.json()["status"] == "executed"

        sicht = await client.get(f"/runs/{run_id}")
        staende = {s["seq"]: s["status"] for s in sicht.json()["plan"]}
        assert staende[1] == "done", staende
        assert staende[2] == "ready", (
            "Der Anspruch muss nach dem Schritt wieder frei sein — sonst ist er eine Sperre."
        )

    async def test_ein_gescheiterter_schritt_blockiert_den_plan_nicht(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """**Der unangenehme Fall, und der Grund, warum ein Anspruch heikel ist.**

        Ein Schritt, der abgewiesen wird, hat nicht gewirkt. Bliebe der Anspruch
        stehen, wäre der Lauf für immer blockiert — und zwar durch die
        Maßnahme, die ihn schützen sollte. Eine Sperre, die man nicht mehr
        loswird, ist schlimmer als ein doppelter Termin.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)

        # Argumente, die an der Schemaprüfung scheitern — vor jeder Wirkung.
        daneben = await client.post(f"/runs/{run_id}/advance", json={"arguments": {"titel": "X"}})
        assert daneben.status_code == 200, daneben.text
        assert daneben.json()["code"] == "arguments-invalid", daneben.json()

        # Und danach geht es weiter.
        nochmal = await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})
        assert nochmal.status_code == 200, nochmal.text
        assert nochmal.json()["status"] == "executed", (
            "Nach einem folgenlos gescheiterten Schritt muss derselbe Schritt erneut "
            "versucht werden können."
        )


class TestDerDirekteSchrittBekommtKeinenAnspruch:
    """Die bewusste Ausnahme — und deshalb festgehalten.

    ``/steps`` nennt das Werkzeug im Request. Das ist ein ausdrücklicher Befehl,
    und zweimal befohlen ist zweimal ausgeführt — wie zweimal auf „Senden".
    Diesen Pfad einmalig zu machen hieße, „lies Datei A" und danach „lies Datei
    B" zu verhindern.

    Wer doppelte Absendungen zusammenfassen will, braucht einen
    Idempotency-Key **vom Aufrufer**; das ist eine andere Zusage und steht auf
    der Liste (Provider-Block). Dieser Test hält fest, dass der Unterschied eine
    Entscheidung ist und kein Versehen.
    """

    async def test_zwei_ausdrueckliche_befehle_wirken_zweimal(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        lauf = await client.post("/runs", json={"input": "Blockier mir eine Stunde"})
        run_id = lauf.json()["id"]

        for _ in range(2):
            antwort = await client.post(
                f"/runs/{run_id}/steps",
                json={"tool": "calendar.create", "arguments": TERMIN},
            )
            assert antwort.status_code == 200, antwort.text
            assert antwort.json()["status"] == "executed"

        termine, _, _ = await _zaehlung(engine, user_id, run_id)
        assert termine == 2, (
            "Zwei ausdrückliche Befehle ergeben zwei Termine. Wäre das nicht so, "
            "ließe sich dasselbe Werkzeug nicht zweimal mit anderen Argumenten aufrufen."
        )


class TestFehlerNachDerWirkung:
    """**Der Anspruch darf nicht zurück, sobald etwas geschehen sein kann.**

    Zweiter Prüfbefund zu derselben Stelle, und er sitzt genau dort, wo der
    erste behoben wurde: Der Anspruch stand danach zwar *vor* der Wirkung — aber
    ein Fehler *nach* der Wirkung gab ihn wieder frei.

    Nachgemessen: Handler legt den Termin an, ``runs.save()`` scheitert, die
    Ausnahme läuft nach oben, der Anspruch wird freigegeben, der Wiederholer
    sieht denselben Schritt als fällig — **zwei Termine.**

    Kein Replay desselben Grants: Der alte bleibt verbraucht, der zweite
    Versuch bekommt eine eigene Invocation und einen eigenen Grant. Der
    Einmaligkeitsanspruch am Grant greift hier gar nicht; er sichert *einen
    Aufruf*, nicht *einen Planschritt*.

    **Die Richtung ist höchstens einmal.** Ist unklar, ob gewirkt wurde, bleibt
    der Schritt beansprucht und der Lauf steht. Ein Termin, der vielleicht
    fehlt, lässt sich erneut anstoßen; einer, der zweimal im Kalender steht,
    nicht.
    """

    @staticmethod
    def _speichern_scheitert(monkeypatch, *, beim: int = 1):
        """Lässt ``runs.save`` genau einmal scheitern — nach dem Handler.

        Ein echter Ausfall an dieser Stelle ist keine Erfindung: eine
        abgerissene Verbindung, ein Serialisierungsfehler, ein ``RunStateConflict``
        aus einem parallelen Schreiber. Für eine Sicherheitszusage genügt ein
        erreichbarer Fehlerpfad.
        """
        from jarvis_api.db.run_store import PostgresRunStore

        echt = PostgresRunStore.save
        zaehler = {"n": 0}

        async def kaputt(self, run, *, erwarteter_status, claim_id=None):
            zaehler["n"] += 1
            if zaehler["n"] == beim:
                raise RuntimeError("Verbindung weg — nach dem Handler, vor dem Commit des Laufs.")
            return await echt(self, run, erwarteter_status=erwarteter_status, claim_id=claim_id)

        monkeypatch.setattr(PostgresRunStore, "save", kaputt)

    @pytest.mark.invariant("plan-step-claimed-before-effect")
    async def test_ein_fehler_nach_der_wirkung_gibt_den_anspruch_nicht_zurueck(
        self, client: AsyncClient, engine: AsyncEngine, monkeypatch
    ) -> None:
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)

        self._speichern_scheitert(monkeypatch)

        with pytest.raises(Exception, match="Verbindung weg"):
            await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})

        termine, _, _ = await _zaehlung(engine, user_id, run_id)
        assert termine == 1, "Der Handler lief einmal — das ist der Ausgangspunkt."

        async with engine.begin() as conn:
            zustand = (
                await conn.execute(
                    text("SELECT state FROM runs WHERE id = :r"), {"r": uuid.UUID(run_id)}
                )
            ).scalar_one()
        assert zustand.get("current_step") == 1, (
            "Der Anspruch muss stehen bleiben. Gibt ihn ein Fehler nach der Wirkung "
            "zurück, legt der nächste Versuch denselben Termin ein zweites Mal an."
        )

    @pytest.mark.invariant("plan-step-claimed-before-effect")
    async def test_der_wiederholer_bekommt_keinen_zweiten_termin(
        self, client: AsyncClient, engine: AsyncEngine, monkeypatch
    ) -> None:
        """Die Wirkung des Befunds, nicht nur sein Zustand.

        Geprüft wird der Kalender und nicht das Zustandsfeld: Ein Anspruch, der
        richtig aussieht und trotzdem einen zweiten Termin zulässt, hätte den
        Test darüber bestanden.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)

        self._speichern_scheitert(monkeypatch)
        with pytest.raises(Exception, match="Verbindung weg"):
            await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})

        # Der Wiederholer — genau das, was ein Client oder ein Worker täte.
        wieder = await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})
        assert wieder.status_code == 409, (
            f"Der Wiederholer darf nicht ausführen, sondern muss den belegten Schritt "
            f"vorfinden. Bekam: {wieder.status_code} {wieder.text[:200]}"
        )

        termine, _, _ = await _zaehlung(engine, user_id, run_id)
        assert termine == 1, (
            f"{termine} Termine nach einem Wiederholungsversuch. Der Anspruch auf einen "
            "Planschritt muss eine mögliche Wirkung überleben."
        )
