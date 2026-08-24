"""Der Ausgang aus ``ENTSCHEIDUNG NÖTIG`` — und seine vier Bedingungen.

Die Wiederaufnahme erzeugt absichtlich einen Zustand, aus dem kein Automat
herausführt: Ist die Frist abgelaufen und schließt das Werkzeugprotokoll eine
Wirkung **nicht** aus, bleibt der Schritt gesperrt. Das ist richtig — und war
eine Sackgasse, weil es keinen Übergang heraus gab.

**Der Übergang ist selbst eine Sicherheitsgrenze**, und diese Datei prüft
genau das. Wer entscheidet, hebt die Sperre auf, die vor einem doppelten
Seiteneffekt schützt; vier Bedingungen tragen sie:

* **Eigentümer** — und zwar auch dann, wenn der Fremde das richtige
  Fencing-Token kennt.
* **Vermerk** — ein Schritt, der bloß *läuft*, ist nicht auflösbar. Am
  Protokoll allein sind die beiden nicht zu unterscheiden; unterscheidbar
  macht sie die Frist, und die hat die Datenbank geprüft, bevor der Vermerk
  entstand.
* **Fencing** — entschieden wird gegen den Anspruch, den der Entscheidende vor
  sich sieht. Ein veraltetes Token entscheidet über eine Lage, die es nicht
  mehr gibt.
* **Atomar** — zwei gleichzeitige Entscheidungen ergeben eine.

**Warum das hier steht und nicht in einem Unit-Test.** Die entscheidende
Zusage ist eine ``WHERE``-Klausel: Die Freigabe des Anspruchs *ist* die
Bedingung des ``UPDATE``. Ein Nachbau in Python prüfte eine andere Behauptung.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.run_store import PostgresRunStore
from jarvis_api.main import create_app
from jarvis_contracts import RunStatus
from tests.integration.test_http_runs import _angemeldet, _fremder_lauf, _mit_kalenderrecht
from tests.integration.test_step_claim import TERMIN, _lauf_mit_terminschritt
from tests.integration.test_wiederaufnahme import _altern_lassen, _termine

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]


async def _unklarer_schritt(client: AsyncClient, engine: AsyncEngine) -> tuple[str, uuid.UUID, str]:
    """Ein Lauf, dessen Schritt möglicherweise gewirkt hat — über den echten Weg.

    Nachgestellt und nicht gesetzt: Der Anspruch wird beansprucht, das
    Protokoll bekommt einen Eintrag, der den Handler betreten hat, und die
    Frist läuft ab. Den Vermerk schreibt daraufhin die Wiederaufnahme selbst —
    ausgelöst durch ein gewöhnliches ``advance``, das daran scheitert.

    Ein von Hand gesetzter Vermerk prüfte den Endpunkt und nicht den Weg
    dorthin; er entstünde in keinem Betriebsfall so.
    """
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

    abgewiesen = await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})
    assert abgewiesen.status_code == 409, abgewiesen.text

    sicht = (await client.get(f"/runs/{run_id}")).json()
    offen = sicht["unresolved"]
    assert offen is not None, "Ohne Vermerk hätte der Lauf keinen Ausgang."
    return run_id, uuid.UUID(offen["claim_id"]), offen["description"]


class TestWasDerMenschZuSehenBekommt:
    async def test_die_sicht_nennt_was_gemeint_war_und_was_niemand_weiss(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """**Die eigentliche Frage vor jeder Entscheidung: woran erkenne ich es?**

        Das System kann nicht nachsehen — es gibt keinen lesenden Zugriff auf
        den Kalender. Eine Ansicht, die das verschweigt, lüde zu einer
        Entscheidung ein, die auf nichts beruht. Also steht dort, was es
        tatsächlich gibt: die Absicht aus dem Plan, der Versuch aus dem
        Protokoll — und der Vorbehalt als Satz.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id, _, beschreibung = await _unklarer_schritt(client, engine)

        offen = (await client.get(f"/runs/{run_id}")).json()["unresolved"]

        assert offen["step_seq"] == 1
        assert offen["tool"] == "calendar.create"
        assert offen["attempts"] == ["effect_unknown"], offen
        assert beschreibung, "Ohne die Absicht aus dem Plan weiß niemand, wonach er sucht."
        assert "nicht, was daraus geworden ist" in offen["caveat"]

    async def test_ein_gesunder_lauf_zeigt_keinen_offenen_vorgang(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Gegenprobe: Ohne Vermerk kein Angebot zu entscheiden."""
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)

        assert (await client.get(f"/runs/{run_id}")).json()["unresolved"] is None


class TestDieDreiEntscheidungen:
    async def test_verbucht_schliesst_den_schritt_ab_und_der_lauf_geht_weiter(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """„Ich habe nachgesehen, es ist geschehen."

        Der Schritt gilt als erledigt, **ohne** dass er noch einmal wirkt: Ein
        zweiter Termin wäre genau das, wovor die Sperre schützt.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id, claim_id, _ = await _unklarer_schritt(client, engine)

        antwort = await client.post(
            f"/runs/{run_id}/resolve",
            json={"decision": "completed", "claim_id": str(claim_id)},
        )

        assert antwort.status_code == 200, antwort.text
        assert antwort.json()["resolution"] == "completed"
        sicht = (await client.get(f"/runs/{run_id}")).json()
        assert sicht["unresolved"] is None
        assert [s["status"] for s in sicht["plan"] if s["seq"] == 1] == ["done"]
        assert await _termine(engine, user_id) == 0, (
            "Verbuchen ist keine Ausführung — es hält fest, was ein Mensch gesehen hat."
        )

    async def test_wiederholen_gibt_den_anspruch_frei_und_der_schritt_laeuft(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Entscheidung mit dem Risiko — und deshalb die eines Menschen.

        Danach läuft der Schritt wie ein gewöhnlicher: Der Anspruch ist frei,
        ``advance`` beansprucht ihn neu. Ob damit ein zweiter Termin entsteht,
        weiß niemand — das ist die Lage, nicht ein Mangel der Umsetzung.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id, claim_id, _ = await _unklarer_schritt(client, engine)

        antwort = await client.post(
            f"/runs/{run_id}/resolve", json={"decision": "retry", "claim_id": str(claim_id)}
        )
        assert antwort.status_code == 200, antwort.text
        assert "ein zweites Mal" in antwort.json()["detail"]

        wieder = await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})

        assert wieder.status_code == 200, wieder.text
        assert wieder.json()["status"] == "executed", wieder.json()
        assert await _termine(engine, user_id) == 1

    async def test_abbrechen_beendet_den_lauf_und_nimmt_nichts_zurueck(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id, claim_id, _ = await _unklarer_schritt(client, engine)

        antwort = await client.post(
            f"/runs/{run_id}/resolve", json={"decision": "abort", "claim_id": str(claim_id)}
        )

        assert antwort.status_code == 200, antwort.text
        assert antwort.json()["run_status"] == "cancelled"
        assert "nimmt nichts zurück" in antwort.json()["detail"]
        assert (await client.get(f"/runs/{run_id}")).json()["status"] == "cancelled"

    async def test_ein_freier_zielstatus_ist_nicht_vorgesehen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Genau drei Entscheidungen — und keine vierte über die Hintertür.

        Ein Endpunkt, der einen Zielzustand entgegennimmt, hätte den
        Zustandsautomaten abgeschafft, den er schützen soll.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id, claim_id, _ = await _unklarer_schritt(client, engine)

        antwort = await client.post(
            f"/runs/{run_id}/resolve", json={"decision": "completed_", "claim_id": str(claim_id)}
        )

        assert antwort.status_code == 422, antwort.text


class TestWerEntscheidenDarf:
    @pytest.mark.invariant("uncertain-effect-resolved-only-by-owner")
    async def test_ein_fremder_entscheidet_nicht_einmal_mit_dem_richtigen_token(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """**Der schärfste Fall dieser Datei.**

        Der Angreifer meldet sich ordentlich an und kennt das Fencing-Token des
        fremden Vorgangs — die stärkste Annahme, die man ihm zugestehen kann.
        Es hilft ihm nicht: Die Zugehörigkeit wird vor allem anderen geprüft,
        und die Antwort ist ``404``. Ein ``403`` bestätigte die Existenz des
        Laufs und machte fremde Kennungen aufzählbar.
        """
        await _angemeldet(client, engine)
        _, fremde_lauf_id = await _fremder_lauf(engine)
        fremdes_token = uuid.uuid4()
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE runs SET status = 'executing', state = state || jsonb_build_object("
                    "  'current_step', 1, 'claim_id', CAST(:c AS text), "
                    "  'claimed_at', to_jsonb(now()), 'unresolved_step', 1"
                    ") WHERE id = :r"
                ),
                {"r": fremde_lauf_id, "c": str(fremdes_token)},
            )

        antwort = await client.post(
            f"/runs/{fremde_lauf_id}/resolve",
            json={"decision": "completed", "claim_id": str(fremdes_token)},
        )

        assert antwort.status_code == 404, antwort.text
        async with engine.begin() as conn:
            stand = (
                await conn.execute(
                    text("SELECT state ->> 'unresolved_step' FROM runs WHERE id = :r"),
                    {"r": fremde_lauf_id},
                )
            ).scalar_one()
        assert stand == "1", "Der fremde Vorgang steht unverändert."

    async def test_ohne_anmeldung_gar_nicht(self, client: AsyncClient, engine: AsyncEngine) -> None:
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id, claim_id, _ = await _unklarer_schritt(client, engine)

        async with AsyncClient(
            transport=ASGITransport(app=create_app()), base_url="http://test"
        ) as ohne:
            antwort = await ohne.post(
                f"/runs/{run_id}/resolve",
                json={"decision": "completed", "claim_id": str(claim_id)},
            )

        assert antwort.status_code == 401, antwort.text


class TestGegenWelchenVorgang:
    @pytest.mark.invariant("uncertain-effect-resolved-only-by-owner")
    async def test_ein_veraltetes_token_entscheidet_nichts(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Eine Browserseite, die den Vorgang von vorhin vor sich hat.

        Läuft die Frist erneut ab, übernimmt der nächste Durchgang den Schritt
        und vergibt ein **neues** Token. Die Lage sieht danach gleich aus und
        ist eine andere. Ohne diese Bindung löste die alte Seite einen Vorgang
        auf, den es so nicht mehr gibt.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id, altes_token, _ = await _unklarer_schritt(client, engine)

        # Die Frist läuft erneut ab, ein zweiter Durchgang übernimmt.
        await _altern_lassen(engine, uuid.UUID(run_id), timedelta(hours=1))
        await client.post(f"/runs/{run_id}/advance", json={"arguments": TERMIN})
        neues_token = (await client.get(f"/runs/{run_id}")).json()["unresolved"]["claim_id"]
        assert neues_token != str(altes_token), "Die Übernahme vergibt ein neues Token."

        antwort = await client.post(
            f"/runs/{run_id}/resolve",
            json={"decision": "retry", "claim_id": str(altes_token)},
        )

        assert antwort.status_code == 409, antwort.text
        assert (await client.get(f"/runs/{run_id}")).json()["unresolved"] is not None

    @pytest.mark.invariant("uncertain-effect-resolved-only-by-owner")
    async def test_ein_laufender_schritt_ist_nicht_aufloesbar(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """**Ohne Vermerk keine Entscheidung — auch mit gültigem Token.**

        Ein Schritt, der gerade läuft, trägt denselben Protokolleintrag wie
        einer, der mitten in der Wirkung abgestürzt ist; der Eintrag entsteht
        *vor* dem Handler. Wäre der Vermerk eine Rechnung des Lesers statt ein
        Befund der Datenbank, böte die Oberfläche „noch einmal versuchen" für
        einen Schritt an, der gerade in Ordnung läuft — und das Ergebnis wäre
        genau der doppelte Termin.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id = await _lauf_mit_terminschritt(client, engine)
        speicher = PostgresRunStore(engine)
        laufend = await speicher.claim_step(
            uuid.UUID(run_id), 1, erwarteter_status=RunStatus.QUEUED
        )
        assert laufend is not None

        antwort = await client.post(
            f"/runs/{run_id}/resolve",
            json={"decision": "completed", "claim_id": str(laufend)},
        )

        assert antwort.status_code == 409, antwort.text
        async with engine.begin() as conn:
            noch_beansprucht = (
                await conn.execute(
                    text("SELECT state ->> 'claim_id' FROM runs WHERE id = :r"),
                    {"r": uuid.UUID(run_id)},
                )
            ).scalar_one()
        assert noch_beansprucht == str(laufend), "Der laufende Anspruch bleibt unberührt."

    @pytest.mark.invariant("uncertain-effect-resolved-only-by-owner")
    async def test_zweimal_entscheiden_geht_nicht(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Entscheidung verbraucht den Anspruch, gegen den sie gilt.

        Deshalb trifft die zweite dieselbe Zeile nicht mehr — ohne eine eigene
        Prüfung dafür, und das ist der Punkt: Die Bedingung steht in der
        Anweisung, die schreibt.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id, claim_id, _ = await _unklarer_schritt(client, engine)

        erste = await client.post(
            f"/runs/{run_id}/resolve", json={"decision": "retry", "claim_id": str(claim_id)}
        )
        zweite = await client.post(
            f"/runs/{run_id}/resolve", json={"decision": "abort", "claim_id": str(claim_id)}
        )

        assert erste.status_code == 200, erste.text
        assert zweite.status_code == 409, zweite.text
        assert (await client.get(f"/runs/{run_id}")).json()["status"] != "cancelled", (
            "Die zweite Entscheidung hat den Lauf nicht mehr angefasst."
        )

    @pytest.mark.invariant("uncertain-effect-resolved-only-by-owner")
    async def test_zwei_gleichzeitige_entscheidungen_ergeben_eine(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Zwei Geräte, derselbe Vorgang, im selben Moment.

        Beide sehen dasselbe Token und dürfen es beide sehen — der Nutzer ist
        derselbe. Genau deshalb entscheidet nicht die Ansicht, sondern das
        ``UPDATE``: Die Freigabe des Anspruchs *ist* seine Bedingung.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id, claim_id, _ = await _unklarer_schritt(client, engine)
        keks = client.cookies

        async def entscheiden(wahl: str):
            async with AsyncClient(
                transport=ASGITransport(app=create_app()),
                base_url="http://test",
                cookies=keks,
            ) as eigener:
                return await eigener.post(
                    f"/runs/{run_id}/resolve",
                    json={"decision": wahl, "claim_id": str(claim_id)},
                )

        antworten = await asyncio.gather(
            entscheiden("completed"), entscheiden("abort"), return_exceptions=True
        )

        codes = sorted(a.status_code for a in antworten)
        assert codes == [200, 409], [getattr(a, "text", a) for a in antworten]


class TestDieSpur:
    async def test_die_entscheidung_steht_im_audit(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Wer eine Sperre gegen doppelte Wirkung aufhebt, hinterlässt eine Spur.

        Wer später fragt, warum ein Termin zweimal im Kalender steht, findet
        hier die Antwort — mit Zeitpunkt, Person und Entscheidung.
        """
        user_id = await _angemeldet(client, engine)
        await _mit_kalenderrecht(engine, user_id=user_id)
        run_id, claim_id, _ = await _unklarer_schritt(client, engine)

        await client.post(
            f"/runs/{run_id}/resolve", json={"decision": "retry", "claim_id": str(claim_id)}
        )

        async with engine.begin() as conn:
            eintrag = (
                await conn.execute(
                    text(
                        "SELECT details FROM audit_log WHERE action = 'run.step_resolved' "
                        "AND resource = :r"
                    ),
                    {"r": run_id},
                )
            ).scalar_one()
        details = eintrag if isinstance(eintrag, dict) else json.loads(eintrag)
        assert details["decision"] == "retry", details
        assert details["step_seq"] == "1", details
