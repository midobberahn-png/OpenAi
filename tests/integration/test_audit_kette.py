"""Die Audit-Kette im Betrieb — nicht als Mechanik, sondern als Spur.

**Der Befund vor diesem Block:** Die Kette war vollständig gebaut und wurde
nirgends benutzt. ``AuditEntry``, ``compute_entry_hash``, ``verify_chain``, der
Port, die Tabelle, der Append-Only-Trigger — alles vorhanden und getestet;
``ToolExecutor(audit=...)`` bekam in der gesamten Anwendung ``None``.

Das ist die unangenehmste Sorte Lücke, weil sie nach außen wie Vollständigkeit
aussieht: Wer Kette, Trigger und Unit-Tests liest, schließt daraus, dass
protokolliert wird. Geprüft war die Mechanik, nicht ihr Betrieb.

Diese Suite prüft deshalb ausschließlich den Betrieb, und zwar an vier Fragen:

1. Entsteht überhaupt ein Eintrag, wenn etwas geschieht?
2. Hält die Kette, wenn zehn Dinge gleichzeitig geschehen?
3. **Wird ein Eingriff erkannt?** Das ist die eigentliche Zusage — eine Kette,
   die eine Manipulation nicht meldet, ist Zierrat.
4. Lässt die Datenbank den Eingriff überhaupt zu? (Sie soll nicht.)
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.audit_store import PostgresAuditSink
from jarvis_core.audit.chain import AuditEntry
from jarvis_core.clock import utc_now
from tests.integration.test_http_runs import _angemeldet

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

TERMIN = {
    "title": "Fokuszeit",
    "start": "2026-09-12T09:00:00+00:00",
    "end": "2026-09-12T10:00:00+00:00",
}


async def _am_trigger_vorbei(engine: AsyncEngine, sql: str, parameter: dict) -> None:
    """Führt eine Änderung am Append-Only-Trigger vorbei aus.

    Nachgestellt wird jemand, der die Datenbank besitzt — anders lässt sich
    nicht prüfen, ob die Kette einen solchen Eingriff *erkennt*. Der Trigger
    wird unmittelbar danach wieder eingeschaltet, auch wenn die Anweisung
    scheitert: Ein Test, der die Append-Only-Zusage abgeschaltet zurückließe,
    nähme jeder folgenden Prüfung ihre Grundlage.
    """
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER trg_audit_log_append_only"))
        try:
            await conn.execute(text(sql), parameter)
        finally:
            await conn.execute(
                text("ALTER TABLE audit_log ENABLE TRIGGER trg_audit_log_append_only")
            )


def _eintrag(nummer: int, user_id: uuid.UUID | None = None) -> AuditEntry:
    return AuditEntry(
        occurred_at=utc_now(),
        actor="jarvis",
        action="test.eintrag",
        resource=f"nr-{nummer}",
        details={"nummer": nummer},
        user_id=user_id,
    )


class TestEsEntstehenEintraege:
    @pytest.mark.invariant("audit-chain-records-what-happened")
    async def test_eine_werkzeugausfuehrung_hinterlaesst_eine_spur(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """**Der Befund, gemessen.** Vor der Verdrahtung blieb die Tabelle leer.

        Geprüft wird über HTTP und an der Tabelle: Was die Anwendung tatsächlich
        schreibt, sagt keine Attrappe.
        """
        user_id = await _angemeldet(client, engine)
        await client.put("/permissions/calendar.create", json={"mode": "allow"})

        lauf = await client.post("/runs", json={"input": "Blockier mir eine Stunde"})
        schritt = await client.post(
            f"/runs/{lauf.json()['id']}/steps",
            json={"tool": "calendar.create", "arguments": TERMIN},
        )
        assert schritt.json()["status"] == "executed", schritt.json()

        async with engine.begin() as conn:
            aktionen = [
                z.action
                for z in await conn.execute(
                    text("SELECT action FROM audit_log WHERE user_id = :u ORDER BY id"),
                    {"u": user_id},
                )
            ]
        assert "tool.executed" in aktionen, f"Keine Spur der Ausführung: {aktionen}"

    @pytest.mark.invariant("audit-chain-records-what-happened")
    async def test_eine_rechteerweiterung_steht_als_solche_darin(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Wer sich Rechte erschleicht, räumt danach auf — deshalb gehört gerade
        dieser Vorgang in die verkettete Spur und nicht nur ins Betriebslog.

        Und die **Richtung** steht im Namen der Aktion: ``permission.granted``
        heißt erweitert, ``permission.set`` heißt geändert oder verschärft.
        """
        user_id = await _angemeldet(client, engine)

        await client.put("/permissions/calendar.create", json={"mode": "allow"})
        await client.put("/permissions/calendar.create", json={"mode": "deny"})

        async with engine.begin() as conn:
            zeilen = [
                (z.action, z.resource, z.details)
                for z in await conn.execute(
                    text(
                        "SELECT action, resource, details FROM audit_log "
                        "WHERE user_id = :u AND action LIKE 'permission.%' ORDER BY id"
                    ),
                    {"u": user_id},
                )
            ]
        assert [a for a, _, _ in zeilen] == ["permission.granted", "permission.set"], zeilen
        assert zeilen[1][2]["vorher"] == "allow", "Der alte Modus fehlt — die Änderung ist unklar."

    async def test_das_zurueckziehen_ebenfalls(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        user_id = await _angemeldet(client, engine)
        await client.put("/permissions/calendar.create", json={"mode": "allow"})

        await client.delete("/permissions/calendar.create")

        async with engine.begin() as conn:
            aktionen = [
                z.action
                for z in await conn.execute(
                    text("SELECT action FROM audit_log WHERE user_id = :u ORDER BY id"),
                    {"u": user_id},
                )
            ]
        assert aktionen[-1] == "permission.revoked", aktionen


class TestDieKetteHaelt:
    @pytest.mark.invariant("audit-chain-records-what-happened")
    async def test_zehn_gleichzeitige_eintraege_gabeln_die_kette_nicht(
        self, engine: AsyncEngine
    ) -> None:
        """Ohne Serialisierung lesen zwei Schreiber denselben Vorgänger.

        Aus einer Kette werden dann zwei Stränge, und die Prüfung meldet einen
        Bruch, den niemand verursacht hat. ``pg_advisory_xact_lock`` hält das
        auseinander — gegen echte Nebenläufigkeit und nicht gegen ein
        Wörterbuch in einem Prozess.
        """
        senke = PostgresAuditSink(engine)

        await asyncio.gather(*(senke.append(_eintrag(i)) for i in range(10)))

        brueche = await senke.verify()
        assert brueche == [], f"Die Kette ist gebrochen: {[str(b) for b in brueche]}"

    async def test_ein_ausschnitt_meldet_keinen_bruch_am_anfang(self, engine: AsyncEngine) -> None:
        """Eine Teilprüfung hat einen Anfang, und dessen Vorgänger liegt außerhalb.

        Ohne Rücksicht darauf meldete jede Teilprüfung genau einen Bruch — und
        eine Prüfung, die immer einen Fund meldet, wird nach drei Tagen
        ignoriert.
        """
        senke = PostgresAuditSink(engine)
        for i in range(5):
            await senke.append(_eintrag(i))

        assert await senke.verify(limit=2) == []


class TestEinEingriffWirdErkannt:
    """Die eigentliche Zusage. Alles andere ist Buchhaltung."""

    async def test_die_datenbank_laesst_eine_aenderung_gar_nicht_zu(
        self, engine: AsyncEngine
    ) -> None:
        """Erst der Trigger, dann die Kette — zwei Verteidigungslinien.

        Wer die Anwendung kompromittiert, kommt an der Tabelle nicht vorbei;
        wer die Datenbank direkt manipuliert, hinterlässt einen Kettenbruch.
        """
        senke = PostgresAuditSink(engine)
        await senke.append(_eintrag(1))

        async with engine.begin() as conn:
            letzte = (await conn.execute(text("SELECT max(id) FROM audit_log"))).scalar_one()

        with pytest.raises(Exception, match="append-only"):
            async with engine.begin() as conn:
                await conn.execute(
                    text("UPDATE audit_log SET action = 'harmlos' WHERE id = :i"), {"i": letzte}
                )

        with pytest.raises(Exception, match="append-only"):
            async with engine.begin() as conn:
                await conn.execute(text("DELETE FROM audit_log WHERE id = :i"), {"i": letzte})

    @pytest.mark.invariant("audit-chain-records-what-happened")
    async def test_eine_am_trigger_vorbei_geaenderte_zeile_faellt_auf(
        self, engine: AsyncEngine
    ) -> None:
        """**Der Kern.**

        Der Trigger wird hier ausdrücklich abgeschaltet — nachgestellt wird
        jemand, der die Datenbank besitzt. Genau für diesen Fall ist die Kette
        da: Verhindern kann sie nichts, erkennen alles.

        **Und der Test räumt auf.** Die erste Fassung ließ die Zeile verändert
        zurück; die Kette ist eine *globale* Struktur, und jede spätere Prüfung
        in derselben Datenbank fand den Bruch von hier. Zwei Tests schlugen
        fehl, die nichts falsch machten. Der Ausweg ist nicht, weniger zu
        prüfen, sondern den Zustand wiederherzustellen — und die
        Wiederherstellung ist zugleich die Gegenprobe: Danach ist die Kette
        wieder unversehrt.
        """
        senke = PostgresAuditSink(engine)
        for i in range(3):
            await senke.append(_eintrag(i))

        async with engine.begin() as conn:
            mitte, vorher = (
                await conn.execute(
                    text("SELECT id, action FROM audit_log ORDER BY id DESC LIMIT 1 OFFSET 1")
                )
            ).one()

        try:
            await _am_trigger_vorbei(
                engine, "UPDATE audit_log SET action = 'harmlos' WHERE id = :i", {"i": mitte}
            )

            brueche = await senke.verify()

            assert brueche, "Eine veränderte Zeile blieb unbemerkt — die Kette ist wertlos."
            assert any(b.row_id == mitte for b in brueche), [str(b) for b in brueche]
            assert any("verändert" in b.reason for b in brueche), [str(b) for b in brueche]
        finally:
            await _am_trigger_vorbei(
                engine,
                "UPDATE audit_log SET action = :a WHERE id = :i",
                {"i": mitte, "a": vorher},
            )

        assert await senke.verify() == [], (
            "Nach der Wiederherstellung muss die Kette wieder halten — sonst prüft der "
            "Test etwas anderes, als er behauptet."
        )

    async def test_die_pseudonymisierung_bricht_die_kette_nicht(self, engine: AsyncEngine) -> None:
        """Die eine Änderung, die zugelassen ist — und der Grund für ihre Form.

        Eine DSGVO-Löschung setzt ``user_id`` auf ``NULL``. Ginge die Kennung in
        den Hash ein, zerrisse jede Nutzerlöschung die Kette und entwertete die
        Unveränderlichkeitszusage. Deshalb ist sie **nicht** Teil der Nutzlast —
        und deshalb lässt der Trigger genau diesen Fall durch.
        """
        senke = PostgresAuditSink(engine)
        nutzer = uuid.uuid4()
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Audit')"),
                {"i": nutzer, "m": f"audit-{nutzer}@example.test"},
            )
        await senke.append(_eintrag(1, user_id=nutzer))

        async with engine.begin() as conn:
            await conn.execute(
                text("UPDATE audit_log SET user_id = NULL WHERE user_id = :u"), {"u": nutzer}
            )

        assert await senke.verify() == []


class TestDerWegZumNachrechnen:
    @pytest.mark.invariant("audit-chain-records-what-happened")
    async def test_der_endpunkt_meldet_eine_unversehrte_kette(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Eine Kette, die niemand prüfen kann, ist eine Behauptung."""
        await _angemeldet(client, engine)
        await client.put("/permissions/calendar.create", json={"mode": "allow"})

        antwort = await client.get("/audit/verify")

        assert antwort.status_code == 200, antwort.text
        assert antwort.json()["intact"] is True, antwort.json()
        assert antwort.json()["checked"] > 0, (
            "Über einer leeren Tabelle ist jede Kette unversehrt — die Zahl gehört dazu."
        )

    async def test_das_protokoll_zeigt_die_eigenen_eintraege(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        await _angemeldet(client, engine)
        await client.put("/permissions/calendar.create", json={"mode": "allow"})

        antwort = await client.get("/audit")

        assert antwort.status_code == 200, antwort.text
        aktionen = [z["action"] for z in antwort.json()]
        assert "permission.granted" in aktionen, aktionen

    async def test_ohne_anmeldung_kein_protokoll(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        antworten = [await client.get("/audit"), await client.get("/audit/verify")]

        assert [a.status_code for a in antworten] == [401, 401]
