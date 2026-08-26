"""Token-Rotation gegen die echte Datenbank — und der Wettlauf darin.

**Warum das nicht bei den Unit-Tests bleiben durfte.** Die Suite dort prüft die
Entscheidung an einer Attrappe: Sie zählt Ersatztoken und Ablehnungen und
belegt damit die Logik. Was sie *nicht* belegen kann, ist die Einmaligkeit
unter echter Nebenläufigkeit — dieselbe Lehre, die dieses Projekt beim
Grant-Verbrauch schon einmal gezogen hat: „Nebenläufigkeitstests belegen keine
Dauerhaftigkeit."

Der Kern der Zusage aus ADR-020 ist eine **Anweisung**, kein Ablauf:

    UPDATE sessions SET token_hash = :neu … WHERE id = :id AND token_hash = :alt

Ob die wirklich genau einmal trifft, wenn zehn Verbindungen gleichzeitig darauf
zielen, weiß nur Postgres. Deshalb hier, mit zehn eigenen Verbindungen.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.session_store import PostgresSessionStore
from jarvis_core.auth import SessionManager, SessionRejection, token_fingerprint

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)


async def _nutzer(engine: AsyncEngine) -> uuid.UUID:
    uid = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Rotation')"),
            {"i": uid, "m": f"{uid}@example.test"},
        )
    return uid


async def _token_altern(engine: AsyncEngine, sid: uuid.UUID, um: timedelta) -> None:
    """Lässt den **aktuellen** Token altern — auf der Uhr der Datenbank.

    Die Fristen dieser Bauart werden aus ``now()`` gerechnet; eine gestellte
    Prozessuhr erreicht sie nicht. Das ist keine Umständlichkeit des Tests,
    sondern die Folge der Entscheidung: Wer das Alter dort rechnet, wo der
    Zeitstempel steht, muss dort auch altern lassen. Dieselbe Technik wie in
    ``scripts/e2e_haengenlassen.py``.
    """
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE sessions SET created_at = now() - CAST(:um AS interval) WHERE id = :i"),
            {"i": sid, "um": um},
        )


async def _rotation_altern(engine: AsyncEngine, sid: uuid.UUID, um: timedelta) -> None:
    """Lässt die **Rotation** altern — damit das Überlappungsfenster abläuft."""
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE sessions SET rotated_at = now() - CAST(:um AS interval) WHERE id = :i"),
            {"i": sid, "um": um},
        )


async def _aufraeumen(engine: AsyncEngine, uid: uuid.UUID) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})


def _manager(engine: AsyncEngine, conn: object, **kw: object) -> SessionManager:
    """Der Manager mit dem **echten** Speicher.

    ``conn`` für Anlegen und Lesen, ``engine`` für alles, was eine eigene
    Transaktion braucht — Rotation und ``touch()``. Genau diese Trennung ist
    hier mit Prüfgegenstand: Eine Rotation in der Transaktion des Aufrufers
    wäre zurückrollbar, und der Client hätte ein Cookie ohne Zeile dahinter.
    """
    return SessionManager(
        PostgresSessionStore(conn, engine=engine),  # type: ignore[arg-type]
        **kw,  # type: ignore[arg-type]
    )


class TestDerWettlaufGegenPostgres:
    @pytest.mark.invariant("session-token-rotation")
    async def test_zehn_gleichzeitige_anfragen_erzeugen_genau_einen_ersatz(
        self, engine: AsyncEngine
    ) -> None:
        """**Der Kern.**

        Zehn Verbindungen, derselbe Token, gleichzeitig. Genau eine darf
        rotieren — und **keine** darf abgemeldet werden. Zwei Ersatztoken
        hießen: Der zweite überschreibt den ersten, und dessen Empfänger fliegt
        beim nächsten Aufruf raus.
        """
        uid = await _nutzer(engine)
        try:
            async with engine.begin() as conn:
                ausgestellt = await _manager(engine, conn).issue(uid, now=NOW)
            await _token_altern(engine, ausgestellt.session.id, timedelta(minutes=20))
            spaeter = NOW + timedelta(minutes=20)

            async def einer() -> object:
                # Eigene Verbindung je Aufruf — sonst prüfte der Test die
                # Serialisierung durch eine geteilte Transaktion und nicht die
                # Bedingung in der Anweisung.
                async with engine.connect() as conn:
                    manager = _manager(engine, conn, rotation_interval=timedelta(minutes=15))
                    return await manager.pruefen(ausgestellt.token, now=spaeter, rotieren=True)

            ergebnisse = await asyncio.gather(*(einer() for _ in range(10)))

            abgemeldet = [e for e in ergebnisse if e.session is None]  # type: ignore[attr-defined]
            ersatz = [e.neuer_token for e in ergebnisse if e.neuer_token is not None]  # type: ignore[attr-defined]

            assert not abgemeldet, (
                f"{len(abgemeldet)} von 10 gleichzeitigen Anfragen wurden abgemeldet — "
                "genau das ist der Grund, warum diese Invariante so lange lag."
            )
            assert len(ersatz) == 1, f"Genau einer darf rotieren, es waren {len(ersatz)}."
        finally:
            await _aufraeumen(engine, uid)

    @pytest.mark.invariant("session-token-rotation")
    async def test_der_ersatz_gilt_und_der_alte_im_fenster_auch(self, engine: AsyncEngine) -> None:
        """Beide Hälften an einer echten Zeile: Der neue Token öffnet, und der
        alte bleibt gültig, solange das Fenster steht."""
        uid = await _nutzer(engine)
        try:
            async with engine.begin() as conn:
                ausgestellt = await _manager(engine, conn).issue(uid, now=NOW)
            await _token_altern(engine, ausgestellt.session.id, timedelta(minutes=20))

            spaeter = NOW + timedelta(minutes=20)
            async with engine.connect() as conn:
                gedreht = await _manager(
                    engine, conn, rotation_interval=timedelta(minutes=15)
                ).pruefen(ausgestellt.token, now=spaeter, rotieren=True)
            assert gedreht.neuer_token is not None

            async with engine.connect() as conn:
                manager = _manager(engine, conn, overlap=timedelta(seconds=60))
                assert (await manager.pruefen(gedreht.neuer_token, now=spaeter)).session is not None
                im_fenster = await manager.pruefen(ausgestellt.token, now=spaeter)
                assert im_fenster.session is not None, (
                    "Eine Anfrage, die zum Zeitpunkt der Rotation schon unterwegs war, "
                    "darf nicht scheitern."
                )
        finally:
            await _aufraeumen(engine, uid)

    @pytest.mark.invariant("session-token-rotation")
    async def test_die_rotation_ueberlebt_einen_rollback(self, engine: AsyncEngine) -> None:
        """**Die Lehre aus dem Grant-Verbrauch, hier noch einmal.**

        Der Aufrufer rollt seine Transaktion zurück. Die Rotation hat trotzdem
        stattgefunden — sie lief in eigener Transaktion, und der neue Token ist
        beim Client bereits angekommen. Läge sie in der Transaktion des
        Requests, bekäme er ein Cookie, zu dem es keine Zeile gibt.
        """
        uid = await _nutzer(engine)
        try:
            async with engine.begin() as conn:
                ausgestellt = await _manager(engine, conn).issue(uid, now=NOW)
            await _token_altern(engine, ausgestellt.session.id, timedelta(minutes=20))
            spaeter = NOW + timedelta(minutes=20)

            async with engine.connect() as conn:
                gedreht = await _manager(
                    engine, conn, rotation_interval=timedelta(minutes=15)
                ).pruefen(ausgestellt.token, now=spaeter, rotieren=True)
                await conn.rollback()
            assert gedreht.neuer_token is not None

            async with engine.connect() as conn:
                zeile = (
                    await conn.execute(
                        text("SELECT token_hash FROM sessions WHERE id = :i"),
                        {"i": ausgestellt.session.id},
                    )
                ).scalar_one()
            assert zeile == token_fingerprint(gedreht.neuer_token)
        finally:
            await _aufraeumen(engine, uid)

    @pytest.mark.invariant("session-token-rotation")
    async def test_eine_kopie_nach_dem_fenster_beendet_die_sitzung(
        self, engine: AsyncEngine
    ) -> None:
        """Wiederverwendungserkennung an einer echten Zeile."""
        uid = await _nutzer(engine)
        try:
            async with engine.begin() as conn:
                ausgestellt = await _manager(engine, conn).issue(uid, now=NOW)
            await _token_altern(engine, ausgestellt.session.id, timedelta(minutes=20))
            spaeter = NOW + timedelta(minutes=20)

            async with engine.connect() as conn:
                gedreht = await _manager(
                    engine, conn, rotation_interval=timedelta(minutes=15)
                ).pruefen(ausgestellt.token, now=spaeter, rotieren=True)
            assert gedreht.neuer_token is not None

            # Das Fenster läuft ab — wieder auf der Uhr, die es rechnet.
            await _rotation_altern(engine, ausgestellt.session.id, timedelta(minutes=5))
            danach = spaeter + timedelta(seconds=61)
            async with engine.connect() as conn:
                fund = await _manager(engine, conn, overlap=timedelta(seconds=60)).pruefen(
                    ausgestellt.token, now=danach
                )
                assert fund.grund is SessionRejection.WIEDERVERWENDET

            async with engine.connect() as conn:
                manager = _manager(engine, conn, overlap=timedelta(seconds=60))
                assert await manager.verify(gedreht.neuer_token, now=danach) is None, (
                    "Nach einer erkannten Kopie muss die ganze Sitzung enden — sonst "
                    "arbeitet der Dieb mit dem neuen Token weiter, falls er auch den hat."
                )
        finally:
            await _aufraeumen(engine, uid)
