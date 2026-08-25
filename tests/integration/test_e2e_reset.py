"""Das Aufräumskript der Browsertests — und warum es wartet.

**Der Befund:** Bei jedem Browserdurchgang standen sechs Tracebacks im
Gate-Protokoll (``ForeignKeyViolationError`` auf ``model_calls.run_id``). Die
Ursache war weder die Anwendung noch ein Wettlauf in ihr: Der Chat-Durchstich
endet absichtlich, während der Lauf noch arbeitet, und der **nächste** Test
räumte ihm mit ``DELETE FROM users`` die Welt unter den Füßen weg — Kaskade auf
``runs``, und die Hauptbuchzeile des noch laufenden Modellaufrufs fand ihren
Fremdschlüssel nicht mehr.

``ModelGateway._buchen()`` sagt zu, dass Schreibfehler durchschlagen, und genau
das tat es: Der Request endete mit 500, sichtbar im Protokoll. Alle 21
Browsertests blieben trotzdem grün — es war der Request eines Tests, dessen
Seite längst zu war.

Ein Gate, das Tracebacks druckt, erzieht dazu, Tracebacks zu übersehen; das hat
dieses Projekt 45 rote CI-Läufe gekostet. Diese Suite prüft deshalb die eine
Zusage, die das abstellt: **Wer die Welt löscht, wartet, bis niemand mehr an
einem Schritt arbeitet.**

Geprüft wird hier und nicht im Browserlauf, weil Playwright das Skript mit
``stdio: "pipe"`` aufruft und dessen Ausgabe verwirft: Ob dort je gewartet
wurde, ist am Gate-Protokoll nicht abzulesen. Zwei stille Durchgänge sind kein
Beweis — sie können auch bedeuten, dass gerade niemand gearbeitet hat.
"""

from __future__ import annotations

import time
import uuid
from datetime import timedelta

import pytest
from scripts.e2e_reset import _warten_bis_ruhe
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def _lauf_mit_anspruch(engine: AsyncEngine, *, alter: timedelta) -> uuid.UUID:
    """Ein Lauf, dessen Schritt seit ``alter`` beansprucht ist. Gibt den Nutzer zurück.

    Geschrieben wird unmittelbar und nicht über den Speicher: Gebraucht wird
    genau ein Feld, und der Weg über ``claim_step`` brächte Plan, Sitzung und
    Einstufung mit, die zur Frage nichts beitragen.

    ``alter`` ist ein ``timedelta`` und keine Zeichenkette: asyncpg bindet ein
    Intervall nicht aus ``'1 hour'`` — derselbe Fallstrick wie im Skript selbst,
    und er hat hier ein zweites Mal zugeschlagen.
    """
    nutzer = uuid.uuid4()
    lauf = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO users (id, email, display_name, created_at) "
                "VALUES (:i, :e, 'Ruhe-Test', now())"
            ),
            {"i": nutzer, "e": f"ruhe-{lauf}@example.test"},
        )
        # ``claimed_at`` kommt aus der Datenbank und nicht aus dem Prozess: Die
        # Bedingung vergleicht gegen ``now()`` derselben Uhr. Ein Wert von hier
        # machte den Test von der Uhrendrift der Colima-VM abhängig — genau der
        # Fehler, der die Leerlaufmessung eine Sitzung gekostet hat.
        await conn.execute(
            text(
                "INSERT INTO runs (id, user_id, trigger, status, budget, trace_id, state) "
                "VALUES (:i, :u, 'user', 'executing', '{}'::jsonb, :t, jsonb_build_object("
                "  'claimed_at', to_jsonb(now() - CAST(:alter AS interval))"
                "))"
            ),
            {"i": lauf, "u": nutzer, "t": uuid.uuid4().hex, "alter": alter},
        )
    return nutzer


async def _aufraeumen(engine: AsyncEngine, nutzer: uuid.UUID) -> None:
    """Über den Nutzer, weil die Kaskade den Lauf mitnimmt — dieselbe Kaskade,
    um die es in dieser Suite geht."""
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users WHERE id = :i"), {"i": nutzer})


class TestWerLoeschtWartet:
    async def test_ein_frischer_anspruch_haelt_das_loeschen_auf(self, engine: AsyncEngine) -> None:
        """Der Fall, der die Tracebacks erzeugt hat: Es wird gerade gearbeitet."""
        nutzer = await _lauf_mit_anspruch(engine, alter=timedelta(seconds=1))
        try:
            begonnen = time.monotonic()
            gewartet = await _warten_bis_ruhe(engine, geduld=0.4)
            tatsaechlich = time.monotonic() - begonnen

            assert gewartet >= 0.4, "Es wurde nicht gewartet, obwohl jemand arbeitet."
            assert tatsaechlich < 3.0, "Die Geduld ist eine Obergrenze, kein Vertrauen."
        finally:
            await _aufraeumen(engine, nutzer)

    async def test_ein_alter_anspruch_haelt_niemanden_auf(self, engine: AsyncEngine) -> None:
        """**Die wichtigere Hälfte.**

        ``e2e_haengenlassen.py`` setzt den Anspruch eine Stunde in die
        Vergangenheit — das ist der Zustand „jemand ist abgestürzt", und darauf
        zu warten hätte keinen Zweck. Ohne diese Unterscheidung zahlte jeder
        Test nach dem Entscheidungsdurchstich die volle Geduld.
        """
        nutzer = await _lauf_mit_anspruch(engine, alter=timedelta(hours=1))
        try:
            gewartet = await _warten_bis_ruhe(engine, geduld=5.0)

            assert gewartet < 0.5, f"Ein abgestürzter Lauf hat {gewartet:.1f}s gekostet."
        finally:
            await _aufraeumen(engine, nutzer)

    async def test_ohne_anspruch_wird_gar_nicht_gewartet(self, engine: AsyncEngine) -> None:
        """Die Gegenprobe — der Normalfall darf nichts kosten."""
        gewartet = await _warten_bis_ruhe(engine, geduld=5.0)

        assert gewartet < 0.5
