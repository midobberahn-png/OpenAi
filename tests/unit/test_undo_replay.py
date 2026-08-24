"""Wiedervorlage eines echten ``UndoGrant`` — derselbe Fehler, neue Stelle.

**Herkunft: externe Prüfung von ``61d4428``.** Der Bericht nennt es beim Namen:
„wieder genau das bekannte Muster ‚Einmaligkeit hängt einen Übergang zu früh‘ —
nur diesmal im gerade neu hinzugefügten Undo-Pfad."

Der erste Übergang ist gesichert. ``claim_undo()`` führt Zugehörigkeit, Status,
Frist und Anspruch in einem atomaren UPDATE zusammen; zwei gleichzeitige
``authorize()`` ergeben genau einen Grant:

    protokollierter Aufruf → UndoGrant        ✔ gesichert

Der zweite war es nicht:

    UndoGrant → ToolRegistry.undo() → Handler ✘ ungesichert

``undo()`` prüfte Herkunft, Nutzer und Implementierung — alles Eigenschaften,
die bei der **zweiten Vorlage desselben Objekts** unverändert gelten. Danach
rief sie den Handler.

Dass ein zweites Löschen desselben Termins folgenlos wäre, ist eine Eigenschaft
von ``calendar.create`` und keine des Weges. Undo ist als **generischer**
Mechanismus gebaut; das nächste Werkzeug bringt seine eigene Umkehrung mit, und
die muss nicht idempotent sein.

Diese Tests entstanden **vor** der Reparatur und schlugen fehl. Gemessen wird
am Handler-Zähler und nicht an der Zahl ausgestellter Grants — dort entsteht
die Wirkung.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
from datetime import UTC, datetime
from uuid import UUID

import pytest

from jarvis_contracts import RiskLevel, ToolResult, ToolSpec
from jarvis_core.policy import UndoGateway
from jarvis_core.ports.invocations import UndoClaim
from jarvis_core.tools import ToolRegistry
from jarvis_core.tools.registry import GrantAlreadyUsed, UnguardedExecution

pytestmark = [pytest.mark.security, pytest.mark.asyncio]

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
NUTZER = UUID("11111111-1111-1111-1111-111111111111")
AUFRUF = UUID("22222222-2222-2222-2222-222222222222")

LOESCHBAR = ToolSpec(
    name="calendar.create",
    description="Legt einen Termin an — und kann ihn zurücknehmen.",
    parameters={"type": "object"},
    scopes=["calendar.create"],
    risk=RiskLevel.MEDIUM,
    supports_undo=True,
)


class UndoSpy:
    """Zählt, wie oft die Rücknahme tatsächlich läuft."""

    def __init__(self) -> None:
        self.tokens: list[str] = []

    async def __call__(self, token: str) -> ToolResult:
        self.tokens.append(token)
        return ToolResult(ok=True, display="Zurückgenommen")

    @property
    def call_count(self) -> int:
        return len(self.tokens)


class EinmalAnspruch:
    """Der Speicher: ein Anspruch je Aufruf, ein Verbrauch je Anspruch.

    Bildet beide atomaren Schritte nach, die in PostgreSQL als bedingtes UPDATE
    stehen. Prozesslokal — die Zusage über Prozessgrenzen prüft
    ``tests/integration/test_undo.py`` gegen die echte Datenbank.
    """

    def __init__(self) -> None:
        self.beansprucht = False
        self.verbraucht = False

    async def claim_undo(self, invocation_id: UUID, *, user_id: UUID, now: datetime):
        if self.beansprucht:
            return None
        self.beansprucht = True
        return UndoClaim(tool_name="calendar.create", undo_token="termin-1")

    async def consume_undo(self, invocation_id: UUID, *, now: datetime) -> bool:
        if self.verbraucht:
            return False
        self.verbraucht = True
        return True


def _registry(speicher: EinmalAnspruch) -> tuple[ToolRegistry, UndoSpy]:
    spy = UndoSpy()
    registry = ToolRegistry(undo_grants=speicher)
    registry.register(LOESCHBAR, _nie_ausfuehren, undo=spy)
    return registry, spy


async def _nie_ausfuehren(**kwargs: object) -> ToolResult:  # pragma: no cover
    raise AssertionError("Diese Suite führt nichts aus — sie nimmt zurück.")


async def _grant(speicher: EinmalAnspruch):
    return await UndoGateway(speicher).authorize(AUFRUF, user_id=NUTZER, now=NOW)


class TestDerselbeGrantZweimal:
    @pytest.mark.invariant("undo-grant-single-use")
    async def test_seriell_erreicht_nur_einer_den_handler(self) -> None:
        """**Der Befund.**

        Ein einmal ausgestellter Grant ändert sich nicht: Typ, Nutzer und
        Werkzeugname gelten beim zweiten Mal unverändert. Wer ihn behält, nimmt
        zweimal zurück — solange nichts ihn verbraucht.
        """
        speicher = EinmalAnspruch()
        registry, spy = _registry(speicher)
        grant = await _grant(speicher)

        await registry.undo(grant, user_id=NUTZER)
        with pytest.raises(GrantAlreadyUsed):
            await registry.undo(grant, user_id=NUTZER)

        assert spy.call_count == 1

    @pytest.mark.invariant("undo-grant-single-use")
    async def test_zehn_parallel_erreicht_nur_einer_den_handler(self) -> None:
        """Nebenläufig, weil ein ``if verbraucht:`` genau hier durchfällt."""
        speicher = EinmalAnspruch()
        registry, spy = _registry(speicher)
        grant = await _grant(speicher)

        async def einer() -> None:
            with contextlib.suppress(GrantAlreadyUsed):
                await registry.undo(grant, user_id=NUTZER)

        await asyncio.gather(*(einer() for _ in range(10)))

        assert spy.call_count == 1, f"{spy.call_count} Rücknahmen aus einem Anspruch."

    @pytest.mark.invariant("undo-grant-single-use")
    async def test_eine_kopie_ist_derselbe_anspruch(self) -> None:
        """``copy``, ``deepcopy``, ``model_copy`` — drei Wege zum zweiten Objekt.

        Der Verbrauch hängt deshalb an der **Kennung des Aufrufs** und nicht am
        Objekt: Eine Kopie trägt dieselbe Kennung, und genau darauf zielt der
        Versuch.
        """
        speicher = EinmalAnspruch()
        registry, spy = _registry(speicher)
        grant = await _grant(speicher)

        await registry.undo(grant, user_id=NUTZER)
        for zwilling in (copy.copy(grant), copy.deepcopy(grant), grant.model_copy()):
            with pytest.raises(GrantAlreadyUsed):
                await registry.undo(zwilling, user_id=NUTZER)

        assert spy.call_count == 1


class TestOhneVerbraucherWirdNichtZurueckgenommen:
    @pytest.mark.invariant("undo-grant-single-use")
    async def test_eine_registry_ohne_undo_verbrauch_weist_ab(self) -> None:
        """Ein fehlender Sicherheitskontext muss schließen, nicht öffnen.

        Dieselbe Regel wie beim Ausführungs-Verbrauch: Ohne eingerichteten
        Verbrauch wäre derselbe Anspruch beliebig oft einlösbar, und das ist
        genau der Zustand, den diese Suite gemessen hat.
        """
        speicher = EinmalAnspruch()
        spy = UndoSpy()
        ohne = ToolRegistry()
        ohne.register(LOESCHBAR, _nie_ausfuehren, undo=spy)
        grant = await _grant(speicher)

        with pytest.raises(UnguardedExecution):
            await ohne.undo(grant, user_id=NUTZER)

        assert spy.call_count == 0


class TestDerAnspruchAmGateBleibt:
    async def test_zwei_ausstellungen_ergeben_einen_grant(self) -> None:
        """Die Gegenprobe: Der erste Übergang war und bleibt gesichert.

        Der neue Verbrauch ersetzt den Anspruch am Gate nicht, er kommt dazu —
        die beiden sichern verschiedene Übergänge.
        """
        speicher = EinmalAnspruch()
        await _grant(speicher)

        from jarvis_core.policy import UndoDenied

        with pytest.raises(UndoDenied):
            await _grant(speicher)
