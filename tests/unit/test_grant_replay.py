"""Wiedervorlage eines echten Grants — der dritte Replay-Pfad.

Gefunden in der dritten externen Prüfrunde, hier nachgemessen und erweitert.

Die Vorgeschichte gehört dazu, weil sie sich wiederholt: Zuerst sicherte die
Nonce die *Bestätigung*, nicht die *Ausführung* — drei Aufrufe von
``authorize_execution()`` ergaben drei Grants. Behoben mit dem atomaren
``claim_execution()``. Der Anspruch sichert seitdem den Übergang

    bestätigte Aktion → ExecutionGrant

und **nur** diesen. Der Übergang danach ist ungesichert:

    ExecutionGrant → ToolRegistry.execute() → Handler

``ToolRegistry.execute()`` prüfte Herkunft, Hash, Lauf und Nutzer — alles
Eigenschaften, die bei einer Wiedervorlage desselben Objekts unverändert
gelten. Danach rief sie den Handler. Ein Verbrauch fehlte.

Dreimal dasselbe Muster: Die Einmaligkeit hing jedes Mal einen Schritt zu
früh. Deshalb prüfen diese Tests dort, wo die Wirkung entsteht — am
Handler-Zähler, nicht an der Zahl der ausgestellten Grants.

Geschlossen durch ``GrantConsumer``: ein Verbrauch an der ``invocation_id``,
als letzter Schritt vor dem Handler. Diese Tests entstanden **vor** der
Reparatur und schlugen alle vier fehl; sie sind der Grund, warum die Reparatur
so aussieht, wie sie aussieht — und nicht umgekehrt.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from jarvis_contracts import (
    ActionPreview,
    ApprovalChannel,
    DataClass,
    PolicyRequest,
    TaintLevel,
    ToolSpec,
)
from jarvis_core.policy import ApprovalGateway, PolicyEngine, UnverifiedSessions
from jarvis_core.tools import GrantAlreadyUsed, ToolRegistry
from tests.fakes import (
    FakePermissions,
    HandlerSpy,
    InMemoryApprovalStore,
    build_registry,
)

pytestmark = pytest.mark.security

NOW = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
USER = uuid4()


def _aufbau(werkzeug: str, *, scope_mode: str) -> tuple[ToolRegistry, HandlerSpy, ToolSpec, Any]:
    registry, spies = build_registry()
    spec = registry.require(werkzeug)
    perms = FakePermissions()
    for scope in spec.scopes:
        perms.allow(scope) if scope_mode == "allow" else perms.confirm(scope)
    gateway = ApprovalGateway(
        InMemoryApprovalStore(),
        PolicyEngine(registry, perms),
        sessions=UnverifiedSessions(),
        # Angehaltene Zeit, auch für den Ausführungsanspruch: Er misst seit dem
        # TOCTOU-Befund seine eigene, frische Zeit — gegen die echte Gegenwart
        # wäre eine Bestätigung dieser Suite abgelaufen, und die Suite prüfte
        # dann den Ablauf statt der Wiedervorlage.
        clock=lambda: NOW,
    )
    return registry, spies[werkzeug], spec, gateway


async def _bestaetigter_grant(
    gateway: Any, spec: ToolSpec, arguments: dict[str, Any], *, run_id: UUID
) -> Any:
    """Ein Grant auf dem vollen Weg: Anfrage → Bestätigung → Ausführungs-Gate.

    Ausdrücklich nicht über ``authorize_allowed()``. Auf jenem Pfad ist ein
    Grant beliebig oft neu zu bekommen, weil die Aktion gar keine Bestätigung
    braucht — eine Wiedervorlage belegte dort nichts über die Zusicherung
    „eine Bestätigung führt höchstens einmal aus".
    """
    session_id = uuid4()
    channel: ApprovalChannel = "ui"
    action = await gateway.request(
        spec=spec,
        arguments=arguments,
        preview=ActionPreview(tool_name=spec.name, title="Mail senden", risk=spec.risk),
        reason="Regressionstest",
        run_id=run_id,
        invocation_id=uuid4(),
        user_id=USER,
        session_id=session_id,
        channel=channel,
        now=NOW,
    )
    outcome = await gateway.respond(
        action_id=action.id,
        nonce=action.nonce,
        approve=True,
        user_id=USER,
        session_id=session_id,
        channel=channel,
        now=NOW,
    )
    assert outcome.approved, outcome.reason

    return await gateway.authorize_execution(
        action_id=action.id,
        arguments=arguments,
        spec=spec,
        taint=TaintLevel.CLEAN,
        run_id=run_id,
        allowed_data_class=DataClass.P2,
        now=NOW,
    )


class TestGrantWiedervorlage:
    """Ein ausgestellter Grant erlaubt genau einen Werkzeugaufruf."""

    @pytest.mark.invariant("grant-single-use")
    async def test_derselbe_grant_zweimal_fuehrt_einmal_aus(self) -> None:
        """Der Kern des Befundes.

        Der Zähler steht am Handler, nicht an der Zahl der Grants: Was zählt,
        ist wie oft die Mail hinausgeht — nicht wie oft eine Erlaubnis
        ausgestellt wurde.
        """
        registry, spy, spec, gateway = _aufbau("mail.send", scope_mode="confirm")
        run_id = uuid4()
        args = {"an": "chef@example.com", "text": "Bericht"}
        grant = await _bestaetigter_grant(gateway, spec, args, run_id=run_id)

        await registry.execute(grant, run_id=run_id, user_id=USER)
        with pytest.raises(GrantAlreadyUsed):
            await registry.execute(grant, run_id=run_id, user_id=USER)

        assert spy.call_count == 1, (
            f"Eine Bestätigung, {spy.call_count} Ausführungen. Der Ausführungsanspruch "
            "sichert die Ausstellung des Grants, nicht seine Verwendung."
        )

    @pytest.mark.invariant("grant-single-use")
    async def test_zehn_parallele_ausfuehrungen_gewinnt_genau_eine(self) -> None:
        """Wie beim Nonce-Verbrauch: Die Zusicherung muss unter Nebenläufigkeit
        halten, sonst ist sie eine Prüfung mit Zeitfenster."""
        registry, spy, spec, gateway = _aufbau("mail.send", scope_mode="confirm")
        run_id = uuid4()
        args = {"an": "chef@example.com", "text": "Bericht"}
        grant = await _bestaetigter_grant(gateway, spec, args, run_id=run_id)

        await asyncio.gather(
            *(registry.execute(grant, run_id=run_id, user_id=USER) for _ in range(10)),
            return_exceptions=True,
        )

        assert spy.call_count == 1, f"{spy.call_count} von 10 parallelen Aufrufen kamen durch."

    @pytest.mark.invariant("grant-single-use")
    async def test_kopien_des_grants_teilen_den_verbrauch(self) -> None:
        """Die Probe darauf, dass der Verbrauch nicht am Objekt hängt.

        Ein Flag im Grant wäre die naheliegende Reparatur und die falsche: Das
        Modell ist frozen, aber ``model_copy()``, ``copy`` und ``deepcopy``
        erzeugen jeweils einen unverbrauchten Zwilling. Der Verbrauch muss an
        etwas hängen, das die Kopie mitbringt — die ``invocation_id`` — und an
        einem Ort, den alle Kopien teilen.
        """
        registry, spy, spec, gateway = _aufbau("mail.send", scope_mode="confirm")
        run_id = uuid4()
        args = {"an": "chef@example.com", "text": "Bericht"}
        grant = await _bestaetigter_grant(gateway, spec, args, run_id=run_id)

        for zwilling in (grant, grant.model_copy(), copy.copy(grant), copy.deepcopy(grant)):
            # Die Ablehnung ist der erwartete Ausgang für drei der vier —
            # welcher zuerst durchkommt, ist gleichgültig, gezählt wird am
            # Handler.
            with contextlib.suppress(GrantAlreadyUsed):
                await registry.execute(zwilling, run_id=run_id, user_id=USER)

        assert spy.call_count == 1, (
            f"{spy.call_count} Ausführungen aus vier Kopien desselben Grants. Eine "
            "Kopie ist dieselbe Erlaubnis, nicht eine zweite."
        )


class TestGrantOhneBestaetigung:
    """Auch der bestätigungsfreie Pfad kennt eine Wiedervorlage.

    Der Ertrag für einen Angreifer ist hier geringer: Wer ``authorize_allowed()``
    aufrufen darf, bekommt jederzeit einen neuen Grant — die Erlaubnis ist auf
    diesem Pfad nicht knapp. Ein Unterschied bleibt trotzdem, und er ist der
    Grund für diesen Test: Ein **neuer** Grant entsteht aus einer frischen
    Policy-Prüfung, eine Wiedervorlage nicht. Ohne Verbrauch überlebt eine
    Erlaubnis den Entzug des Rechts, aus dem sie entstanden ist.
    """

    @pytest.mark.invariant("grant-single-use")
    async def test_wiedervorlage_ueberlebt_den_entzug_des_rechts_nicht(self) -> None:
        """Vorsicht bei der Deutung dieses Tests.

        Er belegt **nicht**, dass die Registry die Berechtigung erneut prüft —
        das tut sie nicht und soll sie nicht: Die Policy-Prüfung gehört ins
        Gate, nicht in den Katalog. Er belegt, dass die Frage sich nicht
        stellt, weil die zweite Vorlage schon am Verbrauch scheitert.

        Der Unterschied ist wichtig, weil genau hier zweimal etwas
        durchgerutscht ist: Ein Test, der grün ist, prüft nicht automatisch das,
        wonach er heißt. Der Entzug steht deshalb im Ablauf — als Beleg, dass
        der Verbrauch auch dann greift, wenn die Berechtigungslage sich
        geändert hat.
        """
        registry, spy, spec, gateway = _aufbau("calendar.read", scope_mode="allow")
        run_id = uuid4()
        args = {"zeitraum": "heute"}

        grant = await gateway.authorize_allowed(
            request=PolicyRequest(user_id=USER, run_id=run_id, tool_name=spec.name, arguments=args),
            spec=spec,
            taint=TaintLevel.CLEAN,
            invocation_id=uuid4(),
            now=NOW,
        )
        await registry.execute(grant, run_id=run_id, user_id=USER)

        # Das Recht wird entzogen — ein neuer Grant wäre ab jetzt nicht mehr zu
        # bekommen. Der alte darf es deshalb auch nicht sein.
        gateway._policy._permissions = FakePermissions()  # type: ignore[attr-defined]

        with pytest.raises(GrantAlreadyUsed):
            await registry.execute(grant, run_id=run_id, user_id=USER)

        assert spy.call_count == 1, (
            f"{spy.call_count} Ausführungen. Ein einmal ausgestellter Grant überlebt "
            "den Entzug des Rechts, aus dem er entstanden ist."
        )
