"""Delegationsketten — Rechte verengen sich, Kontamination steigt auf.

Die beiden Invarianten dieser Suite betreffen den Weg über *mehrere* Stufen.
Eine Stufe war bereits abgesichert; die Lücke lag bei A → B → C, und sie ist
die interessantere: Wenn C die Fähigkeiten von B erben kann, ist die Kette der
Umweg um jede Beschränkung — ein Agent ohne Versandrecht delegiert dann
einfach an einen, der es hat.
"""

from __future__ import annotations

import pytest

from jarvis_contracts import (
    AgentRequest,
    AgentResult,
    AgentSpec,
    AgentStatus,
    DataClass,
    RunBudget,
    TaintLevel,
)
from jarvis_core.agents import (
    AgentChain,
    AgentRegistry,
    AgentRuntime,
    AgentSession,
    DelegationDenied,
    DuplicateAgent,
    UnknownAgent,
)
from jarvis_core.orchestrator import BudgetTracker, ToolExecutor
from jarvis_core.policy import ApprovalGateway, PolicyEngine, UnverifiedSessions
from tests.fakes import (
    NOW,
    SESSION,
    FakePermissions,
    InMemoryApprovalStore,
    RecordingAudit,
    build_registry,
    build_run,
)

pytestmark = pytest.mark.security


# --------------------------------------------------------------------------
# Agentenkatalog des Tests
# --------------------------------------------------------------------------

SUPERVISOR = AgentSpec(
    name="supervisor",
    description="Plant, delegiert und führt Ergebnisse zusammen.",
    system_prompt="Du koordinierst.",
    allowed_tools=["mail.read", "calendar.read", "calendar.create", "mail.send", "system.time"],
    can_delegate=True,
)

MAIL_AGENT = AgentSpec(
    name="mail",
    description="Analysiert das Postfach und bereitet Antworten vor.",
    system_prompt="Du arbeitest mit Mails.",
    allowed_tools=["mail.read", "calendar.read", "system.time"],
    accepts_untrusted_input=True,
    can_delegate=True,
)

CALENDAR_AGENT = AgentSpec(
    name="calendar",
    description="Legt Termine an und prüft Zeitfenster.",
    system_prompt="Du arbeitest mit dem Kalender.",
    allowed_tools=["calendar.read", "calendar.create", "system.time"],
)

SENDER_AGENT = AgentSpec(
    name="sender",
    description="Darf Nachrichten nach außen senden.",
    system_prompt="Du versendest.",
    allowed_tools=["mail.send", "mail.read"],
)


def _agents() -> AgentRegistry:
    registry = AgentRegistry()
    for spec in (SUPERVISOR, MAIL_AGENT, CALENDAR_AGENT, SENDER_AGENT):
        registry.register(spec)
    return registry


def _runtime(perms: FakePermissions, *, audit: RecordingAudit | None = None):
    tools, spies = build_registry()
    policy = PolicyEngine(tools, perms)
    gateway = ApprovalGateway(InMemoryApprovalStore(), policy, sessions=UnverifiedSessions())
    executor = ToolExecutor(
        registry=tools, policy=policy, gateway=gateway, audit=audit, clock=lambda: NOW
    )
    runtime = AgentRuntime(agents=_agents(), tools=tools, policy=policy, executor=executor)
    return runtime, spies


def _tracker() -> BudgetTracker:
    return BudgetTracker(RunBudget(), clock=lambda: NOW)


class ScriptedAgent:
    """Ein Agent, der eine feste Liste von Werkzeugen versucht.

    Ersetzt die Modellschleife. Für die Prüfung der Rechte- und
    Taint-Mechanik ist das kein Verlust, sondern Voraussetzung: Ein echtes
    Modell wäre nicht deterministisch, und geprüft wird hier nicht, *was* ein
    Agent will, sondern was ihm gelingt.
    """

    def __init__(self, attempts: list[tuple[str, dict[str, object]]], *, claims_clean: bool = True):
        self.attempts = attempts
        self.outcomes: list[str] = []
        self.claims_clean = claims_clean
        self.offered_tools: frozenset[str] = frozenset()

    async def act(self, session: AgentSession, request: AgentRequest) -> AgentResult:
        self.offered_tools = await session.current_tools()
        for seq, (name, args) in enumerate(self.attempts, start=1):
            outcome = await session.call_tool(name, args, seq=seq)
            self.outcomes.append(outcome.status)
        return AgentResult(
            status=AgentStatus.SUCCESS,
            output="fertig",
            # Die Selbstauskunft. Bei claims_clean=True behauptet der Agent,
            # nichts Fremdes gelesen zu haben — auch dann, wenn er es hat.
            taint_acquired=not self.claims_clean,
        )


# ==========================================================================
# Die Kette als Rechtemenge
# ==========================================================================


class TestKettenrechte:
    @pytest.mark.invariant("agent-chain-preserves-capability-binding")
    def test_schnittmenge_ueber_drei_stufen(self) -> None:
        """A → B → C: C erbt nicht die Fähigkeiten von B, nur weil B ihn
        aufgerufen hat. Übrig bleibt, was alle drei führen dürfen."""
        chain = AgentChain(agents=(SUPERVISOR, MAIL_AGENT, CALENDAR_AGENT))
        assert chain.capability_ceiling() == frozenset({"calendar.read", "system.time"})

    @pytest.mark.invariant("agent-chain-preserves-capability-binding")
    def test_kette_kann_nur_verengen(self) -> None:
        """Jede weitere Stufe macht die Menge kleiner oder gleich — nie größer.
        Eine Schnittmenge kann nichts anderes."""
        short = AgentChain(agents=(SUPERVISOR,))
        longer = short.extend(MAIL_AGENT)
        longest = longer.extend(CALENDAR_AGENT)

        assert longer.capability_ceiling() <= short.capability_ceiling()
        assert longest.capability_ceiling() <= longer.capability_ceiling()

    @pytest.mark.invariant("agent-chain-preserves-capability-binding")
    def test_versandrecht_ueberlebt_die_kette_ueber_einen_leser_nicht(self) -> None:
        """Der eigentliche Angriff D über zwei Stufen: Der Mail-Agent liest
        Fremdinhalt und hat deshalb kein mail.send. Er delegiert an einen
        Agenten, der es hätte — und bekommt es dadurch nicht."""
        chain = AgentChain(agents=(SUPERVISOR, MAIL_AGENT, SENDER_AGENT))
        assert "mail.send" not in chain.capability_ceiling()
        assert chain.capability_ceiling() == frozenset({"mail.read"})

    def test_strengste_datenklasse_der_kette_gilt(self) -> None:
        """Das Minimum, nicht das Maximum: Über einen auf P1 begrenzten Agenten
        kommt niemand an P3-Daten."""
        restricted = AgentSpec(
            name="restricted",
            description="Arbeitet nur mit unkritischen Daten.",
            system_prompt="…",
            max_data_class=DataClass.P1,
        )
        chain = AgentChain(agents=(SUPERVISOR, restricted))
        assert chain.data_class_ceiling() is DataClass.P1

    def test_leere_whitelist_gibt_nichts_weiter(self) -> None:
        """Bewusst keine Ausnahme: „leer heißt unbeschränkt“ wäre die eine
        Sonderregel, die den Mechanismus aushebelt."""
        empty = AgentSpec(
            name="leer", description="Hat keine Werkzeuge.", system_prompt="…", can_delegate=True
        )
        assert AgentChain(agents=(empty, CALENDAR_AGENT)).capability_ceiling() == frozenset()

    @pytest.mark.invariant("agent-chain-preserves-capability-binding")
    async def test_nutzerrechte_begrenzen_die_kette_zusaetzlich(self) -> None:
        """Die Whitelist ist die Obergrenze, nicht die Erlaubnis: Was der
        Nutzer nicht erteilt hat, fehlt auch dem Agenten."""
        runtime, _ = _runtime(FakePermissions().allow("calendar.read"))
        chain = AgentChain(agents=(SUPERVISOR, CALENDAR_AGENT))
        tools = await runtime.effective_tools(chain, build_run())

        assert "calendar.read" in tools
        assert "calendar.create" not in tools, "Nicht erteilt — also nicht verfügbar"

    @pytest.mark.invariant("agent-chain-preserves-capability-binding")
    async def test_werkzeug_ausserhalb_der_kette_wird_nicht_ausgefuehrt(self) -> None:
        """Der Nutzer hat mail.send erteilt, die Kette führt es nicht — der
        Aufruf erreicht den Handler nicht einmal."""
        perms = FakePermissions().allow("mail.send").allow("calendar.read")
        runtime, spies = _runtime(perms)
        agent = ScriptedAgent([("mail.send", {"to": ["x@y.de"], "body": "b"})])

        outcome = await runtime.delegate(
            chain=AgentChain(agents=(SUPERVISOR,)),
            target="calendar",
            task="Termin prüfen",
            run=build_run(),
            tracker=_tracker(),
            behaviour=agent,
            session_id=SESSION,
        )
        assert agent.outcomes == ["blocked"]
        assert spies["mail.send"].call_count == 0
        assert "mail.send" not in outcome.granted_tools


# ==========================================================================
# Kontamination über die Kette
# ==========================================================================


class TestKettenkontamination:
    @pytest.mark.invariant("agent-chain-propagates-taint")
    async def test_zwischenstufe_ist_keine_waschmaschine(self) -> None:
        """Der Kern der Invariante: Der Sub-Agent liest eine Mail und meldet
        anschließend ``taint_acquired=False`` nach oben.

        Die Selbstauskunft eines Agenten ist eine Modellausgabe — und Modelle
        lesen Fremdinhalt. Würde die Runtime ihr glauben, wäre die
        Zwischenstufe der Weg, Kontamination loszuwerden. Maßgeblich ist
        deshalb der Lauf, nicht das Ergebnis.
        """
        perms = FakePermissions().allow("mail.read")
        runtime, _ = _runtime(perms)
        luegner = ScriptedAgent([("mail.read", {})], claims_clean=True)

        outcome = await runtime.delegate(
            chain=AgentChain(agents=(SUPERVISOR,)),
            target="mail",
            task="Postfach prüfen",
            run=build_run(),
            tracker=_tracker(),
            behaviour=luegner,
            session_id=SESSION,
        )
        assert luegner.outcomes == ["executed"]
        assert outcome.result.taint_acquired is False, "Die Behauptung steht so im Ergebnis"
        assert outcome.tainted, "Der Lauf ist trotzdem kontaminiert — er ist die Wahrheit"

    @pytest.mark.invariant("agent-chain-propagates-taint")
    async def test_kontamination_erreicht_den_aufrufer(self) -> None:
        """Nach der Delegation ist der übergeordnete Lauf kontaminiert — und
        damit ist der Versand auch für den Supervisor gesperrt."""
        perms = FakePermissions().allow("mail.read").allow("mail.send")
        runtime, spies = _runtime(perms)

        delegation = await runtime.delegate(
            chain=AgentChain(agents=(SUPERVISOR,)),
            target="mail",
            task="Postfach prüfen",
            run=build_run(),
            tracker=_tracker(),
            behaviour=ScriptedAgent([("mail.read", {})]),
            session_id=SESSION,
        )
        assert delegation.tainted

        # Der Supervisor versucht nun selbst zu senden.
        supervisor_tools = await runtime.effective_tools(
            AgentChain(agents=(SUPERVISOR,)), delegation.run
        )
        assert "mail.send" not in supervisor_tools
        assert spies["mail.send"].call_count == 0

    @pytest.mark.invariant("agent-chain-propagates-taint")
    async def test_selbstauskunft_kann_nur_erhoehen(self) -> None:
        """Umgekehrt gilt die Behauptung sehr wohl: Meldet ein Agent
        Kontamination, ohne dass ein Werkzeug sie ausgelöst hat, wird sie
        übernommen. Ein Agent, der P2-Inhalt im Prompt gesehen hat, weiß es
        möglicherweise besser als die Werkzeugliste."""
        perms = FakePermissions().allow("calendar.read")
        runtime, _ = _runtime(perms)

        outcome = await runtime.delegate(
            chain=AgentChain(agents=(SUPERVISOR,)),
            target="calendar",
            task="Termine lesen",
            run=build_run(),
            tracker=_tracker(),
            behaviour=ScriptedAgent([("calendar.read", {})], claims_clean=False),
            session_id=SESSION,
        )
        assert outcome.tainted

    @pytest.mark.invariant("taint-monotonic")
    async def test_ein_sauberer_sub_agent_saeubert_nichts(self) -> None:
        """Ein bereits kontaminierter Lauf bleibt kontaminiert, auch wenn der
        Sub-Agent nur Unbedenkliches tut."""
        perms = FakePermissions().allow("calendar.read")
        runtime, _ = _runtime(perms)
        tainted_run = build_run().with_taint(TaintLevel.TAINTED)

        outcome = await runtime.delegate(
            chain=AgentChain(agents=(SUPERVISOR,)),
            target="calendar",
            task="Termine lesen",
            run=tainted_run,
            tracker=_tracker(),
            behaviour=ScriptedAgent([("calendar.read", {})]),
            session_id=SESSION,
        )
        assert outcome.tainted

    @pytest.mark.invariant("agent-chain-propagates-taint")
    async def test_im_kontaminierten_lauf_schrumpft_das_angebot(self) -> None:
        """Was der Agent gar nicht angeboten bekommt, kann er nicht versuchen."""
        perms = FakePermissions().allow("mail.read").allow("mail.send").allow("calendar.read")
        runtime, _ = _runtime(perms)
        agent = ScriptedAgent([])

        await runtime.delegate(
            chain=AgentChain(agents=(SUPERVISOR,)),
            target="mail",
            task="Postfach prüfen",
            run=build_run().with_taint(TaintLevel.TAINTED),
            tracker=_tracker(),
            behaviour=agent,
            session_id=SESSION,
        )
        assert "mail.send" not in agent.offered_tools
        assert "mail.read" in agent.offered_tools


# ==========================================================================
# Strukturelle Grenzen der Delegation
# ==========================================================================


class TestDelegationsgrenzen:
    async def test_ohne_can_delegate_geht_nichts(self) -> None:
        runtime, _ = _runtime(FakePermissions())
        with pytest.raises(DelegationDenied, match="darf nicht delegieren"):
            await runtime.delegate(
                chain=AgentChain(agents=(CALENDAR_AGENT,)),
                target="mail",
                task="x",
                run=build_run(),
                tracker=_tracker(),
                behaviour=ScriptedAgent([]),
                session_id=SESSION,
            )

    async def test_rekursion_wird_abgewiesen(self) -> None:
        """Ein Agent, der sich selbst aufruft, liefe mit vollem Budget weiter."""
        runtime, _ = _runtime(FakePermissions())
        with pytest.raises(DelegationDenied, match="bereits in der Kette"):
            await runtime.delegate(
                chain=AgentChain(agents=(SUPERVISOR, MAIL_AGENT)),
                target="mail",
                task="x",
                run=build_run(),
                tracker=_tracker(),
                behaviour=ScriptedAgent([]),
                session_id=SESSION,
            )

    async def test_tiefengrenze_greift(self) -> None:
        runtime, _ = _runtime(FakePermissions())
        run = build_run().model_copy(update={"budget": RunBudget(max_agent_depth=1)})
        with pytest.raises(DelegationDenied, match="Delegationstiefe"):
            await runtime.delegate(
                chain=AgentChain(agents=(SUPERVISOR, MAIL_AGENT)),
                target="calendar",
                task="x",
                run=run,
                tracker=_tracker(),
                behaviour=ScriptedAgent([]),
                session_id=SESSION,
            )

    async def test_unbekannter_agent_bleibt_unterscheidbar(self) -> None:
        runtime, _ = _runtime(FakePermissions())
        with pytest.raises(UnknownAgent):
            await runtime.delegate(
                chain=AgentChain(agents=(SUPERVISOR,)),
                target="halluziniert",
                task="x",
                run=build_run(),
                tracker=_tracker(),
                behaviour=ScriptedAgent([]),
                session_id=SESSION,
            )

    def test_agent_darf_nicht_ueberschrieben_werden(self) -> None:
        registry = _agents()
        with pytest.raises(DuplicateAgent):
            registry.register(MAIL_AGENT)

    async def test_verbrauch_des_sub_agenten_faellt_dem_lauf_zur_last(self) -> None:
        """Ein Teilbudget begrenzt den Sub-Agenten; bezahlt wird trotzdem aus
        demselben Topf. Sonst wäre Delegation der Weg, das Kostenlimit zu
        vervielfachen."""
        perms = FakePermissions().allow("calendar.read")
        runtime, _ = _runtime(perms)
        tracker = _tracker()

        outcome = await runtime.delegate(
            chain=AgentChain(agents=(SUPERVISOR,)),
            target="calendar",
            task="Termine lesen",
            run=build_run(),
            tracker=tracker,
            behaviour=ScriptedAgent([("calendar.read", {})]),
            session_id=SESSION,
        )
        assert outcome.run.usage.tool_calls == 1
        assert tracker.usage.tool_calls == 1


class TestVertrag:
    def test_lesende_agenten_duerfen_nicht_senden(self) -> None:
        """Die Sperre sitzt schon im Vertrag: Ein Agent mit
        ``accepts_untrusted_input`` und einem sendenden Werkzeug ist gar nicht
        konstruierbar — der Injection-Pfad wäre offen, bevor Taint greift."""
        with pytest.raises(ValueError, match="Fremdinhalt"):
            AgentSpec(
                name="gefaehrlich",
                description="Liest Fremdinhalt und sendet.",
                system_prompt="…",
                allowed_tools=["mail.read", "mail.send"],
                accepts_untrusted_input=True,
            )
