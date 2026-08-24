"""Der Arbeiter, zusammengesetzt — dieselben Teile wie die HTTP-Schicht.

``deps.py`` baut sie aus einem Request, hier entstehen sie aus einem **Lauf**.
Der Unterschied ist genau einer, und er ist die ganze Zusage dieses Moduls:

    HTTP:      Sitzung → Nutzer → Werkzeugkatalog → Ablauf
    Arbeiter:  Lauf    → Nutzer → Werkzeugkatalog → Ablauf

Woher der Eigentümer kommt, ändert sich; **dass** alles an ihm hängt, nicht.
Der Kalender wird an ``run.user_id`` gebunden, und ein Handler kann seinen
Adressaten nach wie vor nicht benennen — der Weg über einen fremden Kalender
ist auch hier nicht offen, sondern gar nicht vorhanden.

Was hier **fehlt**, ist die Sitzung, und dafür gibt es keinen Ersatz: Der
Arbeiter übergibt ``session_id=None``. Ein Schritt, der eine Bestätigung
braucht, wird nicht ausgeführt und erzeugt auch keine.

Zwei Fassungen, aus einem Grund getrennt:

* ``worker_for(engine, settings)`` baut den Arbeiter. Testbar, ohne dass etwas
  läuft — ein Durchgang ist ein Aufruf.
* ``run_forever(...)`` ist die Schleife darum. Sie enthält keine Entscheidung,
  nur einen Takt; deshalb steht in ihr auch nichts, was zu prüfen wäre.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.agents import agent_catalog
from jarvis_api.db.approval_store import PostgresApprovalStore
from jarvis_api.db.audit_store import PostgresAuditSink
from jarvis_api.db.calendar_store import PostgresCalendarStore
from jarvis_api.db.invocation_store import PostgresInvocationStore
from jarvis_api.db.permission_store import PostgresPermissionStore
from jarvis_api.db.run_store import PostgresRunStore
from jarvis_api.db.session_store import PostgresSessionStore
from jarvis_api.providers import model_gateway
from jarvis_api.settings import Settings
from jarvis_api.tools import file_reader_for, tool_catalog
from jarvis_contracts import Run
from jarvis_core.agents import AgentRuntime, AgentStepSource
from jarvis_core.auth import SessionManager
from jarvis_core.orchestrator import (
    DEFAULT_LEASE,
    PlanArgumentSource,
    PlanResponseSource,
    Recovery,
    RunAdvancer,
    RunWorker,
    SweepReport,
    ToolExecutor,
)
from jarvis_core.policy import ApprovalGateway, PolicyEngine

__all__ = ["DEFAULT_INTERVALL", "run_forever", "worker_for"]

DEFAULT_INTERVALL = timedelta(minutes=1)
"""Wie oft nachgesehen wird.

Deutlich kürzer als die Frist (15 Minuten) und deshalb kein zweiter Regler für
dieselbe Sache: Der Takt entscheidet, wie schnell ein überfälliger Lauf
*bemerkt* wird, die Frist entscheidet, ab wann er überfällig **ist**. Ein Takt
länger als die Frist verschöbe die Wiederaufnahme um bis zu einen Takt; ein
sehr kurzer kostet nur Abfragen, die nichts finden."""

_log = logging.getLogger("jarvis.worker")


def worker_for(
    engine: AsyncEngine,
    settings: Settings,
    *,
    lease: timedelta = DEFAULT_LEASE,
    batch: int = 20,
) -> RunWorker:
    """Ein Arbeiter, der seine Bestandteile je Lauf neu zusammensetzt."""

    @asynccontextmanager
    async def advancer_for(lauf: Run) -> AsyncIterator[RunAdvancer]:
        """Der Ablauf für **einen** Lauf, in **einer** Transaktion.

        ``engine.begin()`` entspricht der Transaktion des Requests in der
        HTTP-Fassung: Sie endet mit dem Lauf und rollt bei einer Ausnahme
        zurück. Was ausdrücklich *nicht* an ihr hängt, sind Anspruch,
        Werkzeugprotokoll und Grant-Verbrauch — die nehmen die Engine und
        committen für sich. Genau deshalb überstehen sie einen Absturz, und
        genau deshalb gibt es diesen Arbeiter überhaupt.
        """
        async with engine.begin() as conn:
            registry = tool_catalog(
                engine,
                files=file_reader_for(settings),
                # Der Eigentümer kommt aus dem Lauf, nicht aus einer Sitzung —
                # die einzige Stelle, an der sich diese Fassung von der
                # HTTP-Fassung unterscheidet.
                calendar=PostgresCalendarStore(engine, user_id=lauf.user_id),
            )
            policy = PolicyEngine(registry, PostgresPermissionStore(engine))
            invocations = PostgresInvocationStore(engine)
            runs = PostgresRunStore(engine)
            # Der echte ``SessionManager`` und nicht ``UnverifiedSessions``:
            # Der Arbeiter löst zwar keine Bestätigung ein, aber ein Gate mit
            # abgeschalteter Sitzungsbindung wäre ein Gate, das anders
            # entscheidet als das der HTTP-Schicht. Es soll dasselbe sein.
            approvals = ApprovalGateway(
                PostgresApprovalStore(conn),
                policy,
                sessions=SessionManager(PostgresSessionStore(conn)),
            )
            executor = ToolExecutor(
                registry=registry,
                policy=policy,
                gateway=approvals,
                invocations=invocations,
                # Auch und gerade der Arbeiter: Er wirkt ohne Menschen davor,
                # und ein Vorgang ohne Zeugen ist der, den man später sucht.
                audit=PostgresAuditSink(engine),
            )
            katalog = agent_catalog()
            yield RunAdvancer(
                runs=runs,
                tools=registry,
                policy=policy,
                executor=executor,
                arguments=PlanArgumentSource(gateway=model_gateway(settings)),
                responses=PlanResponseSource(gateway=model_gateway(settings)),
                # Auch der Arbeiter führt Agentenschritte aus — mit derselben
                # Grenze wie überall: ohne Sitzung entsteht keine Bestätigung.
                # Ein Sub-Agent, der ein bestätigungspflichtiges Werkzeug
                # vorschlägt, bekommt eine Ablehnung ins Gespräch zurück und
                # kann es anders versuchen.
                agents=AgentStepSource(
                    runtime=AgentRuntime(
                        agents=katalog, tools=registry, policy=policy, executor=executor
                    ),
                    agents=katalog,
                    gateway=model_gateway(settings),
                    tools=registry,
                ),
                recovery=Recovery(runs=runs, invocations=invocations, tools=registry, lease=lease),
            )

    return RunWorker(
        runs=PostgresRunStore(engine),
        advancer_for=advancer_for,
        lease=lease,
        batch=batch,
    )


async def run_forever(
    engine: AsyncEngine,
    settings: Settings,
    *,
    intervall: timedelta = DEFAULT_INTERVALL,
    lease: timedelta = DEFAULT_LEASE,
) -> None:
    """Durchgang, warten, wiederholen — bis jemand abbricht.

    Ein Durchgang, der scheitert, beendet die Schleife **nicht**: Der Zweck
    dieses Prozesses ist, dass er da ist, wenn etwas hängt. Ein Arbeiter, der
    sich beim ersten Datenbankfehler beendet, ist genau dann weg, wenn er
    gebraucht wird.
    """
    _log.info(
        "Arbeiter gestartet: Takt %ss, Frist %ss",
        int(intervall.total_seconds()),
        int(lease.total_seconds()),
    )
    arbeiter = worker_for(engine, settings, lease=lease)
    while True:
        try:
            _melden(await arbeiter.sweep())
        except asyncio.CancelledError:
            _log.info("Arbeiter beendet.")
            raise
        except Exception:
            _log.exception("Durchgang gescheitert — der nächste folgt.")
        await asyncio.sleep(intervall.total_seconds())


def _melden(bericht: SweepReport) -> None:
    """Ein stiller Durchgang bleibt still.

    Ein Arbeiter, der jede Minute „nichts gefunden" meldet, macht sein Protokoll
    unlesbar — und damit die eine Zeile unsichtbar, auf die es ankommt.
    """
    if bericht.gefunden == 0:
        return
    _log.info(
        "%d überfällige Läufe, %d fortgesetzt, %d liegen geblieben",
        bericht.gefunden,
        bericht.fortgesetzt,
        bericht.liegen_geblieben,
    )
    for ergebnis in bericht.ergebnisse:
        _log.info("  %s → %s: %s", ergebnis.run_id, ergebnis.outcome, ergebnis.detail)
