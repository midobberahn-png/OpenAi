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
from jarvis_api.tools import directory_lister_for, file_reader_for, tool_catalog
from jarvis_contracts import Run
from jarvis_core.agents import AgentRuntime, AgentStepSource
from jarvis_core.audit import DEFAULT_AUDIT_INTERVAL, ChainReport, ChainWatch
from jarvis_core.auth import SessionManager
from jarvis_core.orchestrator import (
    DEFAULT_IDLE,
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
from jarvis_integrations.web import HttpWebFetcher

__all__ = ["DEFAULT_INTERVALL", "chain_watch_for", "durchgang", "run_forever", "worker_for"]

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
    idle: timedelta = DEFAULT_IDLE,
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
                ordner=directory_lister_for(settings),
                # Der Eigentümer kommt aus dem Lauf, nicht aus einer Sitzung —
                # die einzige Stelle, an der sich diese Fassung von der
                # HTTP-Fassung unterscheidet.
                calendar=PostgresCalendarStore(engine, user_id=lauf.user_id),
                web=HttpWebFetcher(),
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
        idle=idle,
        batch=batch,
    )


def chain_watch_for(
    engine: AsyncEngine, *, intervall: timedelta = DEFAULT_AUDIT_INTERVAL
) -> ChainWatch:
    """Der Prüfer der Audit-Kette (ADR-018).

    ``PostgresAuditSink`` erfüllt den Port ``ChainInspector`` — lesen,
    nachrechnen, anfügen. Dass dieselbe Klasse daneben als ``AuditSink`` im
    Executor steckt, ist kein Widerspruch: Der Executor **hält** den schmaleren
    Port und kann deshalb nicht lesen, auch wenn das Objekt es könnte.
    """
    return ChainWatch(PostgresAuditSink(engine), intervall=intervall)


async def durchgang(kette: ChainWatch, arbeiter: RunWorker) -> None:
    """Ein Takt: erst nachrechnen, dann — vielleicht — wirken.

    Steht hier und nicht in der Schleife, weil es eine **Entscheidung** ist:
    Nach einem Kettenbruch findet kein Laufdurchgang mehr statt (ADR-018). In
    einer Schleife wäre dieselbe Zeile nicht prüfbar, ohne den Prozess laufen
    zu lassen — und was nicht geprüft wird, gilt nicht.

    Die Reihenfolge ist die Zusage: Ist die Prüfung fällig, läuft sie **vor**
    dem Durchgang. Ein Halt, der erst danach greift, käme einen Durchgang zu
    spät, und in diesem einen Durchgang ist das Wirken schon geschehen.
    """
    if kette.faellig():
        _melden_kette(await kette.pruefen())
    if kette.darf_wirken:
        _melden(await arbeiter.sweep())


async def run_forever(
    engine: AsyncEngine,
    settings: Settings,
    *,
    intervall: timedelta = DEFAULT_INTERVALL,
    lease: timedelta = DEFAULT_LEASE,
    audit_intervall: timedelta = DEFAULT_AUDIT_INTERVAL,
) -> None:
    """Prüfen, Durchgang, warten, wiederholen — bis jemand abbricht.

    Ein Durchgang, der scheitert, beendet die Schleife **nicht**: Der Zweck
    dieses Prozesses ist, dass er da ist, wenn etwas hängt. Ein Arbeiter, der
    sich beim ersten Datenbankfehler beendet, ist genau dann weg, wenn er
    gebraucht wird.

    **Die Kettenprüfung steht vor dem Durchgang und nicht daneben.** Ein Fund
    hält den Arbeiter an (ADR-018), und ein Halt, der erst nach dem Wirken
    greift, wäre einen Durchgang zu spät.

    **Scheitert die Prüfung selbst, wird nicht gewirkt — und zwar nicht nur in
    diesem Takt.** Dieser Satz stand hier schon, und er stimmte nur zur Hälfte:
    Die Prüfung galt nach einem Fehlschlag trotzdem als erledigt und war eine
    Stunde lang nicht mehr fällig, in der gewirkt wurde. Ein externes Review hat
    den Fail-open gefunden. Jetzt bleibt sie fällig, bis sie einmal durchläuft:
    Wer nicht nachrechnen kann, hat keinen Grund anzunehmen, dass die Kette
    hält.
    """
    _log.info(
        "Arbeiter gestartet: Takt %ss, Frist %ss, Kettenprüfung alle %ss",
        int(intervall.total_seconds()),
        int(lease.total_seconds()),
        int(audit_intervall.total_seconds()),
    )
    arbeiter = worker_for(engine, settings, lease=lease)
    kette = chain_watch_for(engine, intervall=audit_intervall)
    while True:
        try:
            await durchgang(kette, arbeiter)
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


def _melden_kette(bericht: ChainReport) -> None:
    """Was die Kettenprüfung ergeben hat.

    Anders als beim Laufdurchgang bleibt der stille Fall hier **nicht** still:
    Eine Prüfung, die im Erfolgsfall nichts hinterlässt, ist von einer Prüfung,
    die gar nicht läuft, nicht zu unterscheiden — und genau diese Verwechslung
    ist der Grund, warum es dieses Modul gibt. Sie läuft stündlich, nicht
    minütlich; das ist bezahlbar.
    """
    if bericht.unversehrt:
        _log.info("Audit-Kette unversehrt, %d Einträge geprüft.", bericht.geprueft)
        return

    for bruch in bericht.brueche:
        _log.error("Audit-Kette gebrochen: %s", bruch)
    _log.error(
        "Der Arbeiter wirkt ab jetzt nicht mehr: %d Bruch/Brüche in %d Einträgen "
        "(ADR-018). Ein Bruch heißt, dass jemand an der Anwendung vorbei an der "
        "Datenbank war.",
        len(bericht.brueche),
        bericht.geprueft,
    )
    if bericht.melde_fehler is not None:
        _log.error(
            "Der Fund konnte nicht in die Kette geschrieben werden: %s", bericht.melde_fehler
        )
