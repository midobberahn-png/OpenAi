"""Abhängigkeiten der HTTP-Schicht.

Hier liegt die Stelle, an der aus einem anonymen HTTP-Request eine Identität
wird — und zwar die **einzige** solche Stelle. Das ist die Invariante
``identity-derives-from-session``: Kein Endpunkt darf ``user_id`` oder
``session_id`` aus Body, Query, Header oder Pfad als autoritativ übernehmen.

Der Grund ist derselbe wie beim Executor: Wer die Identität mitbringt, bestimmt
sie. Ein Feld ``user_id`` in einem Request-Body sieht harmlos aus und ist der
kürzeste Weg zu einem fremden Konto — und von dort über Policy und Approval
zu einem ``ExecutionGrant``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from functools import lru_cache
from pathlib import Path
from typing import Annotated

import structlog
from fastapi import Depends, HTTPException, Request, Response, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from jarvis_api.agents import agent_catalog
from jarvis_api.auth import WebAuthnVerifier
from jarvis_api.db.account_store import PostgresAccountStore
from jarvis_api.db.approval_store import PostgresApprovalStore
from jarvis_api.db.audit_store import PostgresAuditSink
from jarvis_api.db.authorization_store import PostgresAuthorizationStore
from jarvis_api.db.calendar_store import PostgresCalendarReader, PostgresCalendarStore
from jarvis_api.db.credential_store import PostgresCredentialStore as PostgresOAuthCredentialStore
from jarvis_api.db.invocation_store import PostgresInvocationStore
from jarvis_api.db.permission_store import PostgresPermissionStore
from jarvis_api.db.run_store import PostgresRunStore
from jarvis_api.db.session import engine_for
from jarvis_api.db.session_store import PostgresSessionStore
from jarvis_api.db.spend_store import PostgresSpendReader
from jarvis_api.db.webauthn_store import PostgresChallengeStore, PostgresCredentialStore
from jarvis_api.events import RedisEventBus
from jarvis_api.mail import KontoGebundenerPostfachleser
from jarvis_api.providers import model_gateway
from jarvis_api.rate_limit_store import RedisRateLimitStore
from jarvis_api.settings import Settings, get_settings
from jarvis_api.token_service import TokenService
from jarvis_api.tools import directory_lister_for, file_reader_for, tool_catalog
from jarvis_contracts import Session
from jarvis_core.agents import AgentRuntime, AgentStepSource
from jarvis_core.auth import PasskeyService, SessionManager
from jarvis_core.limits import RateLimiter, RateLimitExceeded, RateLimitPolicy
from jarvis_core.orchestrator import (
    PlanArgumentSource,
    PlanResponseSource,
    ToolExecutor,
)
from jarvis_core.policy import ApprovalGateway, PolicyEngine
from jarvis_core.ports.keys import KeyProvider
from jarvis_core.ports.oauth import TokenExchange
from jarvis_core.tools import ToolRegistry
from jarvis_integrations import DateiSchluessel
from jarvis_integrations.oauth import HttpTokenExchange
from jarvis_integrations.web import HttpWebFetcher

__all__ = [
    "Accounts",
    "Agents",
    "Approvals",
    "Audit",
    "AuditReader",
    "Authorizations",
    "CalendarView",
    "Credentials",
    "CurrentSession",
    "DbConnection",
    "DbEngine",
    "Invocations",
    "Limiter",
    "ModelArguments",
    "ModelResponse",
    "Passkeys",
    "Permissions",
    "Policy",
    "Runs",
    "Schluessel",
    "SessionToken",
    "Sessions",
    "Spend",
    "TokenDienst",
    "Tokens",
    "Tools",
    "agent_step_source",
    "approval_gateway",
    "audit_sink",
    "calendar_view",
    "client_identifier",
    "current_session",
    "current_token",
    "db_connection",
    "db_engine",
    "dispose_redis",
    "event_bus",
    "invocation_store",
    "passkey_service",
    "permission_store",
    "plan_argument_source",
    "plan_response_source",
    "policy_engine",
    "rate_limited",
    "run_store",
    "session_manager",
    "spend_reader",
    "tool_registry",
]


_log = structlog.get_logger(__name__)

STROMPFAD = "/events"
"""Der Ereignisstrom — dort wird nicht rotiert (ADR-020 §6)."""


async def db_connection(
    settings: Annotated[Settings, Depends(get_settings)],
) -> AsyncIterator[AsyncConnection]:
    """Eine Verbindung mit Transaktion je Request.

    ``engine.begin()`` schließt die Transaktion beim Verlassen — bei einer
    Ausnahme mit Rollback. Ein Endpunkt, der auf halbem Weg scheitert,
    hinterlässt damit keine halbe Registrierung.
    """
    async with engine_for(settings.database_url).begin() as conn:
        yield conn


DbConnection = Annotated[AsyncConnection, Depends(db_connection)]


def db_engine(settings: Annotated[Settings, Depends(get_settings)]) -> AsyncEngine:
    """Die Engine selbst — für Speicher, die ihre eigene Transaktion brauchen.

    Neben ``DbConnection`` und nicht an ihrer Stelle. Der Unterschied ist
    bedeutungstragend und hat einen Befund als Ursache: Wer die Verbindung des
    Requests bekommt, schreibt in dessen Transaktion und kann mit ihr
    zurückgerollt werden. Für Lesevorgänge und für Zustand, der zum Request
    gehört, ist das richtig. Für einen Anspruch, der **vor** einer Wirkung nach
    außen gelten muss, ist es falsch — der vierte Replay-Pfad lag genau dort.

    Lauf, Werkzeugprotokoll und Grant-Verbrauch nehmen deshalb die Engine.
    """
    return engine_for(settings.database_url)


DbEngine = Annotated[AsyncEngine, Depends(db_engine)]


def run_store(engine: DbEngine) -> PostgresRunStore:
    return PostgresRunStore(engine)


Runs = Annotated[PostgresRunStore, Depends(run_store)]


def invocation_store(engine: DbEngine) -> PostgresInvocationStore:
    """Das Werkzeugprotokoll — eigene Transaktion je Eintrag.

    Die Engine und nicht die Request-Verbindung: Der Grant-Verbrauch hängt an
    der protokollierten Zeile und committet seinerseits eigenständig. Läge das
    Protokoll in der Request-Transaktion, fände er nichts.
    """
    return PostgresInvocationStore(engine)


Invocations = Annotated[PostgresInvocationStore, Depends(invocation_store)]


def audit_sink(engine: DbEngine) -> PostgresAuditSink:
    """Das Audit-Log — die Engine, nicht die Request-Verbindung.

    Ein Eintrag, der mit dem Request zurückgerollt wird, fehlt genau dann, wenn
    der Request nach einer Wirkung nach außen scheitert. Die Richtung ist:
    lieber ein Eintrag zu viel als einer zu wenig.
    """
    return PostgresAuditSink(engine)


Audit = Annotated[PostgresAuditSink, Depends(audit_sink)]

AuditReader = Annotated[PostgresAuditSink, Depends(audit_sink)]
"""Derselbe Adapter, anderer Name — und der Name ist die Absicht.

Wer ``Audit`` verlangt, schreibt; wer ``AuditReader`` verlangt, liest. Die
Trennung kostet nichts und macht in jeder Signatur sichtbar, was ein Endpunkt
mit dem Protokoll vorhat. Eine echte Trennung wären zwei Ports; die lohnt sich,
sobald das Lesen woanders herkommt als das Schreiben."""


def calendar_view(engine: DbEngine, session: CurrentSession) -> PostgresCalendarReader:
    """Der lesende Blick auf den eigenen Kalender.

    ``session`` steht hier aus demselben Grund wie bei ``tool_registry``: Der
    Eigentümer wird beim Verdrahten gebunden und ist kein Parameter. Ein
    ``user_id`` in Query oder Body wäre der kürzeste Weg in einen fremden
    Kalender — hier gibt es keines, weil es keine Methode gibt, die eines
    entgegennähme.

    **Und es ist ein anderer Adapter als der des Werkzeugs**, nicht derselbe
    unter zweitem Namen wie bei ``Audit``/``AuditReader``: Der Speicher, den
    die Registry hält, soll nicht lesen können. Beim Protokoll ist das
    folgenlos — dort schreibt der Executor und liest ein Endpunkt. Hier hielte
    ein Werkzeug-Handler das Objekt in der Hand.
    """
    return PostgresCalendarReader(engine, user_id=session.user_id)


CalendarView = Annotated[PostgresCalendarReader, Depends(calendar_view)]


def spend_reader(engine: DbEngine, session: CurrentSession) -> PostgresSpendReader:
    """Der Tagesverbrauch des angemeldeten Nutzers.

    Wie beim Kalender wird der Eigentümer beim Verdrahten gebunden. Ein
    Parameter dafür wäre hier besonders unangenehm: Wer einen fremden Nutzer
    benennen könnte, läse dessen Kosten — und könnte über den Umweg der
    Erschöpfung sehen, wie viel jemand arbeitet.
    """
    return PostgresSpendReader(engine, user_id=session.user_id)


Spend = Annotated[PostgresSpendReader, Depends(spend_reader)]


def permission_store(engine: DbEngine) -> PostgresPermissionStore:
    return PostgresPermissionStore(engine)


Permissions = Annotated[PostgresPermissionStore, Depends(permission_store)]


def session_manager(conn: DbConnection, engine: DbEngine) -> SessionManager:
    """Der Sitzungsmanager — mit beidem: Request-Verbindung und Engine.

    Anlegen gehört in die Transaktion des Requests: Eine Anmeldung, die
    scheitert, soll keine Sitzung hinterlassen. ``touch()``, die Rotation und
    der Widerruf gehören daneben in eigene Transaktionen — sonst hält ein
    Request die Zeile gesperrt, solange er läuft (ein Ereignisstrom läuft für
    immer), und schlimmer: Ein Widerruf in der Request-Transaktion würde von
    der 401-Ausnahme zurückgerollt, die unmittelbar darauf folgt.

    **Und die Audit-Senke gehört dazu** (ADR-020 §5): Eine erkannte
    Token-Wiederverwendung hinterlässt eine Spur in der Kette. Ohne diese Zeile
    stünde die Zusage im Entscheidungsdokument und nirgends sonst — genau das
    hat ein externes Review hier gefunden.
    """
    return SessionManager(
        PostgresSessionStore(conn, engine=engine), audit=PostgresAuditSink(engine)
    )


Sessions = Annotated[SessionManager, Depends(session_manager)]


def passkey_service(
    conn: DbConnection,
    sessions: Sessions,
    settings: Annotated[Settings, Depends(get_settings)],
) -> PasskeyService:
    return PasskeyService(
        challenges=PostgresChallengeStore(conn),
        credentials=PostgresCredentialStore(conn),
        verifier=WebAuthnVerifier(
            rp_id=settings.webauthn_rp_id,
            expected_origins=settings.webauthn_origins,
        ),
        sessions=sessions,
    )


Passkeys = Annotated[PasskeyService, Depends(passkey_service)]


def session_token_from(request: Request, settings: Settings) -> str:
    """Liest den Sitzungstoken — Cookie zuerst, dann ``Authorization``.

    Das Cookie ist ``httpOnly``: Ein XSS-Fehler in der Oberfläche kann es nicht
    auslesen. Der Bearer-Header existiert daneben, weil das Sprachgerät kein
    Browser ist und kein Cookie führt.

    Beide Wege enden in derselben Prüfung. Der Header ist keine Abkürzung an
    ihr vorbei, sondern ein zweites Transportmittel für dasselbe Geheimnis.
    """
    cookie = request.cookies.get(settings.session_cookie_name)
    if cookie:
        return cookie
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


def sitzungscookie_setzen(
    response: Response, token: str, settings: Settings, *, gilt_bis: int
) -> None:
    """Setzt das Sitzungscookie — **die einzige Stelle, die seine Flags kennt.**

    Vorher stand ``set_cookie`` genau einmal in ``login/finish``. Mit der
    Rotation (ADR-020) käme eine zweite Stelle dazu, und zwei Stellen mit
    Cookie-Flags sind eine Gelegenheit, sie auseinanderlaufen zu lassen: Ein
    Ersatzcookie ohne ``httponly`` wäre die Lücke, gegen die das erste gebaut
    wurde. Deshalb eine Funktion, die beide benutzen.
    """
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        max_age=gilt_bis,
    )


async def current_session(
    request: Request,
    response: Response,
    sessions: Sessions,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Session:
    """Die angemeldete Sitzung — oder 401.

    Was diese Funktion zurückgibt, ist die einzige Quelle für ``user_id`` und
    ``session_id`` in der gesamten HTTP-Schicht. Ein Strukturtest hält fest,
    dass daneben kein zweiter Weg entsteht.
    """
    # **Rotiert wird nur über den Cookie-Weg** (ADR-020 §4): Wer den Token als
    # ``Authorization: Bearer`` vorlegt, bekämt einen Ersatz, den er nie zu
    # sehen bekommt — das wäre eine Abmeldung mit Ansage. Und nicht im
    # Ereignisstrom (§6): Diese Antwort bleibt Stunden offen, ein Ersatz darin
    # erreichte die übrigen Anfragen des Browsers nicht.
    ueber_cookie = request.cookies.get(settings.session_cookie_name) is not None
    geprueft = await sessions.pruefen(
        session_token_from(request, settings),
        rotieren=ueber_cookie and request.url.path != STROMPFAD,
    )
    if geprueft.session is None:
        # **Der Grund geht ins Protokoll, nicht in die Antwort.** Nach außen
        # bleibt jedes 401 dasselbe — eine Unterscheidung dort wäre ein
        # Aufzählungsorakel. Nach innen ist sie der Unterschied zwischen
        # „Cookie kam nicht an" und „Zeile war noch nicht sichtbar": zwei
        # entgegengesetzte Untersuchungen, die bisher identisch aussahen.
        _log.info(
            "sitzung.abgewiesen",
            grund=str(geprueft.grund),
            pfad=request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nicht angemeldet.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if geprueft.neuer_token is not None:
        # Der Ersatz **muss** hier hinaus. Läge er nur in der Datenbank, hätte
        # der Client den alten — und liefe nach dem Überlappungsfenster in die
        # Wiederverwendungserkennung, also in eine Abmeldung, die er nicht
        # verdient hat.
        sitzungscookie_setzen(
            response,
            geprueft.neuer_token,
            settings,
            gilt_bis=int(
                (geprueft.session.expires_at - geprueft.session.created_at).total_seconds()
            ),
        )
    return geprueft.session


CurrentSession = Annotated[Session, Depends(current_session)]


async def current_token(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Der rohe Sitzungstoken — für Aufrufe, die die Bindung selbst nachweisen.

    Nur eine Stelle braucht das: ``ApprovalGateway.respond()`` prüft, ob der
    vorgelegte Token zu genau dieser Sitzung dieses Nutzers gehört. Die
    Sitzungs-ID allein wäre dort eine Behauptung des Aufrufers.

    Kein zweiter Weg zur Identität: Die Quelle ist dieselbe Funktion, die auch
    ``current_session`` benutzt. Wer diese Dependency nimmt, bekommt ein
    Geheimnis und keine Identität — die entsteht weiterhin ausschließlich in
    ``current_session``, und eine Route, die den Token nähme *ohne* die Sitzung
    zu verlangen, fiele beim Strukturtest durch.

    Der Wert gehört nirgends ins Protokoll.
    """
    return session_token_from(request, settings)


SessionToken = Annotated[str, Depends(current_token)]


def tool_registry(
    engine: DbEngine,
    settings: Annotated[Settings, Depends(get_settings)],
    session: CurrentSession,
) -> ToolRegistry:
    """Der Werkzeugkatalog — an den angemeldeten Nutzer gebunden.

    ``session`` steht hier, weil schreibende Werkzeuge einen Eigentümer
    brauchen und ihn **nicht als Argument** bekommen dürfen. Ein Handler sieht
    ausschließlich die Argumente seines Aufrufs; ein Feld ``user_id`` darin
    wäre dieselbe Lücke wie ``user_id`` in einem Request-Body, nur eine Schicht
    tiefer. Der Kalender wird deshalb hier gebunden — der Handler kann gar
    nicht in einen fremden schreiben, weil er den Adressaten nicht benennen
    kann.

    Die Folge: Der Katalog verlangt eine Sitzung. Das ist richtig so — ein
    Werkzeugangebot ohne Nutzer wäre eines, das niemandem gehört.
    """
    konten = PostgresAccountStore(engine)
    return tool_catalog(
        engine,
        files=file_reader_for(settings),
        ordner=directory_lister_for(settings),
        # Das Postfach wird **hier** an den Nutzer gebunden, wie der Kalender
        # und aus demselben Grund: Ein Argument ``konto`` wäre dieselbe Lücke
        # wie ``user_id`` im Request-Body, nur eine Schicht tiefer.
        mail=KontoGebundenerPostfachleser(
            user_id=session.user_id,
            konten=konten,
            # Faul: Der KEK wird erst angefasst, wenn wirklich ein Postfach
            # gelesen wird. Sonst hinge jedes Werkzeug an der Schlüsseldatei.
            dienst=lambda: TokenService(
                engine,
                konten=konten,
                zugangsdaten=PostgresOAuthCredentialStore(
                    engine, schluessel=key_provider(settings)
                ),
                tausch=HttpTokenExchange(),
            ),
            settings=settings,
        ),
        calendar=PostgresCalendarStore(engine, user_id=session.user_id),
        # **Kein Nutzerbezug, und das ist richtig.** Der Kalender wird an den
        # Angemeldeten gebunden, weil er *seine* Termine schreibt; das Web
        # gehört niemandem. Was den Abruf begrenzt, ist die Berechtigung
        # (``WebConstraints``) und die Adressprüfung im Adapter — beides
        # unabhängig davon, wer fragt.
        web=HttpWebFetcher(),
    )


Tools = Annotated[ToolRegistry, Depends(tool_registry)]


def plan_argument_source(
    settings: Annotated[Settings, Depends(get_settings)],
) -> PlanArgumentSource:
    """Die Quelle der Werkzeugargumente, wenn sie nicht der Aufrufer liefert.

    Hängt am Model Gateway und an nichts sonst — insbesondere nicht an der
    Registry und nicht am Executor. Sie liefert Datenmaterial; ausgeführt wird
    darüber nichts. Ein AST-Test hält das im Kern fest.
    """
    return PlanArgumentSource(gateway=model_gateway(settings))


ModelArguments = Annotated[PlanArgumentSource, Depends(plan_argument_source)]


def plan_response_source(
    settings: Annotated[Settings, Depends(get_settings)],
) -> PlanResponseSource:
    """Die Quelle für den abschließenden ``llm``-Schritt eines Plans.

    Getrennt von ``plan_argument_source``, obwohl beide nur das Gateway
    brauchen: Die eine bietet dem Modell ein Werkzeug an, die andere keines.
    Eine gemeinsame Dependency verwischte genau den Unterschied, auf den es
    ankommt.
    """
    return PlanResponseSource(gateway=model_gateway(settings))


ModelResponse = Annotated[PlanResponseSource, Depends(plan_response_source)]


def agent_step_source(
    tools: Tools,
    policy: Policy,
    invocations: Invocations,
    approvals: Approvals,
    audit: Audit,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentStepSource:
    """Die Quelle für Planschritte der Art ``agent``.

    Sie bekommt denselben Executor wie jeder andere Schritt — und das ist die
    Aussage: Ein Werkzeugaufruf eines Sub-Agenten geht durch Policy Engine,
    Bestätigung und Ausführungs-Gate wie eine Absicht des Nutzers. Die
    Agentenkette ist eine zusätzliche Verengung davor, kein zweiter Weg daneben.
    """
    return AgentStepSource(
        runtime=AgentRuntime(
            agents=agent_catalog(),
            tools=tools,
            policy=policy,
            executor=ToolExecutor(
                registry=tools,
                policy=policy,
                gateway=approvals,
                invocations=invocations,
                # Ein Sub-Agent führt Werkzeuge aus wie jeder andere Weg — und
                # er tut es, weil ein Modell es vorgeschlagen hat. Gerade
                # dieser Weg gehört ins Protokoll.
                audit=audit,
            ),
        ),
        agents=agent_catalog(),
        gateway=model_gateway(settings),
        tools=tools,
    )


Agents = Annotated[AgentStepSource, Depends(agent_step_source)]


def policy_engine(tools: Tools, permissions: Permissions) -> PolicyEngine:
    return PolicyEngine(tools, permissions)


Policy = Annotated[PolicyEngine, Depends(policy_engine)]


def approval_store(conn: DbConnection) -> PostgresApprovalStore:
    """Der Bestätigungsspeicher zum Lesen.

    Getrennt vom Gateway, weil die HTTP-Schicht ihn für etwas braucht, das
    keine Policy-Entscheidung ist: die Sichtbarkeit. Wem eine Bestätigung
    gehört, entscheidet die Grenze; ob sie gilt, entscheidet weiterhin
    ausschließlich das Gateway.
    """
    return PostgresApprovalStore(conn)


ActionStore = Annotated[PostgresApprovalStore, Depends(approval_store)]


def approval_gateway(conn: DbConnection, policy: Policy, sessions: Sessions) -> ApprovalGateway:
    """Das Bestätigungs-Gate.

    Der Bestätigungsspeicher nimmt die Verbindung des Requests und nicht die
    Engine — anders als Lauf, Protokoll und Grant-Verbrauch, und der
    Unterschied ist beabsichtigt: Eine Bestätigung *ist* die Arbeit dieses
    Requests. Scheitert er, soll sie nicht bestehen bleiben.

    Der Anspruch **aus** einer Bestätigung ist davon unberührt:
    ``claim_execution()`` ist ein bedingtes UPDATE, und die Ausführung, die
    daran hängt, liegt hinter dem Grant-Verbrauch — der committet für sich.

    ``sessions`` ist ausdrücklich der echte ``SessionManager`` und nicht
    ``UnverifiedSessions``. Letzteres heißt so, damit an der Aufrufstelle zu
    sehen ist, wenn die Sitzungsbindung ausgeschaltet ist.
    """
    return ApprovalGateway(PostgresApprovalStore(conn), policy, sessions=sessions)


Approvals = Annotated[ApprovalGateway, Depends(approval_gateway)]


# --------------------------------------------------------------------------
# Zugriffsgrenzen
# --------------------------------------------------------------------------


_redis_client: Redis | None = None


def _redis(url: str) -> Redis:
    """Ein Verbindungspool für den Prozess.

    Modulzustand wie bei der Datenbank-Engine, und mit demselben Vorbehalt: Er
    hängt am Event-Loop, der ihn erzeugt hat. Deshalb gibt es ``dispose_redis``
    — ohne das Gegenstück erbt ein zweiter Loop Verbindungen aus einem
    geschlossenen.

    Redis trägt hier nur flüchtigen Zustand (ADR-007, Nachtrag): Geht er
    verloren, sind Zähler zurückgesetzt, aber nichts ist inkonsistent.
    """
    global _redis_client
    if _redis_client is None:
        _redis_client = Redis.from_url(url, decode_responses=True)
    return _redis_client


def event_bus(settings: Annotated[Settings, Depends(get_settings)]) -> RedisEventBus | None:
    """Der Ereignisverteiler — oder ``None``, wenn Redis nicht eingerichtet ist.

    ``None`` und keine Attrappe: Ein stiller Verteiler sähe für die Oberfläche
    aus wie eine offene, ereignislose Leitung — und sie hörte auf, im Takt
    nachzuladen. Der Endpunkt antwortet stattdessen mit 503, und die Oberfläche
    macht weiter wie bisher.

    Ob Redis tatsächlich erreichbar ist, entscheidet sich beim ersten Aufruf;
    ein Verbindungsversuch hier machte aus jeder Abhängigkeit eine Wartezeit.
    """
    if not settings.redis_url:
        return None
    return RedisEventBus(_redis(settings.redis_url))


Events = Annotated["RedisEventBus | None", Depends(event_bus)]


async def dispose_redis() -> None:
    """Für sauberes Herunterfahren und Tests."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
    _redis_client = None


def rate_limiter(settings: Annotated[Settings, Depends(get_settings)]) -> RateLimiter:
    return RateLimiter(RedisRateLimitStore(_redis(settings.redis_url)))


Limiter = Annotated[RateLimiter, Depends(rate_limiter)]


def client_identifier(request: Request, settings: Settings) -> str:
    """Wer fragt — soweit sich das überhaupt feststellen lässt.

    ``X-Forwarded-For`` wird nur geglaubt, wenn die *tatsächliche* Gegenstelle
    als vertrauenswürdiger Proxy konfiguriert ist. Ohne diese Bedingung ist der
    Header ein Feld, das der Anfragende selbst füllt — ihn zu verwenden hieße,
    den Angreifer nach seiner Kennung zu fragen.

    Und selbst dann zählt nur, was hinter der bekannten Proxy-Kette steht: Ein
    Client kann einen eigenen ``X-Forwarded-For`` mitschicken, den der Proxy
    ergänzt statt ersetzt.

    Die Peer-Adresse ist ihrerseits kein knappes Gut: Ein IPv6-Präfix umfasst
    mehr Adressen, als ein Zähler je sehen wird. Deshalb ist diese Kennung nur
    die *feinere* der beiden Stufen; die grobe zählt global und ist von der
    Adresse unabhängig.
    """
    peer = request.client.host if request.client else "unbekannt"
    if peer not in settings.trusted_proxies:
        return peer

    # Die Kette wird von **rechts** ausgewertet, nicht von links.
    #
    # Ein Proxy hängt seine Sicht an: „client, proxy1, proxy2". Wer den ersten
    # Eintrag nimmt, nimmt den, den der Client selbst geschickt hat — und der
    # ist frei erfunden, sobald der Proxy den Header ergänzt statt ihn zu
    # überschreiben. Viele tun das, und ob der eigene dazugehört, weiß man
    # erfahrungsgemäß erst, wenn es darauf ankommt.
    #
    # Von rechts sind die Einträge dagegen genau so weit vertrauenswürdig, wie
    # die Kette aus bekannten Proxies reicht. Der erste unbekannte Eintrag von
    # rechts ist die letzte Adresse, die ein vertrauenswürdiger Proxy gesehen
    # hat — mehr lässt sich ehrlich nicht sagen.
    kette = [teil.strip() for teil in request.headers.get("x-forwarded-for", "").split(",")]
    kette = [teil for teil in kette if teil]
    while kette and kette[-1] in settings.trusted_proxies:
        kette.pop()
    return kette[-1] if kette else peer


def rate_limited(policy: RateLimitPolicy) -> Callable[..., Awaitable[None]]:
    """Erzeugt die Dependency für eine Route.

    Die Antwort bei Überschreitung ist für alle Fälle dieselbe: 429 mit
    ``Retry-After`` und ohne Hinweis darauf, *welche* Stufe gegriffen hat.
    Ein Angreifer soll nicht messen können, ob er allein am Limit ist oder ob
    das System insgesamt unter Last steht — und ein Konto, das es nicht gibt,
    darf sich nicht anders verhalten als eines, das es gibt.
    """

    async def dependency(
        request: Request,
        limiter: Limiter,
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> None:
        try:
            await limiter.require(policy, client=client_identifier(request, settings))
        except RateLimitExceeded as zu_viel:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Zu viele Anfragen.",
                headers={"Retry-After": str(zu_viel.decision.retry_after_s)},
            ) from zu_viel

    return dependency


# ==========================================================================
# Verbundene Konten (OAuth)
# ==========================================================================


@lru_cache(maxsize=1)
def _schluessel(pfad: str) -> DateiSchluessel:
    """Die Schlüsseldatei wird **einmal** gelesen, nicht je Request.

    Nicht aus Sparsamkeit: Ein Provider je Request hieße, dass ein Austausch
    der Datei mitten im Betrieb wirkt, ohne dass jemand neu startet — und dann
    ist die Hälfte der Datensätze mit einem KEK versiegelt, den niemand mehr
    findet. Eine Rotation gehört über ``kek_id`` und einen Neustart, nicht über
    einen zufälligen Zeitpunkt.
    """
    return DateiSchluessel(pfad)


def key_provider(settings: Annotated[Settings, Depends(get_settings)]) -> KeyProvider:
    """Woher der KEK kommt (ADR-008).

    Nur ``file`` ist gebaut, und dass er außerhalb der Entwicklung verboten
    ist, steht im Settings-Validator — beim Start und nicht hier. Eine Prüfung
    an dieser Stelle griffe erst beim ersten Token, und dann läuft das System
    längst.
    """
    if settings.key_provider != "file":
        raise RuntimeError(
            f"KEY_PROVIDER={settings.key_provider!r} ist nicht implementiert. "
            "Gebaut ist nur 'file' (ADR-008); 'keychain' und 'vault' stehen aus."
        )
    pfad = str(Path(settings.key_file).expanduser())
    try:
        return _schluessel(pfad)
    except OSError as fehler:
        # Ein nackter FileNotFoundError aus dem Inneren eines Adapters sagt
        # dem Betreiber nicht, was zu tun ist — und er käme, seit
        # ``create_app`` den Schlüssel beim Start anfasst, aus einem
        # Startvorgang statt aus einem Request.
        raise RuntimeError(
            f"Die Schlüsseldatei {pfad!r} fehlt oder ist nicht lesbar (KEY_FILE). "
            "Ohne sie lassen sich keine Zugangsdaten versiegeln. Anlegen mit "
            "jarvis_integrations.schluesseldatei_anlegen()."
        ) from fehler


Schluessel = Annotated[KeyProvider, Depends(key_provider)]


def authorization_store(engine: DbEngine, schluessel: Schluessel) -> PostgresAuthorizationStore:
    return PostgresAuthorizationStore(engine, schluessel=schluessel)


Authorizations = Annotated[PostgresAuthorizationStore, Depends(authorization_store)]


def oauth_credential_store(
    engine: DbEngine, schluessel: Schluessel
) -> PostgresOAuthCredentialStore:
    return PostgresOAuthCredentialStore(engine, schluessel=schluessel)


Credentials = Annotated[PostgresOAuthCredentialStore, Depends(oauth_credential_store)]


def account_store(engine: DbEngine) -> PostgresAccountStore:
    return PostgresAccountStore(engine)


Accounts = Annotated[PostgresAccountStore, Depends(account_store)]


def token_exchange() -> TokenExchange:
    return HttpTokenExchange()


Tokens = Annotated[TokenExchange, Depends(token_exchange)]


def token_service(
    engine: DbEngine, konten: Accounts, zugangsdaten: Credentials, tausch: Tokens
) -> TokenService:
    return TokenService(engine, konten=konten, zugangsdaten=zugangsdaten, tausch=tausch)


TokenDienst = Annotated[TokenService, Depends(token_service)]
