"""Sitzungsspeicher auf PostgreSQL.

Gesucht wird ausschließlich über den Token-Hash. Die Klartext-Spalte existiert
nicht — nicht als Vorsichtsmaßnahme, sondern weil es sie nie gab: Der Manager
übergibt nur den Fingerabdruck.

Bewusst **ohne** Gültigkeitsfilter in der Abfrage. Der Port schreibt das vor,
und der Grund ist die Erfahrung mit zwei Meinungen über denselben Zustand: Ein
Speicher, der abgelaufene Sitzungen selbst ausblendet, und ein Manager, der
zusätzlich prüft, driften auseinander — und dann ist unklar, welche der beiden
Prüfungen den Widerruf vergessen hat.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from jarvis_contracts import Session
from jarvis_core.ports.sessions import SessionLookup

__all__ = ["PostgresSessionStore"]


_INSERT = text(
    """
    INSERT INTO sessions (
        id, user_id, token_hash, client, channel,
        created_at, last_seen_at, expires_at
    ) VALUES (
        :id, :user_id, :token_hash, :client, :channel,
        :created_at, :last_seen_at, :expires_at
    )
    """
)

_SELECT_COLUMNS = """
    id, user_id, client, channel, created_at, last_seen_at, expires_at, revoked_at
"""

_BY_HASH = text(f"SELECT {_SELECT_COLUMNS} FROM sessions WHERE token_hash = :h")

_LOOKUP = text(
    f"""
    SELECT {_SELECT_COLUMNS},
           (token_hash <> :h) AS ist_vorgaenger,
           now() - COALESCE(rotated_at, created_at) AS token_alter,
           now() - rotated_at AS rotation_alter,
           (rotation_confirmed_at IS NOT NULL) AS ersatz_bestaetigt
      FROM sessions
     WHERE token_hash = :h OR prev_token_hash = :h
    """
)
"""Sucht über beide Hashes (ADR-020).

``ist_vorgaenger`` wird in der Abfrage entschieden und nicht danach: Wer die
Zeile hat, hat auch die Antwort, und eine zweite Auswertung im Python-Teil wäre
eine zweite Wahrheit über dieselbe Zeile.

**Und die beiden Alter ebenfalls** — hier statt im Prozess, weil ein Vergleich
gegen einen Zeitpunkt von dort die Gültigkeit eines Tokens von der Uhrendrift
abhängig machte. Ein Integrationstest hat genau das gefunden: Mit gestellter
Prozessuhr galt ein ersetzter Token weiter, weil die Differenz negativ wurde.

**Eine Einschränkung, die hier stehen muss** (ein externes Review hat sie
gefunden, nachdem eine frühere Fassung dieses Absatzes das Gegenteil
behauptete): ``rotated_at`` setzt die Datenbank, ``created_at`` dagegen der
**Prozess** beim Anlegen. Für ``rotation_alter`` — die Frist, an der die
Wiederverwendungserkennung hängt — ist das ohne Belang, sie rechnet
ausschließlich mit ``rotated_at``. ``token_alter`` mischt bei einer noch nie
rotierten Sitzung dagegen beide Uhren: Läuft der ausstellende Prozess vor,
verzögert sich die erste Rotation um die Drift; läuft er nach, kommt sie zu
früh. Beides ist begrenzt und ohne Sicherheitsfolge — zu früh rotieren ist
harmlos, zu spät verschiebt den Schutz um die Drift.

Die saubere Behebung wäre, ``created_at`` ebenfalls von der Datenbank setzen zu
lassen. Das hängt an ``expires_at`` und damit an der Zeitsteuerung der halben
Testsuite; es steht als eigener Punkt im Dossier statt als stille Halbheit
hier."""

_CONFIRM = text(
    """
    UPDATE sessions
       SET rotation_confirmed_at = now()
     WHERE id = :id AND rotation_confirmed_at IS NULL
    """
)

_ROTATE = text(
    """
    UPDATE sessions
       SET token_hash = :neu, prev_token_hash = :alt, rotated_at = now(),
           rotation_confirmed_at = NULL
     WHERE id = :id AND token_hash = :alt
    RETURNING id
    """
)
"""Vergleiche-und-setze. Die Bedingung auf den **aktuellen** Hash entscheidet
den Wettlauf: Von zwei gleichzeitigen Anfragen trifft genau eine die Zeile."""

_TOUCH = text("UPDATE sessions SET last_seen_at = :now WHERE id = :id AND revoked_at IS NULL")
"""``last_seen_at`` wandert, ``expires_at`` nicht. Wer eine gestohlene Sitzung
aktiv hält, hält sie damit nicht unbegrenzt am Leben."""

_REVOKE = text("UPDATE sessions SET revoked_at = :now WHERE id = :id AND revoked_at IS NULL")

_REVOKE_ALL = text(
    "UPDATE sessions SET revoked_at = :now WHERE user_id = :u AND revoked_at IS NULL"
)

_ACTIVE = text(
    f"SELECT {_SELECT_COLUMNS} FROM sessions "
    "WHERE user_id = :u AND revoked_at IS NULL ORDER BY last_seen_at DESC"
)


def _to_session(row: Any) -> Session:
    return Session(
        id=row.id,
        user_id=row.user_id,
        client=row.client,
        channel=row.channel,
        created_at=row.created_at,
        last_seen_at=row.last_seen_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
    )


class PostgresSessionStore:
    """Sitzungen — Anlegen und Widerrufen im Request, ``touch`` daneben."""

    def __init__(self, conn: AsyncConnection, *, engine: AsyncEngine | None = None) -> None:
        self._conn = conn
        self._engine = engine
        """Für ``touch()`` und **nur** dafür — Begründung dort.

        ``None`` bleibt zulässig: Wer den Speicher nur zum Anlegen oder
        Widerrufen baut, braucht keine zweite Transaktion, und ein
        Pflichtparameter zwänge sie jedem Test auf."""

    async def create(self, session: Session, token_hash: str) -> None:
        await self._conn.execute(
            _INSERT,
            {
                "id": session.id,
                "user_id": session.user_id,
                "token_hash": token_hash,
                "client": session.client,
                "channel": session.channel,
                "created_at": session.created_at,
                "last_seen_at": session.last_seen_at,
                "expires_at": session.expires_at,
            },
        )

    async def by_token_hash(self, token_hash: str) -> Session | None:
        row = (await self._conn.execute(_BY_HASH, {"h": token_hash})).first()
        return _to_session(row) if row is not None else None

    async def lookup(self, token_hash: str) -> SessionLookup | None:
        row = (await self._conn.execute(_LOOKUP, {"h": token_hash})).mappings().first()
        if row is None:
            return None
        felder = dict(row)
        ist_vorgaenger = bool(felder.pop("ist_vorgaenger"))
        token_alter = felder.pop("token_alter")
        rotation_alter = felder.pop("rotation_alter")
        bestaetigt = bool(felder.pop("ersatz_bestaetigt"))
        return SessionLookup(
            session=Session(**felder),
            ist_vorgaenger=ist_vorgaenger,
            token_alter=token_alter,
            rotation_alter=rotation_alter,
            ersatz_bestaetigt=bestaetigt,
        )

    async def confirm_rotation(self, session_id: UUID) -> None:
        """Setzt den Zeitpunkt der ersten Benutzung — einmal.

        ``WHERE rotation_confirmed_at IS NULL`` macht das idempotent **und**
        nebenläufigkeitsfest: Zwei gleichzeitige Anfragen mit dem neuen Token
        schreiben nicht zwei verschiedene Zeitpunkte. Eigene Transaktion aus
        demselben Grund wie bei ``rotate()`` — die Feststellung „der Ersatz kam
        an" darf nicht zurückgerollt werden, denn sie ist die Grundlage, auf der
        später ein Diebstahl erkannt wird.
        """
        if self._engine is None:
            await self._conn.execute(_CONFIRM, {"id": session_id})
            return
        async with self._engine.begin() as conn:
            await conn.execute(_CONFIRM, {"id": session_id})

    async def rotate(self, session_id: UUID, *, alt_hash: str, neu_hash: str) -> bool:
        """Eigene Transaktion, wie beim Anspruch — und aus demselben Grund.

        Die Rotation muss auch dann gelten, wenn der Request danach scheitert:
        Der Aufrufer hat den neuen Token bereits in seiner Antwort. Eine
        Rotation, die mit dem Request zurückrollt, gäbe ihm ein Cookie, das zu
        keiner Zeile gehört — und damit eine Abmeldung beim nächsten Aufruf.
        """
        if self._engine is None:
            # Wie bei ``touch()``: Wer den Speicher ohne Engine baut, rotiert
            # nicht. Kein Fehler, sondern die ehrliche Antwort „nicht getan".
            return False
        async with self._engine.begin() as conn:
            treffer = (
                await conn.execute(_ROTATE, {"id": session_id, "alt": alt_hash, "neu": neu_hash})
            ).first()
        return treffer is not None

    async def touch(self, session_id: UUID, now: datetime) -> None:
        """Setzt ``last_seen_at`` fort — in **eigener**, kurzer Transaktion.

        **Der Befund, der das erzwungen hat.** Jede Sitzungsprüfung schreibt
        diese Zeile, und in der Transaktion des Requests bleibt sie bis zu
        dessen Ende gesperrt. Bei kurzen Requests war das ein Kuriosum: Zwei
        Aufrufe derselben Sitzung liefen hintereinander, ohne dass das jemand
        entworfen hätte — nachzulesen in ``tests/integration/test_step_claim.py``,
        wo eine ganze Testkonstruktion darum herum gebaut ist.

        Mit dem Ereignisstrom wurde daraus ein Stillstand. Ein SSE-Request
        endet nicht; seine Transaktion bleibt offen, die Zeilensperre auch —
        und **jeder weitere Aufruf derselben Sitzung wartet auf ein Ende, das
        nicht kommt.** Gemessen beim ersten Browsertest des Stroms: Die
        Oberfläche verband sich, und danach ging nichts mehr.

        Deshalb eine eigene Transaktion, dieselbe Bauart wie beim
        Grant-Verbrauch. Was daran hängt: ``last_seen_at`` überlebt jetzt einen
        zurückgerollten Request. Das ist die richtige Richtung — der Zeitstempel
        beantwortet „wann wurde diese Sitzung zuletzt benutzt", und benutzt
        wurde sie auch dann, wenn der Aufruf scheiterte.

        Ohne Engine bleibt es beim alten Weg: Ein Speicher, der nur anlegt oder
        widerruft, soll keine zweite Verbindung fordern.
        """
        if self._engine is None:
            await self._conn.execute(_TOUCH, {"id": session_id, "now": now})
            return
        async with self._engine.begin() as conn:
            await conn.execute(_TOUCH, {"id": session_id, "now": now})

    async def revoke(self, session_id: UUID, now: datetime) -> None:
        """Widerruft eine Sitzung — in **eigener** Transaktion, wenn möglich.

        **Ein Integrationstest hat den Grund geliefert, und er ist unangenehm.**
        Die Wiederverwendungserkennung (ADR-020 §5) widerruft die Sitzung und
        lässt danach ein 401 los. Lief der Widerruf in der Transaktion des
        Requests, rollte genau diese Ausnahme ihn wieder zurück: Die
        Sicherheitsmaßnahme hätte sich selbst rückgängig gemacht, und der Dieb
        hätte weitergearbeitet.

        Dieselbe Lehre wie beim Ausführungsanspruch und beim Grant-Verbrauch:
        Wo eine Wirkung auch dann gelten muss, wenn der Aufrufer scheitert,
        gehört ihr eine eigene Transaktion.

        Ohne Engine bleibt es bei der Verbindung des Aufrufers — für einen
        Speicher, der nur zum Anlegen gebaut wurde, ist das die richtige
        Vorgabe, und die Abmeldung über ``POST /auth/logout`` committet
        ohnehin.
        """
        if self._engine is None:
            await self._conn.execute(_REVOKE, {"id": session_id, "now": now})
            return
        async with self._engine.begin() as conn:
            await conn.execute(_REVOKE, {"id": session_id, "now": now})

    async def revoke_all_for_user(self, user_id: UUID, now: datetime) -> int:
        result = await self._conn.execute(_REVOKE_ALL, {"u": user_id, "now": now})
        return int(result.rowcount or 0)

    async def active_for_user(self, user_id: UUID, now: datetime) -> list[Session]:
        rows = await self._conn.execute(_ACTIVE, {"u": user_id})
        return [_to_session(row) for row in rows]
