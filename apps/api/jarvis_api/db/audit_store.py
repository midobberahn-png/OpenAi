"""Das Audit-Log auf PostgreSQL — die fehlende Hälfte einer fertigen Zusage.

**Der Befund:** Die Hash-Kette war vollständig gebaut. ``AuditEntry``,
``compute_entry_hash``, ``verify_chain``, der Port ``AuditSink``, die Tabelle,
der Append-Only-Trigger, sogar der Advisory-Lock-Schlüssel — alles da. Was
fehlte, war die Implementierung dazwischen: ``ToolExecutor(audit=...)`` bekam in
der gesamten Anwendung ``None``. Jede Werkzeugausführung, jede Bestätigung, jede
Ablehnung lief ohne Protokoll.

Das ist die unangenehmste Sorte Lücke, weil sie nach außen wie Vollständigkeit
aussieht: Ein Prüfer liest Kette, Trigger und Tests und schließt daraus, dass
protokolliert wird. Geprüft war die *Mechanik*, nicht ihr Betrieb.

**Zwei Zusagen, und beide liegen in dieser Datei:**

1. **Serialisiert.** Zwei gleichzeitige Schreiber lesen sonst denselben
   ``prev_hash`` und gabeln die Kette — aus einer Kette werden zwei Stränge,
   und die Prüfung meldet einen Bruch, den niemand verursacht hat.
   ``pg_advisory_xact_lock`` hält das auseinander, und der Lock gilt *für die
   Transaktion*: Er muss deshalb in derselben liegen wie Lesen und Schreiben.
2. **In einer Transaktion gelesen und geschrieben.** Ein ``prev_hash`` aus
   einer früheren Transaktion ist eine Behauptung über einen Zustand, der
   inzwischen ein anderer sein kann.

**Eine eigene Transaktion, und das ist hier eine Abwägung und keine Regel.**

Die übrigen Speicher dieses Projekts nehmen eine ``AsyncEngine``, weil ihre
Ansprüche einen Absturz überleben müssen. Hier liegt es anders herum: Ein
Audit-Eintrag gehört zu dem, was tatsächlich geschehen ist. Läge er in der
Transaktion des Requests, verschwände er mit einem Rollback — zusammen mit dem,
was er bezeugt, und das wäre konsistent. Er liegt trotzdem in einer eigenen,
und der Grund ist der Ablauf des Executors: Er protokolliert **vor** dem
Werkzeug (``tool.requested``) und danach (``tool.executed``). Ein Rollback nach
einer Wirkung nach außen — die Mail ist raus — nähme genau den Eintrag mit, der
sie bezeugt.

Die Richtung ist damit: lieber ein Eintrag zu viel als einer zu wenig. Ein
Vorgang, der protokolliert ist und nicht stattfand, ist nachvollziehbar; einer,
der stattfand und nicht protokolliert ist, nicht.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_core.audit.chain import (
    AUDIT_ADVISORY_LOCK_KEY,
    AuditEntry,
    ChainBreak,
    StoredAuditRow,
    compute_entry_hash,
    verify_chain,
)

__all__ = ["PostgresAuditSink"]


_LOCK = text("SELECT pg_advisory_xact_lock(:key)")
"""Serialisiert das Anfügen — je Transaktion, nicht je Sitzung.

``pg_advisory_xact_lock`` und nicht ``pg_advisory_lock``: Der Lock fällt mit dem
Ende der Transaktion, auch wenn der Prozess dazwischen stirbt. Die
Sitzungsvariante bliebe an einer Verbindung hängen, die aus einem Pool kommt
und danach jemand anderem gehört — und das Audit-Log wäre bis zum Neustart
blockiert."""

_LETZTER = text("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
"""Der Vorgänger. Muss in derselben Transaktion gelesen werden wie der INSERT
folgt; sonst beschreibt er einen Zustand, der inzwischen ein anderer ist."""

_INSERT = text(
    """
    INSERT INTO audit_log (
        user_id, occurred_at, actor, action, resource, details, trace_id,
        prev_hash, entry_hash
    ) VALUES (
        :user_id, :occurred_at, :actor, :action, :resource, CAST(:details AS jsonb),
        :trace_id, :prev_hash, :entry_hash
    )
    RETURNING id
    """
)
"""``occurred_at`` kommt aus der Anwendung und nicht aus ``now()``: Der Hash
entsteht vor dem INSERT, und gehashter und gespeicherter Zeitstempel müssen
derselbe sein. Ein ``server_default`` wäre hier ein stiller Kettenbruch."""

_KETTE = text(
    """
    SELECT id, occurred_at, actor, action, resource, details, trace_id,
           prev_hash, entry_hash
      FROM audit_log
     ORDER BY id
    """
)
"""Aufsteigend nach ``id`` — die Reihenfolge *ist* die Kette.

Ohne ``user_id``: Sie geht nicht in den Hash (DSGVO-Pseudonymisierung, siehe
``chain.py``), und was nicht geprüft wird, wird hier auch nicht gelesen."""

_KETTE_AB = text(
    """
    SELECT id, occurred_at, actor, action, resource, details, trace_id,
           prev_hash, entry_hash
      FROM audit_log
     WHERE id > (SELECT COALESCE(MAX(id), 0) - :limit FROM audit_log)
     ORDER BY id
    """
)
"""Die letzten ``limit`` Einträge.

**Und der erste davon hat einen Vorgänger, den diese Abfrage nicht liefert.**
Eine Teilprüfung meldet deshalb am Anfang einen Bruch, der keiner ist — dazu
``verify()``."""


_ANZAHL = text("SELECT count(*) FROM audit_log")

_FUER_NUTZER = text(
    """
    SELECT id, occurred_at, actor, action, resource, details, trace_id,
           prev_hash, entry_hash
      FROM audit_log
     WHERE user_id = :user_id
     ORDER BY id DESC
     LIMIT :limit
    """
)
"""Die Einträge eines Nutzers. ``user_id`` in der Abfrage, nicht in einem
Filter darüber.

**Pseudonymisierte Einträge erscheinen hier nicht.** Nach einer DSGVO-Löschung
steht ``user_id`` auf ``NULL``, und die Zeile gehört damit niemandem mehr — sie
bleibt in der Kette, aber sie ist keine Auskunft über eine Person. Genau das ist
der Zweck."""


class PostgresAuditSink:
    """Hängt Einträge an die Kette und prüft sie."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        """Eine Engine: Anfügen läuft in einer eigenen, kurzen Transaktion —
        Begründung im Modulkopf."""

    async def append(self, entry: AuditEntry) -> bytes:
        """Schreibt einen Eintrag und liefert seinen ``entry_hash``.

        Lock, Vorgänger lesen, Hash bilden, schreiben — in dieser Reihenfolge
        und in einer Transaktion. Jede andere Reihenfolge gabelt die Kette
        unter Nebenläufigkeit.
        """
        async with self._engine.begin() as conn:
            await conn.execute(_LOCK, {"key": AUDIT_ADVISORY_LOCK_KEY})
            vorgaenger = (await conn.execute(_LETZTER)).scalar_one_or_none()
            hash_wert = compute_entry_hash(entry, vorgaenger)
            await conn.execute(
                _INSERT,
                {
                    "user_id": entry.user_id,
                    "occurred_at": entry.occurred_at,
                    "actor": entry.actor,
                    "action": entry.action,
                    "resource": entry.resource,
                    "details": json.dumps(entry.details, ensure_ascii=False, default=str),
                    "trace_id": entry.trace_id,
                    "prev_hash": vorgaenger,
                    "entry_hash": hash_wert,
                },
            )
            return hash_wert

    async def verify(self, *, limit: int | None = None) -> list[ChainBreak]:
        """Prüft die Kette. Leere Liste heißt: unversehrt.

        **``limit`` prüft einen Ausschnitt, und ein Ausschnitt hat einen
        Anfang.** Der erste geprüfte Eintrag verweist auf einen Vorgänger, der
        außerhalb liegt; ohne Rücksicht darauf meldete jede Teilprüfung genau
        einen Bruch — und eine Prüfung, die immer einen Fund meldet, wird nach
        drei Tagen ignoriert. Der Anfang des Ausschnitts wird deshalb als
        gegeben genommen, und was danach kommt, wird gegen ihn geprüft.

        Wer die Kette **ganz** prüfen will, lässt ``limit`` weg. Nur das
        beantwortet die Frage „ist irgendetwas verändert worden?"; alles andere
        beantwortet „ist seit Eintrag N etwas verändert worden?".
        """
        async with self._engine.connect() as conn:
            if limit is None:
                zeilen = (await conn.execute(_KETTE)).mappings().all()
            else:
                zeilen = (await conn.execute(_KETTE_AB, {"limit": limit})).mappings().all()

        gelesen = [StoredAuditRow(**dict(z)) for z in _als_dicts(zeilen)]
        if limit is not None and gelesen:
            # Der Anfang des Ausschnitts gilt als gegeben: Sein ``prev_hash``
            # zeigt auf einen Eintrag, den diese Prüfung nicht gelesen hat.
            kopf = gelesen[0]
            return [
                bruch
                for bruch in verify_chain(gelesen)
                if not (bruch.row_id == kopf.id and "Vorgänger" in bruch.reason)
            ]
        return verify_chain(gelesen)

    async def count(self, *, limit: int | None = None) -> int:
        """Wie viele Einträge die Prüfung tatsächlich gelesen hat.

        Eine Prüfung, die „unversehrt" meldet, ohne zu sagen *wovon*, ist
        wertlos: Über einer leeren Tabelle ist jede Kette unversehrt.
        """
        async with self._engine.connect() as conn:
            gesamt = int((await conn.execute(_ANZAHL)).scalar_one())
        return gesamt if limit is None else min(gesamt, limit)

    async def for_user(self, user_id: UUID, *, limit: int = 50) -> list[StoredAuditRow]:
        """Die jüngsten Einträge **eines** Nutzers, neueste zuerst.

        ``user_id`` steht in der Abfrage und nicht in einem Filter darüber —
        dieselbe Überlegung wie beim Laufspeicher. Dass die Kettenprüfung
        daneben *alle* Einträge liest, ist kein Widerspruch: Sie beantwortet
        eine Frage über das System, diese hier eine über einen Menschen.
        """
        async with self._engine.connect() as conn:
            zeilen = (
                (await conn.execute(_FUER_NUTZER, {"user_id": user_id, "limit": limit}))
                .mappings()
                .all()
            )
        return [StoredAuditRow(**z) for z in _als_dicts(zeilen)]


def _als_dicts(zeilen: Any) -> list[dict[str, Any]]:
    """``details`` kommt als ``dict`` zurück, ``prev_hash`` als ``memoryview``.

    Beides ist für den Vertrag ungeeignet: ``StoredAuditRow`` erwartet Bytes,
    und ein ``memoryview`` vergleicht sich nicht gleich — die Kettenprüfung
    meldete sonst überall Brüche, wo keine sind.
    """
    return [
        {
            **dict(zeile),
            "prev_hash": bytes(zeile["prev_hash"]) if zeile["prev_hash"] is not None else None,
            "entry_hash": bytes(zeile["entry_hash"]),
        }
        for zeile in zeilen
    ]
