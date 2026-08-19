"""Prozesslokaler Grant-Verbrauch.

Erfüllt ``GrantConsumer`` ohne Datenbank. Der Name sagt, was er leistet und
was nicht — dieselbe Überlegung wie bei ``UnverifiedSessions``: Ein Vorgabewert
mit unscheinbarem Namen erzeugt Vertrauen, das er nicht trägt.

**Was er leistet:** Innerhalb eines Prozesses ist der Verbrauch atomar. Zehn
nebenläufige Ausführungen desselben Grants ergeben genau eine; Kopien des
Grant-Objekts teilen den Verbrauch, weil er an der ``invocation_id`` hängt.

**Was er nicht leistet:** Zwei Prozesse teilen diesen Speicher nicht, und ein
Neustart vergisst ihn. Wo mehr als ein Arbeitsprozess läuft oder ein Neustart
eine begonnene Ausführung wieder aufnehmen kann, gehört die persistente
Implementierung eingesetzt (``PostgresGrantConsumer``).
"""

from __future__ import annotations

from datetime import datetime
from threading import Lock
from uuid import UUID

__all__ = ["InProcessGrants"]


class InProcessGrants:
    """Verbrauchte Invocations im Arbeitsspeicher."""

    def __init__(self) -> None:
        self._verbraucht: dict[UUID, datetime] = {}
        self._lock = Lock()
        """Der Ereignisschleife genügte ein Set ohne Sperre — zwischen Prüfung
        und Eintrag liegt kein ``await``. Die Sperre kostet nichts und macht
        die Zusage unabhängig davon, ob jemand die Registry aus einem
        Thread-Pool heraus benutzt."""

    async def consume(self, invocation_id: UUID, *, now: datetime) -> bool:
        with self._lock:
            if invocation_id in self._verbraucht:
                return False
            self._verbraucht[invocation_id] = now
            return True

    def __len__(self) -> int:
        return len(self._verbraucht)
