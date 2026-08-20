"""Der Werkzeugkatalog der Anwendung.

**Er ist leer, und das ist der ehrliche Zustand.** Es gibt bislang keine
einzige Werkzeug-Implementierung; ``build_registry()`` in ``tests/fakes.py``
registriert Attrappen für die Durchstichtests. Diese Datei existiert trotzdem,
und zwar aus zwei Gründen:

1. **Die Lücke gehört in den Anwendungscode.** Solange der einzige Katalog im
   Testcode steht, sieht ein Leser eine Registry mit ``mail.send`` und
   ``calendar.create`` und hält sie für die des Systems. Hier steht, dass es
   sie nicht gibt.

2. **Die Verdrahtung des Grant-Verbrauchs gehört an genau eine Stelle.** Das
   Übergabedossier warnt ausdrücklich davor, beim Verdrahten
   ``InProcessGrants`` zu nehmen — der Testdoppelgänger, der nur innerhalb
   eines Prozesses hält. Diese Funktion nimmt ``PostgresGrantConsumer``, und
   wer künftig ein Werkzeug registriert, muss die Entscheidung nicht noch
   einmal treffen.

Eine ``ToolRegistry`` ohne Werkzeuge ist dabei kein Sicherheitsproblem: Jeder
Aufruf endet in ``UnknownTool``. Das ist dieselbe fail-closed-Richtung wie eine
Registry ohne Grant-Verbrauch, die ``UnguardedExecution`` wirft.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.grant_store import PostgresGrantConsumer
from jarvis_core.tools import ToolRegistry

__all__ = ["tool_catalog"]


def tool_catalog(engine: AsyncEngine) -> ToolRegistry:
    """Die Registry der Anwendung — mit persistentem Grant-Verbrauch.

    Hier kommen die Werkzeuge hin. Wer eines ergänzt, registriert Spezifikation
    **und** Handler; ein Spec ohne Handler ist ein Konfigurationsfehler und
    wird beim Ausführen abgewiesen.
    """
    return ToolRegistry(grants=PostgresGrantConsumer(engine))
