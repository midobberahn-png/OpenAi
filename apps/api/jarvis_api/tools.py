"""Der Werkzeugkatalog der Anwendung.

Hier entsteht die Registry, mit der das System tatsächlich arbeitet — im
Unterschied zu ``build_registry()`` in ``tests/fakes.py``, das Attrappen für
die Durchstichtests registriert. Diese Datei existiert, damit der Unterschied
sichtbar bleibt: Wer eine Registry mit ``mail.send`` im Testcode sieht, hält
sie sonst für die des Systems.

**Der Grant-Verbrauch wird an genau einer Stelle verdrahtet.** Das
Übergabedossier warnt ausdrücklich davor, hier ``InProcessGrants`` zu nehmen —
den Testdoppelgänger, der nur innerhalb eines Prozesses hält. Wer künftig ein
Werkzeug ergänzt, muss diese Entscheidung nicht noch einmal treffen.

**Was registriert ist und was nicht.** Bislang ein einziges Werkzeug,
``files.read``, und das ist Absicht: Es nimmt alle Schichten in Betrieb —
Scope, Berechtigung samt Pfadgrenzen, Protokoll, Grant, Kontamination — und
wirkt dabei nichts nach außen. Alles Weitere kommt danach, nicht daneben.

Ohne konfigurierte Wurzeln (``FILES_ALLOWED_ROOTS``) ist das Werkzeug
registriert, liefert aber für jeden Pfad eine Abweisung. Das ist gewollt: Der
Katalog soll nicht davon abhängen, ob jemand eine Umgebungsvariable gesetzt
hat — sonst wäre das Angebot an das Modell von der Betriebsumgebung abhängig
und der Fehler „Werkzeug fehlt" nicht von „Ordner nicht freigegeben" zu
unterscheiden.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.grant_store import PostgresGrantConsumer
from jarvis_api.db.invocation_store import PostgresInvocationStore
from jarvis_api.settings import Settings
from jarvis_core.ports.calendar import CalendarStore
from jarvis_core.ports.files import FileReader
from jarvis_core.ports.web import WebFetcher
from jarvis_core.tools import ToolRegistry
from jarvis_core.tools.builtin import (
    CALENDAR_CREATE,
    FILES_READ,
    WEB_FETCH,
    calendar_create_handler,
    calendar_undo_handler,
    files_read_handler,
    web_fetch_handler,
)

__all__ = ["tool_catalog"]


def tool_catalog(
    engine: AsyncEngine, *, files: FileReader, calendar: CalendarStore, web: WebFetcher
) -> ToolRegistry:
    """Die Registry der Anwendung — mit persistentem Grant-Verbrauch.

    Die Außenanbindung kommt als Port herein und wird hier nicht gebaut: So
    lässt sich der Katalog in einem Test mit einem anderen Dateizugriff
    aufbauen, ohne dass diese Funktion davon wüsste.
    """
    registry = ToolRegistry(
        grants=PostgresGrantConsumer(engine),
        # Zwei Verbräuche an derselben Zeile, für zwei verschiedene Wirkungen:
        # der eine vor einem Werkzeug, der andere vor einer Rücknahme. Ohne den
        # zweiten wäre eine **ausgestellte** Rücknahme-Erlaubnis beliebig oft
        # einlösbar — der Befund aus der externen Prüfung zu ``61d4428``.
        #
        # Beide Übergänge der Rücknahme stehen im Werkzeugprotokoll, weil beide
        # dieselbe Zeile fortschreiben: ``executed → undoing → undone``.
        undo_grants=PostgresInvocationStore(engine),
    )
    registry.register(FILES_READ, files_read_handler(files))
    registry.register(WEB_FETCH, web_fetch_handler(web))
    registry.register(
        CALENDAR_CREATE,
        calendar_create_handler(calendar),
        # Der Rücknahmeweg desselben Werkzeugs, an denselben Kalender gebunden.
        # Ohne ihn weist die Registry ``supports_undo=True`` zurück — ein
        # Versprechen ohne Weg soll beim Verdrahten auffallen und nicht beim
        # ersten Versuch eines Nutzers.
        undo=calendar_undo_handler(calendar),
    )
    return registry


def file_reader_for(settings: Settings) -> FileReader:
    """Der Dateizugriff des Prozesses.

    Getrennt von ``tool_catalog``, weil die Wurzeln aus der Konfiguration
    stammen und die Registry davon nichts wissen muss.
    """
    from jarvis_integrations import LocalFileReader

    return LocalFileReader(settings.files_allowed_roots)
