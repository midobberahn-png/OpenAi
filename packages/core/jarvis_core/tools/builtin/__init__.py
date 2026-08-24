"""Eingebaute Werkzeuge.

Jedes Modul hier liefert eine ``ToolSpec`` und eine Fabrik für den Handler.
Beides getrennt, weil die Spezifikation ohne Anbindung auskommt: Der Katalog
lässt sich lesen, dokumentieren und auf Berechtigungen prüfen, ohne dass
irgendetwas ausführbar wäre — dieselbe Trennung, die die ``ToolRegistry``
zwischen Spec und Handler führt.

Die Handler nehmen ihre Außenanbindung als **Port** entgegen und nie als
konkrete Implementierung. Sonst hinge der Kern am Dateisystem, am Netz oder an
einem Anbieter; ein Strukturtest hält das fest
(``test_layering.py::test_core_kennt_keine_konkreten_provider``).
"""

from .calendar import CALENDAR_CREATE, calendar_create_handler, calendar_undo_handler
from .files import FILES_READ, files_read_handler

__all__ = [
    "CALENDAR_CREATE",
    "FILES_READ",
    "calendar_create_handler",
    "calendar_undo_handler",
    "files_read_handler",
]
