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
from .files import FILES_LIST, FILES_READ, files_list_handler, files_read_handler
from .mail import MAIL_READ, mail_read_handler
from .web import WEB_FETCH, web_fetch_handler

__all__ = [
    "CALENDAR_CREATE",
    "FILES_LIST",
    "FILES_READ",
    "MAIL_READ",
    "WEB_FETCH",
    "calendar_create_handler",
    "calendar_undo_handler",
    "files_list_handler",
    "files_read_handler",
    "mail_read_handler",
    "web_fetch_handler",
]
