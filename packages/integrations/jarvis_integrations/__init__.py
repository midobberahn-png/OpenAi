"""Fremdsystemadapter — die Stelle, an der das System die Außenwelt anfasst.

Getrennt von ``jarvis_providers`` (KI-Anbieter) und aus demselben Grund wie
dieses: Der Kern spricht über Ports, hier stehen die Implementierungen.

Zwei Regeln, beide aus dem Anbieteradapter übernommen und beide hier schärfer:

1. **Ein Adapter entscheidet nichts über Berechtigungen.** Ob ein Aufruf
   erlaubt war, hat die Policy Engine geklärt.
2. **Ein Adapter setzt aber seine eigene technische Grenze durch.** Das ist
   kein Widerspruch zu (1), sondern der Unterschied zwischen Erlaubnis und
   Wirkung: Die Policy prüft den Pfad, den jemand *nennt*. Wohin er zeigt,
   weiß erst, wer ihn öffnet — und ein Symlink ist auf der Ebene der Erlaubnis
   unsichtbar.
"""

from .localfs import LocalDirectoryLister, LocalFileReader

__all__ = ["LocalDirectoryLister",
    "LocalFileReader"]
