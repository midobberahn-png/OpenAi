"""Port des Schlüsselmaterials — und die Entscheidung, die seine Form bestimmt.

Siehe ADR-008 (docs/01-tech-stack.md), einschließlich der Verschärfung V1.1.

**Dieser Port liefert keinen Schlüssel aus. Er entpackt.**

Der naheliegende Zuschnitt wäre ``kek() -> bytes``: Der Aufrufer holt sich den
Schlüssel und macht damit, was er will. Genau den schließt ADR-008 aus, und
zwar mit einer Begründung, die den Unterschied zwischen beiden Fassungen
ausmacht:

> In Produktion entpackt der API-Prozess **nicht selbst**. Er sendet den
> ``wrapped_dek`` an eine Entpack-Instanz (Vault Transit oder ein lokaler
> Unix-Socket-Dienst unter eigener Benutzerkennung) und erhält nur den DEK
> zurück.

Ein Port, der den KEK herausgibt, ist von Vault Transit **nicht
implementierbar** — dort verlässt das Schlüsselmaterial die Instanz nie. Die
Signatur trägt die Zusage also selbst: Wer nur ``wrap`` und ``unwrap`` anbieten
muss, kann beides über ein Netz erledigen, und eine Schwachstelle im Web-Layer
gibt keinen KEK preis, weil im Prozess keiner liegt.

**Und deshalb ist er asynchron.** In der Entwicklung liegt der KEK in einer
Datei und das ``await`` ist umsonst; in Produktion steht ein Netzaufruf
dahinter. Eine synchrone Signatur machte den Adaptertausch später zu einer
Änderung an jeder Aufrufstelle — dieselbe Überlegung wie beim Dateizugriff, der
in einen Thread gehört.

**``kek_id`` macht Rotation ohne Neuverschlüsselung möglich.** Jeder Datensatz
merkt sich, welcher KEK ihn versiegelt hat; ein neuer gilt für neue Datensätze,
und die alten bleiben lesbar, solange ihr KEK existiert. Ohne diese Kennung
wäre jede Rotation ein Durchlauf über alle Zeilen — und damit etwas, das
niemand macht.
"""

from __future__ import annotations

from typing import Protocol

__all__ = ["KeyProvider", "UnknownKek"]


class UnknownKek(Exception):
    """Der Datensatz nennt einen KEK, den dieser Provider nicht kennt.

    Getrennt von einem Entschlüsselungsfehler, weil die beiden verschiedene
    Vorgänge sind: Ein unbekannter KEK ist ein Betriebsproblem — der Schlüssel
    fehlt, die Zeile ist in Ordnung. Ein Entschlüsselungsfehler heißt, dass an
    den Daten etwas nicht stimmt.
    """


class KeyProvider(Protocol):
    """Verpackt und entpackt Datenschlüssel (DEK) — ohne den KEK preiszugeben."""

    @property
    def kek_id(self) -> str:
        """Kennung des KEK, mit dem **neue** Datensätze versiegelt werden.

        Wird je Datensatz gespeichert. Nach einer Rotation zeigt diese
        Eigenschaft auf den neuen Schlüssel, während ``unwrap`` die alten
        weiterhin bedient.
        """
        ...

    async def wrap(self, dek: bytes) -> bytes:
        """Verpackt einen Datenschlüssel mit dem aktuellen KEK."""
        ...

    async def unwrap(self, wrapped_dek: bytes, *, kek_id: str) -> bytes:
        """Entpackt einen Datenschlüssel — mit **dem** KEK, der ihn verpackt hat.

        ``kek_id`` kommt aus dem Datensatz und nicht aus dem Provider: Wer einen
        alten Datensatz liest, braucht den alten Schlüssel. Kennt der Provider
        ihn nicht, ist das ``UnknownKek`` und keine stille leere Antwort.
        """
        ...
