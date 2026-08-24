"""Port des Grant-Verbrauchs.

Ein ``ExecutionGrant`` ist eine Erlaubnis für **einen** Werkzeugaufruf. Die
Registry prüft Herkunft, Hash, Lauf und Nutzer — vier Werte, die bei einer
zweiten Vorlage desselben Grants unverändert gelten. Ohne einen Verbrauch ist
die Erlaubnis deshalb beliebig oft einlösbar; nachgewiesen in der dritten
externen Prüfrunde (Invariante ``grant-single-use``).

Der Verbrauch hängt an der ``invocation_id`` und ausdrücklich nicht am Objekt:
``model_copy()``, ``copy`` und ``deepcopy`` erzeugen sonst jeweils einen
unverbrauchten Zwilling. Er gehört an einen Ort, den alle Kopien teilen — und
bei mehreren Prozessen an einen, den alle Prozesse teilen.

Die Semantik ist **höchstens einmal**, dieselbe Entscheidung wie beim
Ausführungsanspruch der Bestätigung: Stürzt der Prozess zwischen Verbrauch und
Handler ab, gilt die Erlaubnis als verbraucht. Für Aktionen mit Außenwirkung
ist das die richtige Richtung — eine Mail, die vielleicht nicht hinausging,
kann der Nutzer erneut senden; eine, die zweimal hinausging, holt niemand
zurück.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

__all__ = ["GrantConsumer", "UndoConsumer"]


class GrantConsumer(Protocol):
    """Löst einen Grant ein — genau einmal."""

    async def consume(self, invocation_id: UUID, *, now: datetime) -> bool:
        """``True``, wenn dieser Aufruf den Grant erwirkt hat.

        **Atomar.** Zwei gleichzeitige Aufrufe mit derselben ``invocation_id``
        dürfen nicht beide ``True`` liefern. Ein ``if verbraucht: ...
        markiere()`` erfüllt das nicht — die Zusage gehört in die
        ``WHERE``-Klausel, nicht in eine Prüfung davor.

        **Dauerhaft, bevor dieser Aufruf zurückkehrt.** Die zweite Zusage, und
        sie hat gefehlt: Eine persistente Implementierung darf den Verbrauch
        nicht in einer Transaktion hinterlassen, die der Aufrufer später noch
        zurückrollen kann. Die Registry ruft unmittelbar nach ``True`` den
        Handler auf; wirkt der nach außen und stirbt der Prozess vor dem
        Commit, rollt der Verbrauch zurück, während der Seiteneffekt bleibt.
        Der nächste Versuch löst denselben Grant erneut ein — der vierte
        gemeldete Replay-Pfad, belegt in
        ``tests/integration/test_grant_consumption.py``.

        Atomar und dauerhaft sind zwei Zusagen, und die erste impliziert die
        zweite nicht: Ein bedingtes UPDATE ist unter Nebenläufigkeit korrekt und
        trotzdem flüchtig, solange es uncommitted ist.

        ``False`` heißt „kein einlösbarer Anspruch" und ist bewusst nicht nach
        Ursachen getrennt: bereits verbraucht, nie protokolliert, für diese
        Transaktion nicht sichtbar. Alle drei enden in derselben Abweisung,
        weil alle drei dasselbe bedeuten — und weil ein Aufrufer aus der
        Unterscheidung nichts machen könnte, das öffnen dürfte.
        """
        ...


class UndoConsumer(Protocol):
    """Löst eine **Rücknahme-Erlaubnis** ein — genau einmal.

    Ein eigener Port neben ``GrantConsumer`` und nicht eine zweite Methode
    darin: Die beiden sichern verschiedene Wirkungen an derselben Zeile. Der
    Ausführungs-Grant wird verbraucht, bevor ein Werkzeug wirkt; dieser hier,
    bevor eine Rücknahme wirkt. Eine gemeinsame Methode hieße, dass ein
    verbrauchter Aufruf auch keine Rücknahme mehr zuließe — und das ist genau
    verkehrt herum.

    **Herkunft: externe Prüfung von ``61d4428``.** Der Anspruch am Gate
    (``claim_undo``) sichert nur den Übergang *Aufruf → Erlaubnis*. Wer die
    ausgestellte Erlaubnis behält, legt sie erneut vor: Typ, Nutzer und
    Werkzeugname gelten unverändert. Dass ein zweites Löschen desselben Termins
    folgenlos wäre, ist eine Eigenschaft von ``calendar.create`` und keine des
    Weges — Undo ist als generischer Mechanismus gebaut.
    """

    async def consume_undo(self, invocation_id: UUID, *, now: datetime) -> bool:
        """``True``, wenn dieser Aufruf die Rücknahme erwirkt hat.

        Dieselben zwei Zusagen wie bei ``GrantConsumer.consume``, und aus
        denselben Gründen:

        **Atomar** — zwei gleichzeitige Vorlagen derselben Erlaubnis dürfen
        nicht beide ``True`` liefern. Die Bedingung gehört in die
        ``WHERE``-Klausel.

        **Dauerhaft, bevor dieser Aufruf zurückkehrt** — eine persistente
        Implementierung darf den Verbrauch nicht in einer Transaktion
        hinterlassen, die der Aufrufer noch zurückrollen kann. Sonst rollt er
        nach einem Absturz zurück, während der Seiteneffekt der Rücknahme
        bleibt, und der nächste Versuch nimmt ein zweites Mal zurück.

        ``False`` heißt „kein einlösbarer Anspruch" und ist bewusst nicht nach
        Ursachen getrennt.
        """
        ...
