"""Port des Webzugriffs.

Der Kern kennt kein HTTP. Was er kennt, ist die Zusage: **Was dieser Port
herausgibt, kam von einer öffentlich erreichbaren Adresse — und aus dem
Netzwerk dieses Rechners hat niemand etwas abgefragt, was nicht öffentlich
ist.**

Das ist eine andere Art von Grenze als beim Dateizugriff, und sie ist die
gefährlichere. Eine Datei liegt, wo sie liegt; eine Adresse **wird aufgelöst**,
und wer sie nennt, bestimmt damit, wohin dieser Prozess eine Verbindung
aufbaut. Ein Modell, das eine Adresse vorschlägt, ist in diesem Moment ein
Anweisungsgeber für das Netzwerk, in dem der Server steht:

* ``http://169.254.169.254/…`` ist bei jedem Cloud-Anbieter der Weg zu den
  Zugangsdaten der Instanz.
* ``http://localhost:5432`` ist die eigene Datenbank, ``http://10.0.0.5`` das
  Nachbarsystem hinter der Firewall.
* Ein Name, der auf eine solche Adresse zeigt, sieht von außen harmlos aus —
  die Auflösung entscheidet, nicht die Zeichenkette.

**Drei Grenzen, und sie sind verschieden.**

1. ``WebConstraints`` ist die Berechtigung *dieses Nutzers*: welche Hosts er
   überhaupt nennen darf. Sie prüft die Zeichenkette, mehr kann sie nicht.
2. Die Grenze *des Prozesses* liegt im Adapter: Er löst den Namen auf und
   weist **jede** Adresse ab, die nicht öffentlich routbar ist. Diese Prüfung
   kennt keine Ausnahme und hängt an keiner Berechtigung.
3. Die Grenze *des Inhalts*: Was zurückkommt, ist Fremdinhalt — dieselbe
   Einstufung wie bei einer Mail. Der Lauf ist danach kontaminiert, und die
   sendenden Werkzeuge fallen aus seinem Angebot.

Die zweite ist nicht die Wiederholung der ersten, aus demselben Grund wie beim
Dateizugriff: Die Berechtigung beantwortet „darf dieser Nutzer diese Adresse
nennen?", der Adapter beantwortet „wohin zeigt sie wirklich?".
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict

__all__ = ["WebAccessDenied", "WebDocument", "WebFetcher", "WebUnavailable"]


class WebAccessDenied(Exception):
    """Der Abruf wurde aus Sicherheitsgründen verweigert.

    Getrennt von ``WebUnavailable``, wie beim Dateizugriff und aus demselben
    Grund: „zeigt ins private Netz", „unerlaubtes Schema", „zu viele
    Weiterleitungen" gehören ins Sicherheitsprotokoll. Ein Server, der nicht
    antwortet, ist Alltag.
    """


class WebUnavailable(Exception):
    """Die Adresse war nicht erreichbar oder lieferte keinen brauchbaren Inhalt."""


class WebDocument(BaseModel):
    """Was von einer Adresse zurückkam."""

    model_config = ConfigDict(frozen=True)

    url: str
    """Die **tatsächlich abgerufene** Adresse, nicht die angefragte.

    Nach einer Weiterleitung sind das zwei verschiedene Dinge, und der
    Unterschied ist die Auskunft, die ein Mensch braucht: Wer ``example.com``
    anfragt und Inhalt von ``irgendwo-anders.test`` bekommt, soll das sehen.
    """

    title: str = ""
    text: str = ""
    truncated: bool = False
    """Wurde der Inhalt an der Größengrenze abgeschnitten? Ein halber Text, der
    als ganzer ausgegeben wird, ist eine Falschaussage über die Quelle."""


class WebFetcher(Protocol):
    """Lesender Zugriff auf öffentliche Webadressen."""

    async def fetch(self, url: str, *, max_bytes: int) -> WebDocument:
        """Ruft eine Adresse ab.

        Wirft ``WebAccessDenied``, wenn die Adresse nicht öffentlich ist oder
        das Schema nicht zugelassen — **bevor** eine Verbindung entsteht.
        Wirft ``WebUnavailable`` bei Netz- und Antwortfehlern.
        """
        ...
