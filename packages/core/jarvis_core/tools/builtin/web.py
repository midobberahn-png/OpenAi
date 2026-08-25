"""``web.fetch`` — das erste Werkzeug, das Fremdinhalt aus dem offenen Netz holt.

``files.read`` liest, was jemand selbst hingelegt hat; ``calendar.create``
wirkt nach außen, aber nur mit dem, was ein Mensch bestätigt hat. Dieses
Werkzeug ist beides zugleich und deshalb der Ernstfall, für den der
Sicherheitssockel gebaut wurde:

* **Es wirkt nach außen, ohne etwas zu verändern.** Ein Abruf hinterlässt eine
  Spur beim Betreiber der Adresse und baut eine Verbindung aus *diesem*
  Netzwerk auf. Was von hier aus erreichbar ist, ist mehr als das, was aus dem
  Internet erreichbar ist — die Abwehr dagegen steht im Adapter
  (``jarvis_integrations.web``), nicht hier.
* **Es holt Text, den ein Fremder geschrieben hat, und legt ihn dem Modell
  vor.** Damit ist der Lauf kontaminiert, sendende Werkzeuge fallen aus seinem
  Angebot, und eine untergeschobene Anweisung bleibt folgenlos statt unerkannt.
  Das ist derselbe Mechanismus wie bei einer Datei — nur wählt hier ein Modell
  die Quelle, und im Netz steht Text, der genau dafür geschrieben wurde.

**Warum das Ergebnis P0 ist.** Eine öffentliche Webseite ist öffentlich
(docs/00-uebersicht.md §8 führt „Websuche" ausdrücklich als P0). Die
Einstufung sagt etwas über *Sensibilität*, nicht über *Vertrauen*; dass der
Inhalt nicht vertrauenswürdig ist, sagt ``reads_untrusted_content``. Die beiden
zu verwechseln hieße, jede Webseite wie eine Gesundheitsakte zu behandeln — und
ein Schutz, der den Normalfall blockiert, wird abgeschaltet.

**Keine Vorschau.** Ein Abruf ist nicht rücknehmbar, aber auch nicht
veränderbar; eine Bestätigung je Adresse machte das Werkzeug unbenutzbar und
senkte die Aufmerksamkeit dort, wo sie zählt — beim Senden. Wer den Abruf
einschränken will, tut es über die Berechtigung (``WebConstraints``), und wer
ihn ganz verhindern will, erteilt den Scope nicht.
"""

from __future__ import annotations

from typing import Any

from jarvis_contracts import (
    DataClass,
    PayloadInspectability,
    RiskLevel,
    ToolResult,
    ToolSpec,
)
from jarvis_core.ports.web import WebAccessDenied, WebFetcher, WebUnavailable

__all__ = ["WEB_FETCH", "web_fetch_handler"]

MAX_BYTES = 512_000
"""Was ein Modell an einer Seite lesen soll, ist ihr Text — nicht ihr ganzes
Gewicht. Eine halbe Megabyte reicht für jeden Artikel und hält eine Antwort
ohne Ende vom Arbeitsspeicher fern."""

WEB_FETCH = ToolSpec(
    name="web.fetch",
    description=(
        "Ruft eine öffentliche Webseite ab und gibt ihren Text zurück. "
        "Nur http und https, nur öffentlich erreichbare Adressen. "
        "Lange Seiten werden gekürzt."
    ),
    parameters={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                # **Kein Beispiel.** Ein Beispiel in einer Schemabeschreibung
                # ist für ein Modell die naheliegendste Antwort: ``files.read``
                # führte eines, und das Modell gab es 3 von 3 Malen wörtlich
                # zurück. Bei einer Adresse wäre das eine erfundene Quelle.
                "description": "Vollständige Adresse der Seite, beginnend mit http:// oder https://",
            }
        },
        "required": ["url"],
        "additionalProperties": False,
    },
    returns={
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "title": {"type": "string"},
            "text": {"type": "string"},
            "truncated": {"type": "boolean"},
        },
    },
    scopes=["web.fetch"],
    risk=RiskLevel.LOW,
    data_class=DataClass.P0,
    idempotent=True,
    reads_untrusted_content=True,
    # Was das Modell sieht: Text, Titel — und die **tatsächlich** abgerufene
    # Adresse. Letztere gehört dazu, weil sie nach einer Weiterleitung eine
    # andere sein kann als die angefragte; ein Modell, das eine Quelle nennt,
    # soll die richtige nennen.
    model_visible_fields=["url", "title", "text"],
    forbidden_when_tainted=False,
    payload_inspectability=PayloadInspectability.STRUCTURED,
    outbound_fields=[],
    rate_limit="60/minute",
    timeout_s=15.0,
)


def web_fetch_handler(web: WebFetcher) -> Any:
    """Erzeugt den Handler zu einem Abrufer."""

    async def handler(**kwargs: Any) -> ToolResult:
        url = str(kwargs.get("url") or "")
        if not url:
            return ToolResult(ok=False, error="Keine Adresse angegeben.", display="Nicht abgerufen")

        try:
            dokument = await web.fetch(url, max_bytes=MAX_BYTES)
        except WebAccessDenied as verweigert:
            # Die Begründung geht an den Nutzer **und** ins Modell: Sie ist
            # eine Aussage über die Adresse, nicht über den Inhalt, und sie
            # verrät nichts über das Netzwerk, was der Aufrufer nicht schon
            # gesagt hat.
            return ToolResult(ok=False, error=str(verweigert), display="Abruf verweigert")
        except WebUnavailable as nicht_da:
            return ToolResult(ok=False, error=str(nicht_da), display="Nicht erreichbar")

        gekuerzt = " (gekürzt)" if dokument.truncated else ""
        return ToolResult(
            ok=True,
            data={
                "url": dokument.url,
                "title": dokument.title,
                "text": dokument.text,
                "truncated": dokument.truncated,
            },
            display=f"{dokument.title or dokument.url}{gekuerzt}",
            produced_data_class=DataClass.P0,
            # **Der Kern dieses Werkzeugs.** Was hier zurückkommt, hat ein
            # Fremder geschrieben — und anders als bei einer Datei hat er es
            # womöglich geschrieben, weil er wusste, dass ein Modell es liest.
            taints_context=True,
        )

    return handler
