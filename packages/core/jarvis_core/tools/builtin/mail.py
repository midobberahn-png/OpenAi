"""``mail.read`` — das erste Werkzeug, das ein verbundenes Konto benutzt.

Und das erste, bei dem der Fremdinhalt **nicht** vom Modell ausgesucht wurde.

**Warum das schärfer ist als ``web.fetch``.** Dort nennt ein Modell eine
Adresse; wer dort Text unterschiebt, muss erst dafür sorgen, dass das Modell
seine Seite anfragt. Ein Postfach dagegen ist eine Adresse, die jeder kennt:
**Ein Angreifer entscheidet allein, dass sein Text im Kontext des Modells
landet.** Er braucht keine Suchmaschinenplatzierung und keinen Zufall — er
braucht eine Mailadresse. Die untergeschobene Anweisung ist hier der
Normalfall und nicht der Grenzfall, und deshalb ist ``taints_context=True``
an diesem Werkzeug keine Vorsicht, sondern seine Existenzbedingung.

**P2, und was daran hängt.** ``docs/00-uebersicht.md §8`` sagt es
ausdrücklich: „der Mail-Connector markiert alles als P2". Damit bleibt der
Inhalt bei den Anbietern, die dafür freigegeben sind — er ist nicht
öffentlich wie eine Webseite und nicht harmlos wie ein Kalendertitel. Die
Einstufung ist eine Aussage über **Sensibilität**; dass der Inhalt nicht
vertrauenswürdig ist, sagt ``reads_untrusted_content``. Bei diesem Werkzeug
trifft zum ersten Mal beides zugleich zu.

**Zwei Erlaubnisse mit demselben Wort.** ``mail.read`` ist unser Scope — was
der Nutzer diesem System erlaubt hat. ``gmail.readonly`` ist Googles Scope —
was der Nutzer bei der Zustimmung bewilligt hat. Beide müssen gelten, und
keiner ersetzt den anderen: Ein erteilter Scope ohne Bewilligung endet in
einem 403 des Anbieters, eine Bewilligung ohne Scope wäre eine
Rechteerteilung, die niemand vorgenommen hat. Geprüft wird deshalb an beiden
Stellen — die Policy prüft das eine, die Verdrahtung das andere.

**Kein Versand, keine Löschung, kein Markieren.** Der Scope-Katalog führt sie;
dieses Werkzeug und sein Port können sie nicht. Der Unterschied ist derselbe
wie beim Kalender: Der Handler tut es nicht, weil er es nicht kann — nicht,
weil es ihm verboten wäre.
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
from jarvis_core.ports.mail import MailAccessDenied, MailReader, MailUnavailable

__all__ = ["MAIL_READ", "mail_read_handler"]

STANDARD_ANZAHL = 10

MAIL_READ = ToolSpec(
    name="mail.read",
    description=(
        "Liest die jüngsten Nachrichten aus dem verbundenen Postfach. "
        "Gibt Absender, Betreff, Datum und Text zurück. Lange Nachrichten "
        "werden gekürzt."
    ),
    parameters={
        "type": "object",
        "properties": {
            "anzahl": {
                "type": "integer",
                "minimum": 1,
                "maximum": 25,
                "description": "Wie viele Nachrichten, höchstens 25.",
            },
            "suche": {
                "type": "string",
                # **Kein Beispiel**, aus derselben Erfahrung wie bei
                # ``files.read``: Ein Modell, das raten muss, gibt das Beispiel
                # wörtlich zurück. Hier wäre das eine erfundene Suche, deren
                # Ergebnis wie eine Antwort aussieht.
                "description": (
                    "Optionaler Suchausdruck des Anbieters. Ohne Angabe die jüngsten Nachrichten."
                ),
            },
        },
        "required": [],
        "additionalProperties": False,
    },
    returns={
        "type": "object",
        "properties": {
            "messages": {"type": "array"},
            "count": {"type": "integer"},
        },
    },
    scopes=["mail.read"],
    risk=RiskLevel.LOW,
    # Lesen verändert nichts — auch nicht den Gelesen-Status: Der Adapter holt
    # mit ``format=full`` und markiert nicht. Ein Werkzeug, das beim Lesen
    # etwas verändert, wäre nicht idempotent, und niemand hätte es gemerkt.
    idempotent=True,
    data_class=DataClass.P2,
    reads_untrusted_content=True,
    model_visible_fields=["messages", "count"],
    forbidden_when_tainted=False,
    payload_inspectability=PayloadInspectability.STRUCTURED,
    outbound_fields=[],
    rate_limit="30/minute",
    timeout_s=30.0,
)


def mail_read_handler(mail: MailReader) -> Any:
    """Erzeugt den Handler zu einem Postfachleser.

    Der Leser ist **beim Verdrahten** an ein Konto gebunden, wie beim Kalender
    und aus demselben Grund: Ein Argument ``konto`` wäre dieselbe Lücke wie
    ``user_id`` im Request-Body, nur eine Schicht tiefer.
    """

    async def handler(**kwargs: Any) -> ToolResult:
        roh_anzahl = kwargs.get("anzahl")
        anzahl = roh_anzahl if isinstance(roh_anzahl, int) else STANDARD_ANZAHL
        roh_suche = kwargs.get("suche")
        suche = roh_suche if isinstance(roh_suche, str) and roh_suche.strip() else None

        try:
            nachrichten = await mail.lesen(anzahl=anzahl, suche=suche)
        except MailAccessDenied as verweigert:
            return ToolResult(ok=False, error=str(verweigert), display="Kein Zugriff")
        except MailUnavailable as nicht_da:
            return ToolResult(ok=False, error=str(nicht_da), display="Nicht erreichbar")

        return ToolResult(
            ok=True,
            data={
                "messages": [
                    {
                        "id": n.id,
                        "from": n.absender,
                        "subject": n.betreff,
                        "date": n.datum.isoformat() if n.datum else None,
                        "text": n.text,
                        "truncated": n.gekuerzt,
                    }
                    for n in nachrichten
                ],
                "count": len(nachrichten),
            },
            display=f"{len(nachrichten)} Nachricht(en)",
            produced_data_class=DataClass.P2,
            # **Der Kern dieses Werkzeugs.** Jeder, der die Adresse kennt,
            # kann hier Text hineinlegen — ohne Umweg, ohne Zufall und in dem
            # Wissen, dass ein Modell ihn liest.
            taints_context=True,
        )

    return handler
