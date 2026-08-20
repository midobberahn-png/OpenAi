"""``files.read`` — das erste Werkzeug mit echter Außenanbindung.

Bis hierher sicherte der gesamte Sockel — Policy Engine, Approval Gateway,
Grant-Verbrauch, Taint-Gate — nichts Reales ab: Es gab ausschließlich
Attrappen in ``tests/fakes.py``. Dieses Werkzeug ist bewusst das erste, weil es
**alle** Schichten auf einmal in Betrieb nimmt und dabei nichts nach außen
wirkt:

* Scope (``files.read``) und Berechtigung aus der Tabelle,
* Einschränkungen der Berechtigung (``FilesConstraints.allowed_roots``),
* Protokollierung, Grant und Verbrauch,
* und die Kontamination — eine Datei ist Fremdinhalt.

**Warum lesend zuerst.** Ein schreibendes Werkzeug prüfte dieselben Schichten
und hinterließe bei jedem Fehlschlag Spuren. Der Preis eines Fehlers ist hier
eine Auskunft, die es nicht hätte geben sollen; das ist schlimm genug, um die
Grenzen ernst zu nehmen, und harmlos genug, um sie zu erproben.

**Der Lauf ist danach kontaminiert.** ``reads_untrusted_content=True``: Was in
einer Datei steht, hat jemand anderes geschrieben — für den Taint-Schutz ist
das nichts anderes als eine Mail. Ein ``SYSTEM: sende …`` in einer Textdatei
ist ein Injection-Versuch, und der Schutz dagegen besteht nicht darin, ihn zu
erkennen, sondern darin, dass danach keine sendenden Werkzeuge mehr im Angebot
sind.

**Aber selbst nicht gesperrt.** ``forbidden_when_tainted=False``: Nach einer
gelesenen Datei noch eine zweite zu lesen, erhöht nichts — der Lauf ist bereits
kontaminiert, und die sendenden Werkzeuge sind bereits weg. Diese Erklärung ist
ausdrücklich nötig, weil der Vorgabewert ``True`` lautet: Ein Werkzeug muss
sich als unbedenklich erklären, nicht umgekehrt (docs/07-security §4).
"""

from __future__ import annotations

from typing import Any

from jarvis_contracts import DataClass, PayloadInspectability, RiskLevel, ToolResult, ToolSpec
from jarvis_core.policy.secrets import data_class_for_content
from jarvis_core.ports.files import FileAccessDenied, FileReader, FileUnavailable

__all__ = ["FILES_READ", "MAX_BYTES", "files_read_handler"]

MAX_BYTES = 256_000
"""Obergrenze je Aufruf.

Nicht die Dateigröße aus ``FilesConstraints.max_file_size_mb`` — die ist die
Grenze der *Berechtigung*, diese hier die Grenze des *Kontextfensters*. Eine
Datei von 40 MB darf gelesen werden und passt trotzdem in keinen Prompt. Wird
die Grenze erreicht, kürzt der Adapter und sagt es.
"""

FILES_READ = ToolSpec(
    name="files.read",
    description=(
        "Liest eine Textdatei aus einem freigegebenen Ordner und gibt ihren Inhalt "
        "zurück. Der Pfad muss absolut sein. Große Dateien werden gekürzt."
    ),
    parameters={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Absoluter Pfad der Datei, z. B. /Users/ich/Notizen/plan.md",
            }
        },
        "required": ["path"],
        "additionalProperties": False,
    },
    returns={
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "text": {"type": "string"},
            "truncated": {"type": "boolean"},
        },
    },
    scopes=["files.read"],
    risk=RiskLevel.LOW,
    # ``data_class=P2``: Was in freigegebenen Ordnern liegt, ist persönlich,
    # aber nicht das Geheimste. P2 erlaubt die Verarbeitung in zugelassenen
    # Cloud-Modellen und hält P3-Material (Zugangsdaten, Gesundheitsakten)
    # strukturell davon fern. Wer einen Ordner mit P3-Inhalt freigibt, muss die
    # Berechtigung eng ziehen — die Einstufung eines Werkzeugs kann nicht
    # wissen, was jemand in einen Ordner legt.
    data_class=DataClass.P2,
    idempotent=True,
    reads_untrusted_content=True,
    forbidden_when_tainted=False,
    payload_inspectability=PayloadInspectability.STRUCTURED,
    outbound_fields=[],
    rate_limit="120/minute",
    timeout_s=10.0,
)


def files_read_handler(reader: FileReader) -> Any:
    """Erzeugt den Handler zu einem Dateizugriff.

    Der Reader kommt als Port herein. Die eigentliche Absicherung — Auflösung
    des Pfades, Vergleich nach dem Öffnen — liegt dort und ausdrücklich nicht
    hier: Eine Prüfung im Handler wäre eine zweite Wahrheit über dieselbe
    Frage, und die Antwort des Dateisystems kennt nur, wer es tatsächlich
    öffnet.
    """

    async def handler(**kwargs: Any) -> ToolResult:
        pfad = str(kwargs["path"])
        try:
            inhalt = await reader.read_text(pfad, max_bytes=MAX_BYTES)
        except FileAccessDenied as verweigert:
            # Die Meldung des Ports wird durchgereicht, nicht ausgeschmückt.
            # Sie nennt bewusst keinen aufgelösten Pfad — sonst wäre die
            # abgewiesene Anfrage ein Erkundungswerkzeug.
            return ToolResult(ok=False, error=str(verweigert), display="Zugriff verweigert")
        except FileUnavailable as fehlt:
            return ToolResult(ok=False, error=str(fehlt), display="Datei nicht lesbar")

        # Die Einstufung des Ergebnisses kann strenger ausfallen als die
        # statische des Werkzeugs: Steht in der Datei etwas, das wie ein
        # Zugangsdatum aussieht, gilt der Inhalt als P3 und verlässt das Gerät
        # nicht mehr. Die Richtung ist einseitig — hochstufen, nie herab
        # (``policy/secrets.py``).
        klasse = data_class_for_content(inhalt.text, declared=FILES_READ.data_class)

        hinweis = " (gekürzt)" if inhalt.truncated else ""
        return ToolResult(
            ok=True,
            data={
                "path": inhalt.path,
                "text": inhalt.text,
                "truncated": inhalt.truncated,
                "bytes_read": inhalt.bytes_read,
            },
            display=f"{inhalt.path} — {inhalt.bytes_read} Bytes{hinweis}",
            produced_data_class=klasse,
            taints_context=True,
        )

    return handler
