"""Argumente gegen das Werkzeugschema prüfen.

``ToolSpec.parameters`` ist JSON Schema. Bis hierher wurde es an genau einer
Stelle gelesen — in ``ToolRegistry.to_schema()``, also dort, wo dem Modell
mitgeteilt wird, was es schicken soll. Was zurückkam, hat niemand dagegen
gehalten:

    additionalProperties: false     stand im Schema und galt nicht
    required: [title, start, end]   stand im Schema und galt nicht

Das war tragbar, solange ein Mensch die Argumente tippte. Ab der Modellschleife
formuliert sie ein Modell, das eine kontaminierte Datei gelesen haben kann —
und dann ist ein Schema ohne Gegenprüfung eine Ansage nach außen ohne Kontrolle
nach innen.

**Warum das eine Sicherheitsfrage ist und nicht Hygiene.** Der Payload eines
bestätigungspflichtigen Aufrufs wandert durch drei Stellen, an denen er wirkt:
die Vorschau, die ein Mensch liest; den Payload-Hash, der sie an die Ausführung
bindet; und den Handler. Ein erfundenes Feld erscheint in der Vorschau als
Zeile, als gehörte es zur Aktion — und die Vorschau ist genau der Ort, an dem
ein eingeschmuggelter Inhalt auffallen muss. ``build_preview`` behauptet in
seinem Docstring seit jeher, aus dem *validierten* Argument-Objekt zu bauen.
Diese Datei macht die Behauptung wahr.

**Warum die Referenzimplementierung.** Ein handgeschriebener Prüfer für die
gerade benutzte Teilmenge wäre schnell geschrieben und wäre die zweite Wahrheit
über dasselbe Schema. Daran ist ``FilesConstraints.check()`` schon einmal
gescheitert: Eine Pfadprüfung, die nachbildete, was ein anderes System tut, lag
bei der ersten unbedachten Eingabe daneben. ``jsonschema`` ist kein Framework,
sondern die Umsetzung eines Formats, auf das dieses Projekt sich ohnehin
festgelegt hat.

**Was hier nicht passiert: normalisieren.** Die Prüfung lässt durch oder weist
ab und gibt dasselbe Objekt zurück. Ein Validator, der nebenbei umschreibt —
Vorgabewerte einsetzt, Zahlen in Strings wandelt —, veränderte den Payload
zwischen Vorschau und Hash. Bestätigt wird, was angezeigt wurde; ausgeführt
wird, was bestätigt wurde. Dazwischen darf nichts umgeschrieben werden.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import jsonschema
from jsonschema import Draft202012Validator

from jarvis_contracts import ToolSpec

__all__ = ["ArgumentsRejected", "validate_arguments"]


class ArgumentsRejected(Exception):
    """Die Argumente passen nicht zum Schema des Werkzeugs.

    Ausnahme und kein Rückgabewert, aus demselben Grund wie bei
    ``ExecutionDenied``: Ein Aufrufer, der einen Rückgabewert übersieht, führte
    sonst mit ungeprüften Argumenten aus.
    """


def validate_arguments(spec: ToolSpec, arguments: dict[str, Any]) -> dict[str, Any]:
    """Prüft ``arguments`` gegen ``spec.parameters`` und gibt sie unverändert zurück.

    Der Rückgabewert ist bewusst dasselbe Objekt und nicht eine Kopie mit
    Vorgabewerten: Was geprüft wurde, ist was ausgeführt wird.
    """
    try:
        Draft202012Validator(spec.parameters).validate(arguments)
    except jsonschema.ValidationError as verstoss:
        raise ArgumentsRejected(
            f"Argumente von {spec.name!r} passen nicht zum Schema: {_meldung(verstoss)}"
        ) from verstoss
    except jsonschema.SchemaError as kaputt:  # pragma: no cover - Fehler im Katalog
        # Ein fehlerhaftes Schema ist ein Konfigurationsfehler des Werkzeugs
        # und kein Berechtigungsproblem — aber er darf nicht dazu führen, dass
        # ungeprüfte Argumente durchlaufen. Fail closed.
        raise ArgumentsRejected(
            f"Das Schema von {spec.name!r} ist selbst ungültig; es wird nichts ausgeführt."
        ) from kaputt
    return arguments


def _meldung(verstoss: jsonschema.ValidationError) -> str:
    """Benennt Feld und Regel — und zitiert den abgelehnten Wert nicht.

    Die Meldung geht als ``tool``-Nachricht in den Modellkontext zurück, damit
    das Modell es anders versuchen kann. Ein Validator, der den abgelehnten
    Wert mitliefert, schriebe damit Fremdinhalt in genau die Nachricht, die
    anschließend wieder im Prompt steht — der Weg, den das Taint-Tracking
    schließen soll, einmal quer durch die Fehlerbehandlung.

    ``jsonschema`` setzt den Wert standardmäßig in ``str(fehler)``. Deshalb
    wird die Meldung hier aus den strukturierten Feldern gebaut statt
    durchgereicht.
    """
    pfad = ".".join(str(teil) for teil in verstoss.absolute_path) or "(Wurzel)"

    if verstoss.validator == "required":
        # ``message`` lautet „'start' is a required property" — kein Wert darin.
        return f"Pflichtfeld fehlt: {verstoss.message}"
    if verstoss.validator == "additionalProperties":
        schema = verstoss.schema if isinstance(verstoss.schema, Mapping) else {}
        erlaubt = set(schema.get("properties", {}))
        vorgelegt = set(verstoss.instance) if isinstance(verstoss.instance, Mapping) else set()
        return (
            f"Unbekannte Felder: {', '.join(sorted(vorgelegt - erlaubt))}. "
            f"Erlaubt sind: {', '.join(sorted(erlaubt)) or '(keine)'}."
        )
    if verstoss.validator == "type":
        return f"Feld {pfad!r} hat den falschen Typ (erwartet: {verstoss.validator_value})."
    return f"Feld {pfad!r} verletzt die Regel {verstoss.validator!r}."
