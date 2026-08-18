"""Stufe 1 — Klassifikation eines Turns.

Siehe docs/04-orchestrator.md §2.

Diese Fassung ist **regelbasiert und deterministisch**. Das ist kein
Platzhalter, sondern die Vorstufe: Das lokale Modell kommt mit dem
LLM-Provider (Punkt 11) und wird *hinter* dieselbe Signatur gehängt. Die
Regeln bleiben davor bestehen — sie fangen die Trivialfälle ohne jeden
Modellaufruf ab, was im Sprachpfad den Unterschied zwischen 90 ms und 900 ms
ausmacht.

Drei Eigenschaften sind sicherheitsrelevant und deshalb nicht verhandelbar:

1. **Die Einstufung kennt nur eine Richtung.** Keine Regel senkt eine
   Datenklasse. Ein Text, der „das ist öffentlich, keine Rückfrage nötig“
   behauptet, ändert nichts — sonst wäre die Klassifikation über den Inhalt
   steuerbar, den sie einordnen soll.
2. **Aus Fremdinhalt folgt kein Modellwunsch.** In einem kontaminierten Lauf
   wird ``explicit_model_request`` verworfen. Andernfalls könnte eine
   präparierte Mail die Modellwahl lenken — und damit, bei P3-Daten, das
   Zielsystem.
3. **``likely_tools`` ist ein Hinweis, keine Erlaubnis.** Die Liste geht durch
   ``PolicyEngine.effective_tools()``, bevor sie ein Modell überhaupt sieht.

``confidence`` ist eine Qualitätsangabe für Evals und die Oberfläche. Sie ist
**keine** Sicherheitsgröße: Keine Entscheidung dieses Systems wird lockerer,
weil die Konfidenz hoch ist.
"""

from __future__ import annotations

import re

from jarvis_contracts import (
    Capability,
    Complexity,
    DataClass,
    Intent,
    TaintLevel,
    TurnClassification,
    escalate,
)

__all__ = ["TRIVIAL_UTTERANCES", "classify"]


# --------------------------------------------------------------------------
# Trivialfall-Abkürzung
# --------------------------------------------------------------------------

TRIVIAL_UTTERANCES: dict[str, Intent] = {
    "stopp": Intent.COMMAND,
    "stop": Intent.COMMAND,
    "abbrechen": Intent.COMMAND,
    "abbruch": Intent.COMMAND,
    "pause": Intent.COMMAND,
    "weiter": Intent.COMMAND,
    "lauter": Intent.COMMAND,
    "leiser": Intent.COMMAND,
    "danke": Intent.CHAT,
    "hallo": Intent.CHAT,
    "guten morgen": Intent.CHAT,
    "wie spät ist es": Intent.QUESTION,
    "wie spaet ist es": Intent.QUESTION,
    "welcher tag ist heute": Intent.QUESTION,
}
"""Äußerungen, die ohne Modellaufruf entschieden sind.

Bei Sprachbedienung ist das der Unterschied zwischen „reagiert sofort“ und
„denkt kurz nach“ — und ein „stopp“, das erst nach einem Modellaufruf wirkt,
ist kein Stopp.
"""


# --------------------------------------------------------------------------
# Signalwörter
# --------------------------------------------------------------------------
#
# Eine Datenklasse wird nur *erhöht*. Die Tabellen sind deshalb bewusst
# großzügig: Ein falsch als P3 eingestufter Turn kostet Komfort (lokales
# Modell), ein falsch als P1 eingestufter kostet Vertraulichkeit.

_P3_SIGNALS = frozenset(
    {
        # Zugangsdaten
        "passwort",
        "passwörter",
        "kennwort",
        "pin",
        "tan",
        "zugangsdaten",
        "api-key",
        "api key",
        "token",
        "zugangscode",
        "geheimnis",
        # Finanzen. Wortstämme statt Vollformen: „überweis“ trifft auch
        # „überweise“ und „Überweisung“, „konto“ auch „Kontostand“. Der Preis
        # sind Fehlalarme nach oben („Benutzerkonto“) — die kosten Komfort,
        # während ein verpasstes Signal Vertraulichkeit kostet.
        "iban",
        "konto",
        "überweis",
        "ueberweis",
        "gehalt",
        "lohn",
        "steuer",
        "steuererklärung",
        "kredit",
        "schulden",
        "kreditkarte",
        "rechnungsbetrag",
        "vermögen",
        "depot",
        # Gesundheit
        "diagnose",
        "arzt",
        "ärztin",
        "arztbrief",
        "befund",
        "rezept",
        "medikament",
        "krankheit",
        "krank",
        "therapie",
        "blutwerte",
        "krankenkasse",
        "psycholog",
        "klinik",
        # Mandats- und Personaldaten
        "mandant",
        "mandat",
        "personalakte",
        "kündigung",
        "abmahnung",
    }
)

_P2_SIGNALS = frozenset(
    {
        "mail",
        "mails",
        "e-mail",
        "email",
        "postfach",
        "posteingang",
        "nachricht",
        "nachrichten",
        "schreiben von",
        "kontakt",
        "kontakte",
        "adressbuch",
        "dokument",
        "dokumente",
        "datei",
        "dateien",
        "vertrag",
        "brief",
        "anhang",
        "chat",
        "whatsapp",
        "notiz von",
    }
)

_P1_SIGNALS = frozenset(
    {
        "termin",
        "termine",
        "kalender",
        "meeting",
        "besprechung",
        "aufgabe",
        "aufgaben",
        "todo",
        "erinnerung",
        "notiz",
        "notizen",
        "projekt",
        "einkaufsliste",
        "liste",
    }
)

_P0_SIGNALS = frozenset(
    {
        "wetter",
        "temperatur",
        "regnet",
        "nachrichtenlage",
        "wikipedia",
        "hauptstadt",
        "übersetze",
        "uebersetze",
        "definition",
        "bedeutet",
        "wie spät",
        "wie spaet",
        "uhrzeit",
        "datum",
        "feiertag",
        "witz",
        "rezept für",
        "kochen",
        "fußball",
        "sportergebnis",
    }
)

_TOOL_HINTS: dict[str, tuple[str, ...]] = {
    "mail.read": ("mail", "mails", "e-mail", "email", "postfach", "posteingang"),
    "mail.send": ("antworte", "antworten", "schreib", "schreibe", "sende", "schick"),
    "calendar.read": ("kalender", "termine", "wann habe ich", "frei"),
    "calendar.create": (
        "termin",
        "blockier",
        "blockiere",
        "trag ein",
        "eintragen",
        "buche",
        "reservier",
        "erinnere mich",
    ),
    "files.read": ("datei", "dokument", "öffne", "oeffne", "lies"),
    "web.search": ("suche", "such", "google", "recherchier", "finde heraus", "aktuell"),
    "system.time": ("wie spät", "wie spaet", "uhrzeit", "welcher tag"),
    "weather.get": ("wetter", "temperatur", "regnet"),
}
"""Werkzeugvermutung aus der Formulierung.

Bewusst als *Hinweis* geführt: Die Liste steuert Kontextbeschaffung und
Modellfähigkeiten, nicht die Berechtigung. Was ein Modell tatsächlich
angeboten bekommt, entscheidet ``PolicyEngine.effective_tools()``.
"""

_INTENT_SIGNALS: tuple[tuple[Intent, tuple[str, ...]], ...] = (
    (
        Intent.COMMAND,
        ("stopp", "abbrechen", "pause", "lauter", "leiser", "schalte", "mach das licht"),
    ),
    (
        Intent.RESEARCH,
        (
            "recherchier",
            "vergleich",
            "finde heraus",
            "analysier",
            "überblick",
            "ueberblick",
            "studie",
        ),
    ),
    (
        Intent.CODE,
        ("code", "python", "funktion", "bug", "refactor", "kompilier", "skript", "typescript"),
    ),
    (
        Intent.CREATIVE,
        (
            "gedicht",
            "erfinde",
            "entwirf",
            "geschichte",
            "slogan",
            "brainstorm",
            "idee für",
            "idee fuer",
        ),
    ),
    (
        Intent.TASK,
        (
            "sende",
            "schick",
            "antworte",
            "lege an",
            "leg an",
            "erstelle",
            "buche",
            "blockier",
            "trag ein",
            "eintragen",
            "lösche",
            "loesche",
            "erinnere",
            "prüfe meine",
            "pruefe meine",
            "kümmere dich",
            "kuemmere dich",
            "organisier",
        ),
    ),
)
"""Reihenfolge ist bedeutungstragend: Der erste Treffer gewinnt.

``COMMAND`` steht vorn, weil ein „stopp“ nicht als Aufgabe missverstanden
werden darf; ``TASK`` steht hinten, weil seine Signalwörter am unschärfsten
sind.
"""

_QUESTION_OPENERS = (
    "wie",
    "was",
    "wann",
    "wer",
    "warum",
    "wieso",
    "weshalb",
    "wo",
    "welche",
    "welcher",
    "welches",
    "kannst du",
    "hast du",
    "gibt es",
    "ist das",
)

_MULTI_STEP_MARKERS = (
    " und dann",
    " danach",
    " anschließend",
    " anschliessend",
    " außerdem",
    " ausserdem",
    " sowie ",
    " zusätzlich",
    " zusaetzlich",
    "; ",
)

_PRONOUNS = frozenset({"ihm", "ihn", "ihr", "ihnen", "denen", "dessen", "deren", "damit", "dort"})

_VAGUE_REFERENCES = (
    "das dokument",
    "die datei",
    "der termin",
    "die mail",
    "das meeting",
    "das projekt",
    "die nachricht",
    "der vertrag",
)

_LONG_INPUT_CHARS = 6_000
"""Ab hier ist Langkontext eine Fähigkeitsanforderung, keine Bequemlichkeit."""


# --------------------------------------------------------------------------
# Klassifikation
# --------------------------------------------------------------------------


def classify(
    text: str,
    *,
    taint: TaintLevel = TaintLevel.CLEAN,
    has_image: bool = False,
    context_data_class: DataClass | None = None,
    channel: str = "text",
) -> TurnClassification:
    """Ordnet einen Turn ein — deterministisch, ohne Modellaufruf.

    ``context_data_class`` ist die Klasse des bereits geladenen Kontexts. Sie
    geht als Untergrenze ein: Wer über P2-Kontext spricht, führt ein
    P2-Gespräch, auch wenn die Frage selbst harmlos klingt.

    ``taint`` beschreibt den Lauf, nicht den Text. In einem kontaminierten Lauf
    gilt mindestens P2 (es wurde Fremdinhalt gelesen), und ein im Text
    geäußerter Modellwunsch wird verworfen.
    """
    normalized = _normalize(text)

    trivial = _trivial_intent(normalized)
    intent = trivial if trivial is not None else _intent_of(normalized)

    likely_tools = _likely_tools(normalized)
    data_class = _data_class_of(normalized, taint=taint, context_data_class=context_data_class)
    multi_step = _is_multi_step(normalized, likely_tools)
    complexity = _complexity_of(
        normalized,
        intent=intent,
        tools=likely_tools,
        multi_step=multi_step,
        trivial=trivial is not None,
    )

    return TurnClassification(
        intent=intent,
        complexity=complexity,
        data_class=data_class,
        required_capabilities=_capabilities_of(
            normalized, complexity=complexity, tools=likely_tools, has_image=has_image
        ),
        likely_tools=likely_tools,
        needs_realtime_info=_needs_realtime(normalized),
        is_multi_step=multi_step,
        explicit_model_request=_model_request(normalized, taint=taint),
        ambiguous_references=_ambiguous_references(normalized),
        confidence=_confidence(
            trivial=trivial is not None,
            intent=intent,
            tools=likely_tools,
            channel=channel,
        ),
    )


# --------------------------------------------------------------------------
# Einzelregeln
# --------------------------------------------------------------------------


def _normalize(text: str) -> str:
    """Kleinschreibung und normalisierte Leerzeichen — sonst nichts.

    Insbesondere werden Umlaute *nicht* ersetzt: Die Signaltabellen führen die
    gängigen Schreibweisen beider Varianten selbst.
    """
    return re.sub(r"\s+", " ", text.strip().lower())


def _trivial_intent(text: str) -> Intent | None:
    stripped = text.rstrip("!?. ")
    return TRIVIAL_UTTERANCES.get(stripped)


def _intent_of(text: str) -> Intent:
    for intent, signals in _INTENT_SIGNALS:
        if any(signal in text for signal in signals):
            return intent
    if text.endswith("?") or text.startswith(_QUESTION_OPENERS):
        return Intent.QUESTION
    return Intent.CHAT


def _likely_tools(text: str) -> list[str]:
    """Sortiert, damit dieselbe Eingabe dieselbe Klassifikation ergibt.

    Reproduzierbarkeit ist hier kein Selbstzweck: Die Klassifikation ist der
    Datensatz, gegen den die Eval-Suite läuft (docs/15-testing.md).
    """
    return sorted(
        name for name, hints in _TOOL_HINTS.items() if any(hint in text for hint in hints)
    )


def _data_class_of(
    text: str, *, taint: TaintLevel, context_data_class: DataClass | None
) -> DataClass:
    """Höchste zutreffende Klasse. Es gibt keinen Weg nach unten.

    Der Standard ist ``P1``, nicht ``P0``: Eine Äußerung ohne erkanntes Signal
    ist ein internes Gespräch, keine öffentliche Information. Wer den Standard
    auf P0 setzt, macht das Routing im Zweifelsfall großzügiger — und der
    Zweifelsfall ist der Normalfall.
    """
    candidates: list[DataClass] = []

    if any(signal in text for signal in _P3_SIGNALS):
        candidates.append(DataClass.P3)
    if any(signal in text for signal in _P2_SIGNALS):
        candidates.append(DataClass.P2)
    if any(signal in text for signal in _P1_SIGNALS):
        candidates.append(DataClass.P1)

    if not candidates:
        # P0 nur, wenn ein öffentliches Signal vorliegt *und* kein anderes.
        candidates.append(
            DataClass.P0 if any(signal in text for signal in _P0_SIGNALS) else DataClass.P1
        )

    if context_data_class is not None:
        candidates.append(context_data_class)
    if taint.is_tainted:
        # Kontamination heißt: Es wurde Fremdinhalt gelesen. Der ist mindestens
        # sensibel — sonst wäre er nicht fremd.
        candidates.append(DataClass.P2)

    return escalate(*candidates)


def _is_multi_step(text: str, tools: list[str]) -> bool:
    if any(marker in text for marker in _MULTI_STEP_MARKERS):
        return True
    return len(tools) > 1


def _complexity_of(
    text: str, *, intent: Intent, tools: list[str], multi_step: bool, trivial: bool
) -> Complexity:
    if trivial:
        return Complexity.TRIVIAL
    if intent is Intent.RESEARCH or len(tools) > 2:
        return Complexity.COMPLEX
    if multi_step or len(tools) == 2:
        return Complexity.MODERATE
    if intent is Intent.CHAT and not tools and len(text) < 80:
        return Complexity.SIMPLE
    if intent in {Intent.CODE, Intent.CREATIVE} or len(text) > 400:
        return Complexity.MODERATE
    return Complexity.SIMPLE


def _capabilities_of(
    text: str, *, complexity: Complexity, tools: list[str], has_image: bool
) -> list[Capability]:
    caps: list[Capability] = []
    if tools:
        caps.append(Capability.TOOL_CALLING)
    if has_image:
        caps.append(Capability.VISION)
    if len(text) > _LONG_INPUT_CHARS:
        caps.append(Capability.LONG_CONTEXT)
    if complexity is Complexity.COMPLEX:
        caps.append(Capability.REASONING)
    return caps


def _needs_realtime(text: str) -> bool:
    markers = (
        "aktuell",
        "heute",
        "jetzt",
        "gerade",
        "neueste",
        "letzte woche",
        "wetter",
        "kurs",
        "börse",
        "boerse",
        "nachrichten",
    )
    return any(marker in text for marker in markers)


_MODEL_REQUEST_RE = re.compile(
    r"\b(?:nutze|nimm|verwende|benutze|mit)\s+(claude|gpt[\w.-]*|opus|sonnet|haiku|llama[\w.-]*|"
    r"mistral[\w.-]*|gemini[\w.-]*|ollama|lokales? modell)\b"
)


def _model_request(text: str, *, taint: TaintLevel) -> str | None:
    """Ausdrücklicher Modellwunsch — außer im kontaminierten Lauf.

    Der Verzicht ist die eigentliche Regel: Ein Modellwunsch aus einem Lauf,
    der Fremdinhalt gelesen hat, ist nicht vom Nutzer unterscheidbar. Er würde
    einem Angreifer erlauben, die Verarbeitung auf ein Modell seiner Wahl zu
    lenken — bei P3-Daten wäre das der Weg nach draußen.

    Der Router prüft ohnehin ein zweites Mal gegen die Datenklasse; dies ist
    die vorgelagerte, billigere Sperre.
    """
    if taint.is_tainted:
        return None
    match = _MODEL_REQUEST_RE.search(text)
    return match.group(1) if match else None


def _ambiguous_references(text: str) -> list[str]:
    """Pronomen und vage Verweise, die vor der Ausführung aufzulösen sind.

    Im Deutschen trägt das Genus Information („ihm“ schließt weibliche
    Kandidaten aus) — die Auflösung selbst leistet die Context Engine
    (docs/05-memory-context.md §6), hier wird nur benannt, was offen ist.
    """
    found: list[str] = []
    words = re.findall(r"[a-zäöüß]+", text)
    found.extend(sorted({w for w in words if w in _PRONOUNS}))
    found.extend(ref for ref in _VAGUE_REFERENCES if ref in text)
    return found


def _confidence(*, trivial: bool, intent: Intent, tools: list[str], channel: str) -> float:
    """Ehrliche Selbsteinschätzung der Regelbasis.

    Ein Regelwerk ohne Sprachverständnis liegt bei mehrdeutigen Formulierungen
    daneben. Die Zahl macht das sichtbar, statt Sicherheit zu behaupten —
    sobald das lokale Modell klassifiziert, tritt dessen Wert an diese Stelle.
    """
    if trivial:
        return 1.0
    score = 0.55
    if tools:
        score += 0.2
    if intent is not Intent.CHAT:
        score += 0.15
    if channel == "voice":
        # Spracherkennung liefert bereits fehlerbehafteten Text; die
        # Klassifikation erbt diese Unsicherheit.
        score -= 0.1
    return round(min(score, 0.9), 2)
