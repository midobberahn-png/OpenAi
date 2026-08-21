"""Was ein Modell über einen Planschritt zu sehen bekommt.

Zwei Stellen fragen ein Modell nach einem Planschritt: ``plan_arguments.py``
nach den Argumenten eines Werkzeugschrittes, ``plan_response.py`` nach dem Text
eines ``llm``-Schrittes. Beide brauchen denselben Kontext — Ziel,
Schrittbeschreibung, bisheriger Verlauf — und beide brauchen an derselben
Stelle dieselbe Herkunftsmarkierung.

**Deshalb steht der Aufbau hier und nicht zweimal.** ``is_untrusted`` ist die
Angabe, an der das Model Gateway entscheidet, ob eine Antwort kontaminiert.
Zwei Fassungen desselben Aufbaus liefen irgendwann auseinander, und die zweite
wäre dann die, die das Setzen der Markierung vergisst — mit dem Ergebnis, dass
ein Lauf nach dem Lesen einer präparierten Datei wieder sauber aussieht. Das
Projekt hat diese Art Fehler mehrfach gehabt; sie entsteht nie dort, wo jemand
hinsieht.

**Was der Verlauf enthält und was nicht.** Die Zusammenfassungen erledigter
Schritte (``StepOutcome.summary``) — also für ``files.read`` Pfad und
Bytezahl, nicht den Inhalt. Das ist bewusst wenig: Sobald hier Werkzeugdaten
stünden, stünde Fremdinhalt im Prompt, und die Markierung wäre nicht mehr eine
Vorsichtsmaßnahme, sondern die einzige Absicherung. Wer das erweitert, erweitert
damit die Angriffsfläche und sollte es wissen.
"""

from __future__ import annotations

from jarvis_contracts import Message, MessageRole, PlanStep, Run

__all__ = ["PlanStepUnavailable", "schritt_nachrichten"]


class PlanStepUnavailable(Exception):
    """Ein Planschritt lässt sich nicht aus einem Modell bedienen.

    Gemeinsame Oberklasse für die beiden Quellen, damit die HTTP-Schicht einen
    Fall behandelt und nicht zwei. Ausnahme und kein Rückgabewert: Ein leeres
    Ergebnis sähe aus wie ein erfolgreicher Schritt ohne Inhalt.
    """


def schritt_nachrichten(
    *,
    auftrag: str,
    step: PlanStep,
    run: Run,
    goal: str,
) -> list[Message]:
    """Der Kontext eines Planschrittes als Nachrichtenfolge.

    ``auftrag`` ist die Systemnachricht und der einzige Teil, der sich zwischen
    den beiden Quellen unterscheidet — sie stammt aus dem Programm und ist
    vertrauenswürdig. Alles Weitere ist hier gleich, und zwar absichtlich.

    Die Markierung wandert **nicht** über die Leitung: Der Adapter schickt Rolle
    und Inhalt. Sie dem Modell mitzuschicken hieße, ihm die Kennzeichnung zur
    eigenen Verwendung zu überlassen.
    """
    nachrichten = [
        Message(role=MessageRole.SYSTEM, content=auftrag),
        Message(role=MessageRole.USER, content=f"Ziel des Vorgangs: {goal}"),
        Message(role=MessageRole.USER, content=f"Dieser Schritt: {step.description}"),
    ]

    erledigt = run.state.completed_steps
    if erledigt:
        nachrichten.append(
            Message(
                role=MessageRole.USER,
                content="Bisher erledigt:\n" + "\n".join(f"{s.seq}. {s.summary}" for s in erledigt),
                # Abgeleitet aus Werkzeugergebnissen. In einem kontaminierten
                # Lauf ist das Fremdinhalt — unabhängig davon, wie harmlos eine
                # Zusammenfassung aussieht.
                is_untrusted=run.taint_level.is_tainted,
            )
        )
    return nachrichten
