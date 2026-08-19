"""Anbieteradapter — die einzige Stelle im System mit Provider-SDKs.

Siehe ADR-009. Der Kern kennt nur ``LLMProvider``; was hier liegt, übersetzt
zwischen diesem Protokoll und dem, was ein Anbieter tatsächlich spricht.

Zwei Regeln gelten für jeden Adapter hier:

1. **Er entscheidet nichts.** Ob eine Anfrage gestellt werden durfte, hat das
   Model Gateway vorher geklärt. Ein Adapter, der selbst prüft, hätte die
   Daten bereits — und bei einem Netzwerkadapter wären sie damit unterwegs.
2. **Er verschluckt keine Fehler.** Eine leere Antwort statt einer Ausnahme
   macht aus einem Ausfall eine Erfindung (docs/04-orchestrator.md §9).
"""

from .ollama import OllamaProvider

__all__ = ["OllamaProvider"]
