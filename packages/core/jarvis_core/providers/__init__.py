"""Sprachmodelle — der Weg dorthin, nicht die Anbieter selbst.

Hier liegt das Gateway, das über jeden Modellaufruf entscheidet. Die Adapter
liegen in ``packages/providers`` und sind die einzige Stelle im System, an der
ein Anbieter-SDK vorkommt (ADR-009).

Die Trennung ist dieselbe wie bei Werkzeugen: Der Kern entscheidet, die
Adapterschicht führt aus. Ein Modell ist aus Sicht des Sicherheitsentwurfs
nichts anderes als ein besonders redseliges Werkzeug — mit dem Unterschied,
dass es nicht nur etwas tut, sondern auch etwas zurückgibt, das gelesen wird.
"""

from .gateway import ModelGateway, ModelNotPermitted

__all__ = ["ModelGateway", "ModelNotPermitted"]
