"""Orchestrator — entscheidet, *was* passiert; ausgeführt wird woanders.

Siehe docs/04-orchestrator.md.

Die prägende Eigenschaft dieses Pakets ist eine Nicht-Eigenschaft: Der
Orchestrator bildet **keine** Meinung darüber, ob etwas erlaubt ist. Er
klassifiziert, routet, plant und führt aus — und fragt für jede Aktion mit
Außenwirkung die Policy Engine und das Ausführungs-Gate.

Der Grund steht in der Invariante ``orchestrator-consumes-decisions``: Sobald
der Orchestrator selbst beurteilt, was „wahrscheinlich sicher“ ist, gibt es
zwei Wahrheiten über Berechtigungen — und die zweite prüft niemand.
"""

from .classifier import TRIVIAL_UTTERANCES, classify
from .router import (
    HealthSnapshot,
    NoEligibleModel,
    RoutingPreferences,
    route,
)

__all__ = [
    "TRIVIAL_UTTERANCES",
    "HealthSnapshot",
    "NoEligibleModel",
    "RoutingPreferences",
    "classify",
    "route",
]
