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

from .advance import AdvanceOutcome, AdvanceRejected, RunAdvancer
from .budget import BudgetTracker, utc_now
from .classifier import TRIVIAL_UTTERANCES, classify
from .executor import StepExecution, StepStatus, ToolExecutor
from .plan_arguments import (
    ArgumentsUnavailable,
    FormulatedArguments,
    PlanArgumentSource,
)
from .plan_context import PlanStepUnavailable
from .plan_response import (
    FormulatedResponse,
    PlanResponseSource,
    ResponseUnavailable,
)
from .planner import ExecutionMode, plan_turn, select_mode
from .router import (
    HealthSnapshot,
    NoEligibleModel,
    RoutingPreferences,
    route,
)

__all__ = [
    "TRIVIAL_UTTERANCES",
    "AdvanceOutcome",
    "AdvanceRejected",
    "ArgumentsUnavailable",
    "BudgetTracker",
    "ExecutionMode",
    "FormulatedArguments",
    "FormulatedResponse",
    "HealthSnapshot",
    "NoEligibleModel",
    "PlanArgumentSource",
    "PlanResponseSource",
    "PlanStepUnavailable",
    "ResponseUnavailable",
    "RoutingPreferences",
    "RunAdvancer",
    "StepExecution",
    "StepStatus",
    "ToolExecutor",
    "classify",
    "plan_turn",
    "route",
    "select_mode",
    "utc_now",
]
