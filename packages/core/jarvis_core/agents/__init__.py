"""Agenten — Spezialisierung als Sicherheitsmechanismus.

Siehe docs/06-agenten-tools.md.

Sub-Agenten sind hier keine Organisationsform, sondern Least Privilege in
Struktur gegossen: Der Research Agent liest Fremdinhalt und besitzt deshalb
strukturell keine sendenden Werkzeuge. Selbst wenn eine Webseite eine
Anweisung enthält, gibt es von dort keinen Pfad zu ``mail.send``.
"""

from .chain import AgentChain
from .model_loop import ModelLoop
from .plan_step import ROOT_AGENT, AgentStepSource, AgentStepUnavailable
from .registry import AgentRegistry, DuplicateAgent, UnknownAgent
from .runtime import (
    AgentBehaviour,
    AgentRuntime,
    AgentSession,
    DelegationDenied,
    DelegationOutcome,
)

__all__ = [
    "ROOT_AGENT",
    "AgentBehaviour",
    "AgentChain",
    "AgentRegistry",
    "AgentRuntime",
    "AgentSession",
    "AgentStepSource",
    "AgentStepUnavailable",
    "DelegationDenied",
    "DelegationOutcome",
    "DuplicateAgent",
    "ModelLoop",
    "UnknownAgent",
]
