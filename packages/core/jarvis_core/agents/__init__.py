"""Agenten — Spezialisierung als Sicherheitsmechanismus.

Siehe docs/06-agenten-tools.md.

Sub-Agenten sind hier keine Organisationsform, sondern Least Privilege in
Struktur gegossen: Der Research Agent liest Fremdinhalt und besitzt deshalb
strukturell keine sendenden Werkzeuge. Selbst wenn eine Webseite eine
Anweisung enthält, gibt es von dort keinen Pfad zu ``mail.send``.
"""

from .chain import AgentChain
from .model_loop import ModelLoop
from .registry import AgentRegistry, DuplicateAgent, UnknownAgent
from .runtime import (
    AgentBehaviour,
    AgentRuntime,
    AgentSession,
    DelegationDenied,
    DelegationOutcome,
)

__all__ = [
    "AgentBehaviour",
    "AgentChain",
    "AgentRegistry",
    "AgentRuntime",
    "AgentSession",
    "DelegationDenied",
    "DelegationOutcome",
    "DuplicateAgent",
    "ModelLoop",
    "UnknownAgent",
]
