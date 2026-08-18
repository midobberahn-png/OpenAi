"""WebSocket-Ereignisprotokoll.

Siehe docs/11-api.md §3.

Bewusste Auslassung: Es gibt keinen Nachrichtentyp für Roh-Audio oder
Videoframes. Die Zusicherung, dass diese das Gerät nie verlassen, ist damit
strukturell im Protokoll verankert und nicht bloß eine Konvention.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .classification import DataClass
from .permissions import PendingAction
from .runs import Intent, PlanStep, RunStatus, Usage

__all__ = [
    "CameraState",
    "ClientMessage",
    "CoreState",
    "HealthEntry",
    "MicState",
    "ServerMessage",
]


class CoreState(StrEnum):
    """Zustand der AI-Core-Darstellung (docs/10-ui.md §3)."""

    IDLE = "idle"
    LISTENING = "listening"
    THINKING = "thinking"
    EXECUTING = "executing"
    AWAITING = "awaiting"
    SPEAKING = "speaking"
    ERROR = "error"
    MUTED = "muted"

    def __str__(self) -> str:
        return self.value


class MicState(StrEnum):
    ON = "on"
    OFF = "off"
    MUTED = "muted"


class CameraState(StrEnum):
    ON = "on"
    OFF = "off"


# --------------------------------------------------------------------------
# Client → Server
# --------------------------------------------------------------------------


class _Msg(BaseModel):
    model_config = ConfigDict(frozen=True)


class UserMessage(_Msg):
    t: Literal["user.message"] = "user.message"
    conversation_id: UUID | None = None
    text: str = Field(min_length=1, max_length=100_000)
    attachment_ids: list[UUID] = Field(default_factory=list)


class UserInterrupt(_Msg):
    t: Literal["user.interrupt"] = "user.interrupt"
    run_id: UUID


class ActionRespond(_Msg):
    t: Literal["action.respond"] = "action.respond"
    action_id: UUID
    approve: bool
    nonce: str = Field(min_length=16)
    channel: Literal["ui", "voice", "gesture"] = "ui"
    """CRITICAL-Aktionen akzeptieren ausschließlich 'ui'."""


class EdgeHello(_Msg):
    t: Literal["edge.hello"] = "edge.hello"
    device_id: str
    capabilities: list[Literal["mic", "speaker", "camera"]] = Field(default_factory=list)


class EdgeWake(_Msg):
    t: Literal["edge.wake"] = "edge.wake"
    confidence: float = Field(ge=0.0, le=1.0)


class EdgeTranscript(_Msg):
    t: Literal["edge.transcript"] = "edge.transcript"
    text: str
    is_final: bool
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    language: str = "de"


class EdgeGesture(_Msg):
    t: Literal["edge.gesture"] = "edge.gesture"
    gesture: str
    confidence: float = Field(ge=0.0, le=1.0)


class EdgeState(_Msg):
    t: Literal["edge.state"] = "edge.state"
    mic: MicState
    camera: CameraState
    aec_active: bool = False


class Ping(_Msg):
    t: Literal["ping"] = "ping"


ClientMessage = Annotated[
    UserMessage
    | UserInterrupt
    | ActionRespond
    | EdgeHello
    | EdgeWake
    | EdgeTranscript
    | EdgeGesture
    | EdgeState
    | Ping,
    Field(discriminator="t"),
]


# --------------------------------------------------------------------------
# Server → Client
# --------------------------------------------------------------------------


class _ServerMsg(BaseModel):
    model_config = ConfigDict(frozen=True)

    seq: int = Field(ge=0)
    """Lückenerkennung nach Reconnect. Ohne Sequenznummern driftet die
    Anzeige nach jedem Netzwerkwackler."""


class RunStarted(_ServerMsg):
    t: Literal["run.started"] = "run.started"
    run_id: UUID
    trace_id: str
    conversation_id: UUID | None = None


class RunClassified(_ServerMsg):
    t: Literal["run.classified"] = "run.classified"
    run_id: UUID
    intent: Intent
    data_class: DataClass
    complexity: str


class RunRouted(_ServerMsg):
    t: Literal["run.routed"] = "run.routed"
    run_id: UUID
    model: str
    provider: str
    reason: str
    is_fallback: bool = False
    """Ein Providerwechsel wird sichtbar gemacht — kein stiller Failover."""


class RunPlan(_ServerMsg):
    t: Literal["run.plan"] = "run.plan"
    run_id: UUID
    goal: str
    steps: list[PlanStep]


class StepStarted(_ServerMsg):
    t: Literal["step.started"] = "step.started"
    run_id: UUID
    step_seq: int
    description: str
    kind: str


class StepFinished(_ServerMsg):
    t: Literal["step.finished"] = "step.finished"
    run_id: UUID
    step_seq: int
    status: str
    latency_ms: int


class TokenDelta(_ServerMsg):
    t: Literal["token.delta"] = "token.delta"
    run_id: UUID
    text: str
    """Speist gleichzeitig Textausgabe und TTS-Satzpuffer."""


class ActionPending(_ServerMsg):
    t: Literal["action.pending"] = "action.pending"
    run_id: UUID
    action: PendingAction


class ActionResolved(_ServerMsg):
    t: Literal["action.resolved"] = "action.resolved"
    action_id: UUID
    result: Literal["approved", "rejected", "expired"]


class RunFinished(_ServerMsg):
    t: Literal["run.finished"] = "run.finished"
    run_id: UUID
    status: RunStatus
    usage: Usage
    cost_eur: Decimal


class RunError(_ServerMsg):
    t: Literal["run.error"] = "run.error"
    run_id: UUID | None = None
    code: str
    message: str
    recoverable: bool = False
    remediation_url: str | None = None


class CoreStateChanged(_ServerMsg):
    t: Literal["core.state"] = "core.state"
    state: CoreState
    detail: str | None = None


class HealthEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    component: str
    status: Literal["ok", "degraded", "down", "unknown"]
    latency_ms: int | None = None
    detail: str | None = None
    checked_at: datetime


class SystemHealth(_ServerMsg):
    t: Literal["system.health"] = "system.health"
    components: list[HealthEntry]


class Proactive(_ServerMsg):
    t: Literal["proactive"] = "proactive"
    kind: str
    title: str
    body: str
    dismissible: bool = True


class Pong(_ServerMsg):
    t: Literal["pong"] = "pong"


ServerMessage = Annotated[
    RunStarted
    | RunClassified
    | RunRouted
    | RunPlan
    | StepStarted
    | StepFinished
    | TokenDelta
    | ActionPending
    | ActionResolved
    | RunFinished
    | RunError
    | CoreStateChanged
    | SystemHealth
    | Proactive
    | Pong,
    Field(discriminator="t"),
]
