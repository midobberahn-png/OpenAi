"""HTTP-Routen. Dünne Adapter auf den Kern — keine Sicherheitslogik."""

from .actions import router as actions_router
from .audit import router as audit_router
from .auth import router as auth_router
from .events import router as events_router
from .permissions import router as permissions_router
from .runs import router as runs_router
from .undo import router as undo_router

__all__ = [
    "actions_router",
    "audit_router",
    "auth_router",
    "events_router",
    "permissions_router",
    "runs_router",
    "undo_router",
]
