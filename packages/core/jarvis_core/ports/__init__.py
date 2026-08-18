"""Protokolle. Enthält keine Implementierungen."""

from .approval import ApprovalStore, BurnResult
from .permissions import PermissionStore, RateLimiter, ToolLookup

__all__ = [
    "ApprovalStore",
    "BurnResult",
    "PermissionStore",
    "RateLimiter",
    "ToolLookup",
]
