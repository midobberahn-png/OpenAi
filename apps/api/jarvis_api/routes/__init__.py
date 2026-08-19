"""HTTP-Routen. Dünne Adapter auf den Kern — keine Sicherheitslogik."""

from .auth import router as auth_router

__all__ = ["auth_router"]
