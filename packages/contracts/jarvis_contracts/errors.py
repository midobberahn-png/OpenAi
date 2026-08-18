"""Einheitliches Fehlerformat (RFC-9457-nah).

Siehe docs/11-api.md §4.

Das Feld ``remediation`` ist bewusst Teil des Vertrags: Ein Fehler, der nicht
sagt, wie man ihn behebt, erzeugt Aufwand — auch bei einem persönlichen System.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["ErrorCode", "JarvisError", "Problem", "Remediation"]

_BASE_URI = "https://jarvis.local/errors/"


class ErrorCode(StrEnum):
    VALIDATION = "validation-error"
    UNAUTHENTICATED = "unauthenticated"
    PERMISSION_DENIED = "permission-denied"
    TAINT_BLOCKED = "taint-blocked"
    """HTTP 423 — eigens vergeben, damit die UI die Taint-Sperre von einer
    gewöhnlichen fehlenden Berechtigung unterscheiden kann."""

    NOT_FOUND = "not-found"
    CONFLICT = "conflict"
    RATE_LIMITED = "rate-limited"
    BUDGET_EXCEEDED = "budget-exceeded"
    PROVIDER_ERROR = "provider-error"
    PROVIDER_UNAVAILABLE = "provider-unavailable"
    AUTH_EXPIRED = "auth-expired"
    TOOL_VALIDATION = "tool-validation-error"
    ACTION_EXPIRED = "action-expired"
    INVALID_NONCE = "invalid-nonce"
    DEGRADED = "degraded"

    @property
    def http_status(self) -> int:
        return _HTTP_STATUS[self]

    @property
    def uri(self) -> str:
        return _BASE_URI + self.value

    def __str__(self) -> str:
        return self.value


_HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.VALIDATION: 400,
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.PERMISSION_DENIED: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.CONFLICT: 409,
    ErrorCode.TOOL_VALIDATION: 422,
    ErrorCode.TAINT_BLOCKED: 423,
    ErrorCode.ACTION_EXPIRED: 410,
    ErrorCode.INVALID_NONCE: 403,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.BUDGET_EXCEEDED: 429,
    ErrorCode.PROVIDER_ERROR: 502,
    ErrorCode.PROVIDER_UNAVAILABLE: 503,
    ErrorCode.AUTH_EXPIRED: 401,
    ErrorCode.DEGRADED: 503,
}


class Remediation(BaseModel):
    """Wie der Nutzer den Fehler beheben kann."""

    model_config = ConfigDict(frozen=True)

    action: str
    label: str
    url: str | None = None


class Problem(BaseModel):
    """Fehlerantwort des API."""

    model_config = ConfigDict(frozen=True)

    type: str
    title: str
    status: int
    detail: str
    instance: str | None = None
    trace_id: str | None = None
    scope: str | None = None
    remediation: Remediation | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_code(
        cls,
        code: ErrorCode,
        detail: str,
        *,
        title: str | None = None,
        instance: str | None = None,
        trace_id: str | None = None,
        scope: str | None = None,
        remediation: Remediation | None = None,
        **extra: Any,
    ) -> Problem:
        return cls(
            type=code.uri,
            title=title or _TITLES[code],
            status=code.http_status,
            detail=detail,
            instance=instance,
            trace_id=trace_id,
            scope=scope,
            remediation=remediation,
            extra=extra,
        )


_TITLES: dict[ErrorCode, str] = {
    ErrorCode.VALIDATION: "Ungültige Eingabe",
    ErrorCode.UNAUTHENTICATED: "Nicht angemeldet",
    ErrorCode.PERMISSION_DENIED: "Berechtigung fehlt",
    ErrorCode.TAINT_BLOCKED: "Aktion gesperrt",
    ErrorCode.NOT_FOUND: "Nicht gefunden",
    ErrorCode.CONFLICT: "Konflikt",
    ErrorCode.RATE_LIMITED: "Zu viele Anfragen",
    ErrorCode.BUDGET_EXCEEDED: "Budget erschöpft",
    ErrorCode.PROVIDER_ERROR: "Anbieterfehler",
    ErrorCode.PROVIDER_UNAVAILABLE: "Anbieter nicht erreichbar",
    ErrorCode.AUTH_EXPIRED: "Zugang abgelaufen",
    ErrorCode.TOOL_VALIDATION: "Werkzeugaufruf ungültig",
    ErrorCode.ACTION_EXPIRED: "Bestätigung abgelaufen",
    ErrorCode.INVALID_NONCE: "Bestätigung ungültig",
    ErrorCode.DEGRADED: "Eingeschränkter Betrieb",
}


class JarvisError(Exception):
    """Basisklasse aller erwarteten Fehler. Trägt ein Problem-Objekt."""

    def __init__(
        self,
        code: ErrorCode,
        detail: str,
        *,
        scope: str | None = None,
        remediation: Remediation | None = None,
        **extra: Any,
    ) -> None:
        self.code = code
        self.detail = detail
        self.scope = scope
        self.remediation = remediation
        self.extra = extra
        super().__init__(detail)

    def to_problem(self, *, instance: str | None = None, trace_id: str | None = None) -> Problem:
        return Problem.from_code(
            self.code,
            self.detail,
            instance=instance,
            trace_id=trace_id,
            scope=self.scope,
            remediation=self.remediation,
            **self.extra,
        )
