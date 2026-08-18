"""Berechtigungen, Risikoklassen und Policy-Entscheidungen.

Siehe docs/07-security-permissions.md.

Grundsatz: Was JARVIS darf, ist ein Datenobjekt — kein Codepfad. Jede
Entscheidung trägt eine menschenlesbare Begründung, die in der UI erscheint.
"""

from __future__ import annotations

import re
from datetime import datetime, time
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from .classification import DataClass

__all__ = [
    "ActionPreview",
    "AmountConstraints",
    "ConstraintViolation",
    "FilesConstraints",
    "MailSendConstraints",
    "PendingAction",
    "PermissionGrant",
    "PermissionMode",
    "PolicyDecision",
    "PolicyEffect",
    "PolicyRequest",
    "RiskLevel",
    "ScopeConstraints",
    "ScopeName",
    "ScopeSpec",
    "TimeWindow",
]


# --------------------------------------------------------------------------
# Risiko und Modi
# --------------------------------------------------------------------------


class RiskLevel(StrEnum):
    """Folgenschwere eines Werkzeugs.

    Die Ordnung ist bedeutungstragend und wird explizit definiert — die
    lexikografische Ordnung der Werte wäre falsch ("critical" < "high").
    """

    LOW = "low"
    """Lesend, lokal, folgenlos. Wird ohne Rückfrage ausgeführt."""

    MEDIUM = "medium"
    """Schreibend, aber umkehrbar. Ausführung mit angebotenem Undo."""

    HIGH = "high"
    """Außenwirkung oder schwer umkehrbar. Bestätigung mit Vorschau."""

    CRITICAL = "critical"
    """Irreversibel oder finanziell. Bestätigung nur in der UI, nie autonom."""

    @property
    def level(self) -> int:
        return _RISK_LEVELS[self]

    @property
    def needs_confirmation(self) -> bool:
        return self.level >= RiskLevel.HIGH.level

    @property
    def ui_only_confirmation(self) -> bool:
        """CRITICAL darf nicht per Sprache oder Geste bestätigt werden."""
        return self is RiskLevel.CRITICAL

    # Wie bei DataClass wird bei Fremdtypen ausdrücklich TypeError geworfen.
    # Hier ist das nicht bloß Hygiene: RiskLevel erbt von ``str``, und der
    # lexikografische Rückfall lieferte das *Gegenteil* der gemeinten Ordnung
    # ("critical" < "high" ist als String wahr, semantisch aber falsch).
    def _other_level(self, other: Any) -> int:
        if isinstance(other, RiskLevel):
            return other.level
        raise TypeError(
            f"RiskLevel lässt sich nicht mit {type(other).__name__} vergleichen. "
            "Die String-Ordnung von Risikoklassen ist semantisch falsch."
        )

    def __lt__(self, other: Any) -> bool:
        return self.level < self._other_level(other)

    def __le__(self, other: Any) -> bool:
        return self.level <= self._other_level(other)

    def __gt__(self, other: Any) -> bool:
        return self.level > self._other_level(other)

    def __ge__(self, other: Any) -> bool:
        return self.level >= self._other_level(other)

    def __str__(self) -> str:
        return self.value


_RISK_LEVELS: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


class PermissionMode(StrEnum):
    """Wie eine Berechtigung erteilt ist."""

    DENY = "deny"
    CONFIRM = "confirm"
    ALLOW = "allow"

    def __str__(self) -> str:
        return self.value


class PolicyEffect(StrEnum):
    """Ergebnis einer Policy-Prüfung."""

    ALLOW = "allow"
    CONFIRM = "confirm"
    DENY = "deny"

    def __str__(self) -> str:
        return self.value


# --------------------------------------------------------------------------
# Scopes
# --------------------------------------------------------------------------

_SCOPE_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")

ScopeName = Annotated[
    str,
    Field(
        pattern=_SCOPE_RE.pattern,
        min_length=3,
        max_length=64,
        description="Scope im Format <domäne>.<aktion>, z. B. 'mail.send'.",
        examples=["mail.read", "mail.send", "calendar.delete", "files.write"],
    ),
]


class ScopeSpec(BaseModel):
    """Katalogeintrag eines Scopes. Scopes sind Daten, kein Enum im Code —
    neue Werkzeuge bringen neue Scopes mit."""

    model_config = ConfigDict(frozen=True)

    name: ScopeName
    description: str = Field(min_length=1, max_length=500)
    default_mode: PermissionMode
    risk_level: RiskLevel

    @property
    def domain(self) -> str:
        return self.name.split(".", 1)[0]

    @property
    def action(self) -> str:
        return self.name.split(".", 1)[1]


# --------------------------------------------------------------------------
# Einschränkungen
# --------------------------------------------------------------------------


class ConstraintViolation(BaseModel):
    """Warum ein Aufruf an einer Einschränkung scheitert."""

    model_config = ConfigDict(frozen=True)

    field: str
    message: str
    """Menschenlesbar, erscheint direkt in der UI."""


class TimeWindow(BaseModel):
    """Tageszeitfenster, in dem ein Scope nutzbar ist."""

    model_config = ConfigDict(frozen=True)

    start: time
    end: time

    def contains(self, moment: time) -> bool:
        if self.start <= self.end:
            return self.start <= moment <= self.end
        # Fenster über Mitternacht, z. B. 22:00–06:00
        return moment >= self.start or moment <= self.end


class ScopeConstraints(BaseModel):
    """Basisklasse für scope-spezifische Einschränkungen.

    In der Datenbank als JSONB abgelegt (docs/03-datenmodell.md §2); die
    Typsicherheit sitzt hier an der Anwendungsgrenze, nicht im DDL.
    """

    model_config = ConfigDict(extra="forbid")

    time_window: TimeWindow | None = None

    def check(
        self, arguments: dict[str, Any], *, now: datetime | None = None
    ) -> ConstraintViolation | None:
        """Prüft die Argumente eines Werkzeugaufrufs. ``None`` heißt: in Ordnung."""
        if self.time_window is not None:
            moment = (now or datetime.now()).time()
            if not self.time_window.contains(moment):
                return ConstraintViolation(
                    field="time_window",
                    message=(
                        f"Nur zwischen {self.time_window.start:%H:%M} und "
                        f"{self.time_window.end:%H:%M} erlaubt."
                    ),
                )
        return None


class MailSendConstraints(ScopeConstraints):
    """Einschränkungen für ``mail.send``."""

    recipients_allowlist: list[EmailStr] = Field(default_factory=list)
    """Leer bedeutet: keine Empfängerbeschränkung."""

    max_recipients: int = Field(default=5, ge=1, le=200)
    require_draft_review: bool = True

    def check(
        self, arguments: dict[str, Any], *, now: datetime | None = None
    ) -> ConstraintViolation | None:
        if (base := super().check(arguments, now=now)) is not None:
            return base

        recipients: list[str] = []
        for key in ("to", "cc", "bcc"):
            value = arguments.get(key) or []
            if isinstance(value, str):
                recipients.append(value)
            else:
                recipients.extend(str(item) for item in value)

        if len(recipients) > self.max_recipients:
            return ConstraintViolation(
                field="to",
                message=f"Höchstens {self.max_recipients} Empfänger erlaubt, angefordert: {len(recipients)}.",
            )

        if self.recipients_allowlist:
            allowed = {str(addr).lower() for addr in self.recipients_allowlist}
            blocked = sorted({r.lower() for r in recipients} - allowed)
            if blocked:
                return ConstraintViolation(
                    field="to",
                    message="Empfänger nicht freigegeben: " + ", ".join(blocked),
                )
        return None


class FilesConstraints(ScopeConstraints):
    """Einschränkungen für ``files.read`` / ``files.write``."""

    allowed_roots: list[str] = Field(min_length=1)
    """Niemals leer — ein Dateizugriff ohne Pfadgrenze ist keine Berechtigung."""

    max_file_size_mb: int = Field(default=50, ge=1, le=10_000)
    forbidden_extensions: list[str] = Field(
        default_factory=lambda: [".app", ".sh", ".command", ".dylib", ".so", ".pkg"]
    )

    @field_validator("allowed_roots")
    @classmethod
    def _absolute_roots(cls, value: list[str]) -> list[str]:
        for root in value:
            if not root.startswith(("/", "~/")):
                raise ValueError(f"allowed_roots müssen absolut sein: {root!r}")
        return value

    def check(
        self, arguments: dict[str, Any], *, now: datetime | None = None
    ) -> ConstraintViolation | None:
        if (base := super().check(arguments, now=now)) is not None:
            return base

        raw = arguments.get("path")
        if raw is None:
            return None

        candidate = PurePosixPath(str(raw))
        if not any(_is_within(candidate, PurePosixPath(root)) for root in self.allowed_roots):
            return ConstraintViolation(
                field="path",
                message=(
                    f"Pfad liegt außerhalb der freigegebenen Ordner "
                    f"({', '.join(self.allowed_roots)})."
                ),
            )

        if candidate.suffix.lower() in {ext.lower() for ext in self.forbidden_extensions}:
            return ConstraintViolation(
                field="path",
                message=f"Dateityp {candidate.suffix} ist gesperrt.",
            )
        return None


class AmountConstraints(ScopeConstraints):
    """Betragsgrenze für Scopes mit finanzieller Wirkung."""

    max_amount_eur: float = Field(gt=0)
    currency: Literal["EUR"] = "EUR"

    def check(
        self, arguments: dict[str, Any], *, now: datetime | None = None
    ) -> ConstraintViolation | None:
        if (base := super().check(arguments, now=now)) is not None:
            return base
        amount = arguments.get("amount_eur")
        if amount is not None and float(amount) > self.max_amount_eur:
            return ConstraintViolation(
                field="amount_eur",
                message=f"Betragsgrenze {self.max_amount_eur:.2f} € überschritten.",
            )
        return None


def _is_within(candidate: PurePosixPath, root: PurePosixPath) -> bool:
    """Echte Präfixprüfung auf Pfadsegmentebene.

    Ein reiner String-Vergleich wäre hier ein Sicherheitsloch:
    ``/home/user-evil`` beginnt mit ``/home/user``.
    """
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


# --------------------------------------------------------------------------
# Erteilte Berechtigungen
# --------------------------------------------------------------------------


class PermissionGrant(BaseModel):
    """Eine für einen Nutzer erteilte Berechtigung."""

    scope: ScopeName
    mode: PermissionMode
    constraints: ScopeConstraints = Field(default_factory=ScopeConstraints)
    granted_at: datetime
    expires_at: datetime | None = None

    def is_valid_at(self, moment: datetime) -> bool:
        return self.expires_at is None or self.expires_at > moment


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------


class PolicyRequest(BaseModel):
    """Anfrage an die Policy Engine. Einziger Weg zur Werkzeugausführung."""

    user_id: UUID
    run_id: UUID
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    trigger: Literal["user", "schedule", "event", "webhook"] = "user"
    """Automatisierte Auslöser werden strenger behandelt — es ist niemand da,
    der bestätigen könnte."""

    allowed_data_class: DataClass = DataClass.P3
    """Höchste Klasse, die in diesem Kontext verarbeitet werden darf."""

    agent_name: str | None = None


class PolicyDecision(BaseModel):
    """Ergebnis einer Policy-Prüfung — inklusive Begründung für die UI."""

    model_config = ConfigDict(frozen=True)

    effect: PolicyEffect
    reason: str = Field(min_length=1)
    """Menschenlesbar. 'Ich darf das nicht' ohne Erklärung ist unbrauchbar."""

    scope: ScopeName | None = None
    violation: ConstraintViolation | None = None
    preview: ActionPreview | None = None
    offer_grant: bool = False
    """UI bietet an, die fehlende Berechtigung zu erteilen."""

    escalate_to_user: bool = False
    """Nutzer muss aktiv informiert werden — z. B. bei Taint-Sperre."""

    @model_validator(mode="after")
    def _confirm_needs_preview(self) -> Self:
        if self.effect is PolicyEffect.CONFIRM and self.preview is None:
            raise ValueError(
                "CONFIRM ohne Vorschau ist unzulässig: Der Nutzer muss sehen, "
                "was tatsächlich ausgeführt wird."
            )
        return self

    @classmethod
    def allow(cls, reason: str = "Berechtigung erteilt.", *, scope: str | None = None) -> Self:
        return cls(effect=PolicyEffect.ALLOW, reason=reason, scope=scope)

    @classmethod
    def deny(
        cls,
        reason: str,
        *,
        scope: str | None = None,
        violation: ConstraintViolation | None = None,
        offer_grant: bool = False,
        escalate_to_user: bool = False,
    ) -> Self:
        return cls(
            effect=PolicyEffect.DENY,
            reason=reason,
            scope=scope,
            violation=violation,
            offer_grant=offer_grant,
            escalate_to_user=escalate_to_user,
        )

    @classmethod
    def confirm(cls, reason: str, preview: ActionPreview, *, scope: str | None = None) -> Self:
        return cls(effect=PolicyEffect.CONFIRM, reason=reason, preview=preview, scope=scope)


# --------------------------------------------------------------------------
# Bestätigungen
# --------------------------------------------------------------------------


class ActionPreview(BaseModel):
    """Was tatsächlich passieren wird.

    Wird aus dem *validierten Argument-Objekt* gebaut, nicht aus einer vom
    Modell formulierten Beschreibung. Damit kann das Modell nichts anderes
    anzeigen, als es ausführt (docs/07-security-permissions.md §5).
    """

    model_config = ConfigDict(frozen=True)

    tool_name: str
    title: str
    """Kurzform für die Kopfzeile, z. B. 'E-Mail senden'."""

    fields: list[PreviewField] = Field(default_factory=list)
    risk: RiskLevel
    reversible: bool = False
    warnings: list[str] = Field(default_factory=list)
    """Z. B. 'Empfänger ist nicht in deinen Kontakten.'"""


class PreviewField(BaseModel):
    """Ein angezeigtes Feld der Vorschau."""

    model_config = ConfigDict(frozen=True)

    label: str
    value: str
    emphasis: Literal["normal", "warn"] = "normal"
    truncated: bool = False


class PendingAction(BaseModel):
    """Ausstehende Bestätigung — ein persistiertes, ablaufendes Objekt."""

    id: UUID
    invocation_id: UUID
    user_id: UUID
    tool_name: str
    preview: ActionPreview
    risk: RiskLevel
    reason: str
    nonce: str = Field(min_length=16)
    """HMAC-signiert, an Nutzer und Sitzung gebunden — gegen gefälschte
    Bestätigungen."""

    expires_at: datetime
    created_at: datetime

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def allows_channel(self, channel: Literal["ui", "voice", "gesture"]) -> bool:
        """CRITICAL verlangt eine Interaktion in der UI.

        Spracherkennung und Gestenerkennung sind zu fehleranfällig für
        irreversible Aktionen — und aus einem anderen Raum auslösbar.
        """
        if self.risk.ui_only_confirmation:
            return channel == "ui"
        return True


ActionPreview.model_rebuild()
PolicyDecision.model_rebuild()
