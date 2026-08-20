"""Berechtigungen, Risikoklassen und Policy-Entscheidungen.

Siehe docs/07-security-permissions.md.

Grundsatz: Was JARVIS darf, ist ein Datenobjekt — kein Codepfad. Jede
Entscheidung trägt eine menschenlesbare Begründung, die in der UI erscheint.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, time
from enum import StrEnum
from fnmatch import fnmatch
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from .classification import DataClass

__all__ = [
    "CONSTRAINTS_BY_SCOPE",
    "SENSITIVE_FILE_PATTERNS",
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
    "constraints_for",
    "is_sensitive_filename",
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


SENSITIVE_FILE_PATTERNS: frozenset[str] = frozenset(
    {
        ".env",
        ".env.*",
        "*.env",
        ".netrc",
        ".pgpass",
        ".htpasswd",
        "credentials",
        "credentials.*",
        "*.credentials",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*.jks",
        "*.keystore",
        "*.kdbx",
        "known_hosts",
        "shadow",
        "*.secret",
        "*.secrets",
        "secrets.*",
    }
)
"""Dateinamen, die typischerweise Zugangsdaten enthalten.

Eine zweite Schicht **innerhalb** der freigegebenen Ordner. Die Wurzelgrenze
beantwortet „darf hier gelesen werden?"; sie beantwortet nicht, ob im
freigegebenen Ordner zufällig ein ``id_rsa`` liegt. Ein Heimatverzeichnis
freizugeben ist nachvollziehbar, den SSH-Schlüssel darin mitzuliefern nicht.

Die Idee stammt aus ``security/file_policy.py`` von OpenJarvis (Apache 2.0);
die Umsetzung hier ist eigenständig. **Als alleinige Grenze wäre eine solche
Liste untauglich** — jede Sperrliste übersieht etwas, und dort wird sie in
jenem Projekt tatsächlich als primäre Prüfung eingesetzt. Als zweite Schicht
hinter einer Wurzelgrenze kostet sie nichts und fängt den häufigsten Unfall.
"""


def is_sensitive_filename(path: str) -> bool:
    """Passt der Dateiname auf ein Muster für Zugangsdaten?

    Geprüft wird der **Basisname**, nicht der ganze Pfad: Ein Ordner namens
    ``keys`` ist unverdächtig, die Datei ``server.key`` darin nicht. Der
    Vergleich läuft ohne Groß-/Kleinschreibung, weil Dateisysteme sich darin
    unterscheiden und ``ID_RSA`` derselbe Schlüssel ist.
    """
    name = PurePosixPath(path).name.lower()
    return any(fnmatch(name, muster) for muster in SENSITIVE_FILE_PATTERNS)


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
        """Wurzeln sind absolut und ohne ``..``.

        ``~/`` war früher zugelassen und konnte nie greifen: Der Vergleich
        unten sieht einen aufgelösten Pfad, und der ist zu ``~/…`` nie relativ.
        Die Berechtigung hätte alles abgelehnt — fail closed, aber unbrauchbar.

        Die Auflösung nachzubauen wäre der falsche Ausweg. Was ``~`` bedeutet,
        hängt davon ab, als welcher Nutzer der Prozess läuft; eine Berechtigung,
        deren Umfang vom Betriebssystemkonto abhängt, lässt sich weder
        anzeigen noch prüfen. Wer ein Heimatverzeichnis freigeben will, gibt
        es aus.
        """
        for root in value:
            if not root.startswith("/"):
                raise ValueError(
                    f"allowed_roots müssen absolut sein und mit '/' beginnen: {root!r}"
                )
            if ".." in PurePosixPath(root).parts:
                raise ValueError(f"allowed_roots dürfen kein '..' enthalten: {root!r}")
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

        # ``..`` wird abgelehnt, nicht weggerechnet.
        #
        # Der Grund ist ein Befund: ``relative_to()`` vergleicht Segmente und
        # normalisiert nicht. ``/Users/test/Dokumente/../../../etc/passwd``
        # beginnt segmentweise mit der Wurzel und galt damit als erlaubt,
        # obwohl der Pfad auf ``/etc/passwd`` zeigt. Der Test daneben prüfte
        # die Präfix-Umgehung — die Traversierung hatte niemand geprüft.
        #
        # Wegrechnen wäre die naheliegende Behebung und die schlechtere: Sie
        # bildet nach, was das Dateisystem tut, und liegt spätestens bei
        # Symlinks wieder daneben. Eine reine Pfadprüfung kann einen Symlink
        # grundsätzlich nicht sehen; deshalb ist sie hier bewusst *streng und
        # dumm*, und die eigentliche Auflösung geschieht beim Öffnen
        # (``file-access-confined-to-roots``).
        if not candidate.is_absolute() or ".." in candidate.parts:
            return ConstraintViolation(
                field="path",
                message=(
                    "Pfad muss absolut und ohne '..' angegeben werden. Ein Pfad, der erst "
                    "gerechnet werden muss, ist nicht der Pfad, der geöffnet wird."
                ),
            )

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

        # Zugangsdaten sind auch im freigegebenen Ordner gesperrt — und zwar
        # ohne Abschaltmöglichkeit. Ein Feld, das diese Liste leeren könnte,
        # wäre eine Berechtigung, ``id_rsa`` zu lesen; dafür gibt es über
        # ``files.read`` keinen legitimen Anlass. Wird einer bekannt, kommt ein
        # ausdrückliches Opt-in dazu — bis dahin ist die strengere Antwort die
        # richtige.
        if is_sensitive_filename(str(raw)):
            return ConstraintViolation(
                field="path",
                message=(
                    "Dateien mit Zugangsdaten sind gesperrt, auch innerhalb freigegebener Ordner."
                ),
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


CONSTRAINTS_BY_SCOPE: dict[str, type[ScopeConstraints]] = {
    "files.read": FilesConstraints,
    "files.write": FilesConstraints,
    "files.delete": FilesConstraints,
    "mail.send": MailSendConstraints,
}
"""Welcher Scope welche Einschränkungen führt.

Die Unterklassen gab es von Anfang an, aber nichts bildete einen Scope auf eine
von ihnen ab — aufgefallen beim ersten echten Werkzeug: Der Berechtigungsspeicher
las jede Einschränkung als Basisklasse, und die verbietet zusätzliche Felder
(``extra="forbid"``). Eine erteilte ``files.read``-Berechtigung mit Pfadgrenzen
war damit **überhaupt nicht ladbar**.

Die Zuordnung steht hier und nicht im Speicher: Sie gehört zum Vertrag. Ein
zweiter Ort hieße, dass eine Einschränkung beim Schreiben anders ausgelegt wird
als beim Lesen.

Ein Scope ohne Eintrag führt die Basisklasse — er kennt dann nur ``time_window``.
Das ist die richtige Vorgabe: Wer eine neue Einschränkung einführt, trägt sie
hier ein, und bis dahin wird sie nicht stillschweigend akzeptiert.
"""


def constraints_for(scope: str, raw: Mapping[str, Any] | None) -> ScopeConstraints:
    """Liest gespeicherte Einschränkungen als den Typ, der zum Scope gehört.

    Wirft ``ValidationError``, wenn die gespeicherten Felder nicht passen — auch
    dann, wenn Pflichtfelder fehlen. Für ``files.*`` ist das der Regelfall bei
    einer leeren Einschränkung: ``allowed_roots`` ist Pflicht, weil ein
    Dateizugriff ohne Pfadgrenze keine Berechtigung ist. Der Aufrufer muss
    entscheiden, was ein unlesbarer Datensatz bedeutet; er darf ihn nur nicht
    für „keine Einschränkung" halten.
    """
    typ = CONSTRAINTS_BY_SCOPE.get(scope, ScopeConstraints)
    return typ.model_validate(dict(raw or {}))


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

    @property
    def trigger_is_supervised(self) -> bool:
        """Ist ein Mensch anwesend, der eine Aktion beaufsichtigen könnte?"""
        return self.trigger == "user"

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


ApprovalChannel = Literal["ui", "voice", "gesture"]


class PendingAction(BaseModel):
    """Ausstehende Bestätigung — ein persistiertes, ablaufendes Objekt.

    Die Bestätigung gilt **nicht** für eine Aktion, sondern für einen konkreten
    Payload: Sie bedeutet „ich stimme genau diesem Inhalt zu", nicht „ich stimme
    dieser Art von Aktion grundsätzlich zu".
    """

    id: UUID
    run_id: UUID
    invocation_id: UUID
    user_id: UUID
    session_id: UUID
    """Bindung an die Sitzung, in der die Bestätigung angefordert wurde.

    Begrenzt den Schaden eines gestohlenen Sitzungstokens auf Aktionen, die
    diese Sitzung selbst angestoßen hat — eine andere Sitzung desselben Nutzers
    kann eine fremde Bestätigung nicht einlösen.
    """

    tool_name: str
    preview: ActionPreview
    risk: RiskLevel
    reason: str

    payload_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    """SHA-256 über die kanonisierten Argumente zum Zeitpunkt der Anfrage.

    Der Kern der Bindung: Vor der Ausführung wird der Hash des tatsächlich
    auszuführenden Payloads erneut gebildet und verglichen. Ohne diesen Wert
    wäre die Bestätigung eine Pauschalfreigabe.
    """

    nonce: str = Field(min_length=32)
    """Serverseitig erzeugte Zufallsfolge, genau einmal einlösbar.

    Bewusst *ohne* zusätzliche HMAC-Signatur: Die Nonce hat ausreichend
    Entropie, wird serverseitig erzeugt, in der Datenbank gehalten und atomar
    verbraucht. Eine HMAC-Schicht darüber schützt gegen nichts in unserem
    Bedrohungsmodell — wer die Datenbank lesen kann, kann auch Schlüssel lesen.
    Kryptografie ohne Angreifermodell ist Dekoration.

    Wichtig: Die Nonce ist **nicht** die Sicherheitsidentität. Die trägt die
    vollständige Bindung aus Nutzer, Sitzung, Lauf, Aktion, Payload-Hash,
    Kanal und Ablaufzeit.
    """

    requested_channel: ApprovalChannel
    """Kanal, auf dem die Vorschau angezeigt wurde."""

    expires_at: datetime
    created_at: datetime

    response: Literal["approved", "rejected", "expired"] | None = None
    """``None`` heißt: noch offen. Der Übergang von ``None`` auf einen Wert ist
    der Nonce-Verbrauch und wird von der Datenbank atomar erzwungen."""

    responded_at: datetime | None = None
    responded_via: ApprovalChannel | None = None

    @property
    def is_open(self) -> bool:
        return self.response is None

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def allows_channel(self, channel: ApprovalChannel) -> bool:
        """Darf über diesen Kanal bestätigt werden?

        Zwei getrennte Gründe, die hier zusammenkommen:

        1. **Irreversibles nur in der Oberfläche.** Sprach- und Gestenerkennung
           sind zu fehleranfällig für ``CRITICAL`` — und aus einem anderen Raum
           auslösbar.
        2. **Kanalbindung.** Bestätigt werden darf nur dort, wo die Vorschau
           auch angezeigt wurde. Eine Geste aus vier Metern Entfernung, die
           einen ungelesenen Dialog freigibt, ist keine informierte Zustimmung,
           sondern genau die Bestätigungsmüdigkeit aus Risiko R5.

        Ausnahme: Eine in der Oberfläche angezeigte Vorschau darf auch per
        Sprache bestätigt werden, solange sie nicht ``CRITICAL`` ist — der
        Nutzer sieht sie dann ja. Umgekehrt gilt das nicht.
        """
        if self.risk.ui_only_confirmation:
            return channel == "ui"
        if channel == self.requested_channel:
            return True
        return self.requested_channel == "ui" and channel == "voice"


ActionPreview.model_rebuild()
PolicyDecision.model_rebuild()
