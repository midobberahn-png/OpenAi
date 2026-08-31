"""Datenbankmodelle. Entspricht docs/03-datenmodell.md.

Gestaltungsprinzipien, die hier sichtbar werden:

* Löschung ist kaskadierend und in einer Transaktion durchführbar — der
  praktische Grund für ADR-003 (eine Datenbank statt zwei Systeme).
* Embeddings liegen getrennt von ihren Datensätzen, damit ein Modellwechsel
  keine Fakten anfasst.
* ``audit_log`` ist append-only und hash-verkettet.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    Computed,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, uuid_pk

EMBEDDING_DIM = 1024
"""bge-m3 und die meisten offenen Modelle liefern 1024 Dimensionen. Cloud-Modelle
mit abweichender Größe werden auf diese Länge projiziert oder erhalten eine
eigene Tabelle — die Modellspalte erlaubt beides parallel."""


# ==========================================================================
# Identität und Zugang
# ==========================================================================


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(Text)
    """Argon2id. Optional — Passkey ist der primäre Faktor (ADR-007)."""

    locale: Mapped[str] = mapped_column(String(10), nullable=False, server_default="de-DE")
    timezone: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default="Europe/Berlin"
    )
    preferences: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    daily_budget_eur: Mapped[Decimal] = mapped_column(
        Numeric(10, 2), nullable=False, server_default=text("5.00")
    )

    credentials: Mapped[list[WebAuthnCredential]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    permissions: Mapped[list[Permission]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Session(Base):
    """Angemeldete Sitzung.

    ``token_hash`` statt Token: Wer diese Tabelle liest — über ein Backup, eine
    fehlgeleitete Abfrage, einen Zugriff aus zweiter Hand —, findet nichts,
    womit er sich anmelden könnte. Der Klartext existiert genau einmal, bei der
    Ausgabe.

    Zwei Fristen, weil sie verschiedene Fälle abdecken: ``expires_at`` ist
    absolut und wird nie verlängert (eine gestohlene Sitzung ist endlich, auch
    wenn der Dieb sie aktiv hält); ``last_seen_at`` trägt die Leerlauffrist
    (ein vergessenes Gerät wird von selbst wertlos).
    """

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    """SHA-256 des Tokens als Hex. Eindeutig — zwei Sitzungen mit demselben
    Token wären ein Fehler, den die Datenbank melden soll."""

    client: Mapped[str] = mapped_column(String(200), nullable=False, server_default="")
    """Gerätebezeichnung für die Sitzungsübersicht. Stammt vom Client und wird
    nie geprüft; es darf keine Entscheidung davon abhängen."""

    channel: Mapped[str] = mapped_column(String(16), nullable=False, server_default="ui")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("channel IN ('ui','voice','edge')", name="session_channel_valid"),
        Index(
            "ix_sessions_active",
            "user_id",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )


class WebAuthnChallenge(Base):
    """Ausgestellte, genau einmal einlösbare Challenge.

    Dieselbe Bauart wie die Bestätigungs-Nonce, aus demselben Grund: Der
    Verbrauch ist ein bedingtes ``UPDATE``, dessen Trefferzahl die Antwort
    liefert. Ein ``lesen → prüfen → markieren`` wäre bei zwei gleichzeitigen
    Anfragen ein Doppelverbrauch.

    ``user_id`` ist bei der Anmeldung leer: Dort steht der Nutzer erst nach der
    Prüfung fest. Wer ihn vorher aus dem Request übernähme, ließe den Angreifer
    benennen, in welches Konto er einbricht.
    """

    __tablename__ = "webauthn_challenges"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")
    )
    purpose: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(
            "purpose IN ('registration','authentication')", name="challenge_purpose_valid"
        ),
        Index("ix_challenges_open", "expires_at", postgresql_where=text("used_at IS NULL")),
    )


class WebAuthnCredential(Base, TimestampMixin):
    __tablename__ = "webauthn_credentials"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    device_label: Mapped[str | None] = mapped_column(String(120))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="credentials")


# ==========================================================================
# Berechtigungen
# ==========================================================================


class Scope(Base):
    """Scope-Katalog. Scopes sind Daten, kein Enum im Code — neue Werkzeuge
    bringen neue Scopes mit."""

    __tablename__ = "scopes"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    default_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)

    __table_args__ = (
        CheckConstraint("default_mode IN ('deny','confirm','allow')", name="default_mode_valid"),
        CheckConstraint(
            "risk_level IN ('low','medium','high','critical')", name="risk_level_valid"
        ),
    )


class Permission(Base, TimestampMixin):
    __tablename__ = "permissions"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    scope: Mapped[str] = mapped_column(String(64), ForeignKey("scopes.name"), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    constraints: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    """Je Scope strukturell verschieden; typisiert an der Anwendungsgrenze
    validiert (docs/03-datenmodell.md §2)."""

    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="permissions")

    __table_args__ = (
        UniqueConstraint("user_id", "scope", name="uq_permissions_user_scope"),
        CheckConstraint("mode IN ('deny','confirm','allow')", name="mode_valid"),
    )


# ==========================================================================
# Verbundene Konten und Secrets
# ==========================================================================


class ConnectedAccount(Base, TimestampMixin):
    __tablename__ = "connected_accounts"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    display_label: Mapped[str] = mapped_column(String(255), nullable=False)
    granted_scopes: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="active")
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

    credentials: Mapped[list[OAuthCredential]] = relationship(
        back_populates="account", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("user_id", "provider", "external_id", name="uq_account_identity"),
        CheckConstraint("status IN ('active','expired','revoked','error')", name="status_valid"),
    )


class OAuthAuthorization(Base, TimestampMixin):
    """Ein angefangener Zustimmungsvorgang — der Anspruch auf **einen** Rückruf.

    **Warum diese Zeile existiert.** Zwischen „der Nutzer wird zum Anbieter
    geschickt" und „der Anbieter ruft zurück" liegt ein Wechsel des Kanals.
    Was zurückkommt, ist ein GET auf unseren Server mit zwei Zeichenketten
    darin. Ohne eine Zeile, die den Vorgang vorher festhält, gäbe es nichts,
    wogegen sich prüfen ließe, ob dieser Rückruf zu diesem Nutzer gehört — und
    genau das ist der Angriff: Wer sein eigenes ``code`` in den Browser eines
    Fremden bringt, hängt **sein** Postfach an **dessen** Konto.

    **``state`` steht als Hash hier, nicht im Klartext.** Wer die Datenbank
    liest, soll keinen gültigen Rückruf bauen können. Dieselbe Überlegung wie
    beim Sitzungstoken: Der Wert lebt beim Nutzer, die Zeile kennt nur seinen
    Abdruck.

    **Der PKCE-Verifier ist versiegelt** (ADR-008) und an die Kennung dieser
    Zeile gebunden. Er ist kurzlebig, aber ein Geheimnis: Wer ihn und den
    abgefangenen Code hat, löst ihn ein.
    """

    __tablename__ = "oauth_authorizations"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    state_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)

    verifier_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    verifier_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    verifier_wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    verifier_kek_id: Mapped[str] = mapped_column(String(64), nullable=False)

    requested_scopes: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    """Was **gefragt** wurde. Bewilligt wird, was der Anbieter zurückmeldet;
    das steht in ``connected_accounts.granted_scopes`` und ist die andere
    Aussage."""

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    """Macht den Rückruf einmalig. Die Bedingung steht im ``WHERE`` der
    Anweisung, die auch schreibt — wer erst liest und dann schreibt, hat
    dazwischen ein Fenster, und zwei gleichzeitige Rückrufe gäben zwei
    Konten."""


class OAuthCredential(Base, TimestampMixin):
    """Envelope Encryption (ADR-008).

    Es gibt bewusst keine Klartextspalte. Ein Datenbank-Dump ohne den separat
    verwahrten KEK ist wertlos — genau das ist der Zweck.
    """

    __tablename__ = "oauth_credentials"

    id: Mapped[uuid.UUID] = uuid_pk()
    account_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("connected_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    kek_id: Mapped[str] = mapped_column(String(64), nullable=False)
    """Ermöglicht KEK-Rotation ohne Neuverschlüsselung der Nutzdaten."""

    access_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    account: Mapped[ConnectedAccount] = relationship(back_populates="credentials")


# ==========================================================================
# Konversation
# ==========================================================================


class Conversation(Base, TimestampMixin):
    __tablename__ = "conversations"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str | None] = mapped_column(String(300))
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    """Rollierende Verdichtung — verhindert, dass Abschneiden den
    Gesprächsanfang verliert (docs/05-memory-context.md §2)."""

    summary_upto: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True))
    private_mode: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    """Kein Persistieren, keine Gedächtnisbildung."""

    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    messages: Mapped[list[Message]] = relationship(
        back_populates="conversation", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "channel IN ('voice','text','proactive','automation')", name="channel_valid"
        ),
    )


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[uuid.UUID] = uuid_pk()
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str | None] = mapped_column(Text)
    content_parts: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    data_class: Mapped[str] = mapped_column(String(2), nullable=False, server_default="P1")
    is_tainted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    token_count: Mapped[int | None] = mapped_column(Integer)
    model_used: Mapped[str | None] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    conversation: Mapped[Conversation] = relationship(back_populates="messages")

    __table_args__ = (
        Index("ix_messages_conversation_created", "conversation_id", "created_at"),
        CheckConstraint("role IN ('user','assistant','tool','system')", name="role_valid"),
        CheckConstraint("data_class IN ('P0','P1','P2','P3')", name="data_class_valid"),
    )


# ==========================================================================
# Läufe
# ==========================================================================


class Run(Base):
    """Das zentrale Ausführungsobjekt — persistiert, damit Läufe pausierbar,
    wiederaufnehmbar und kanalunabhängig sind."""

    __tablename__ = "runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("conversations.id", ondelete="CASCADE")
    )
    trigger: Mapped[str] = mapped_column(String(16), nullable=False, server_default="user")
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="queued")
    classification: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    routing: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    plan: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    state: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    taint_level: Mapped[str] = mapped_column(String(10), nullable=False, server_default="clean")
    data_class: Mapped[str] = mapped_column(String(2), nullable=False, server_default="P1")
    budget: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    usage: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    trace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    error: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    sanitized_from_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("runs.id", ondelete="SET NULL")
    )
    """Herkunft eines Laufs aus dem Taint-Sanitization-Gate.

    Der Lauf ist sauber, fuehrt genau einen bestaetigten Werkzeugaufruf aus und
    hat keinen Zugriff auf den Herkunftslauf — die Verknuepfung dient
    ausschliesslich der Nachvollziehbarkeit im Audit.
    """

    steps: Mapped[list[RunStep]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="RunStep.seq"
    )

    __table_args__ = (
        Index("ix_runs_user_started", "user_id", "started_at"),
        # Teilindex: Der Worker sucht beim Neustart genau diese Läufe.
        Index(
            "ix_runs_resumable",
            "status",
            postgresql_where=text(
                "status IN ('queued','planning','executing','awaiting_confirmation')"
            ),
        ),
        CheckConstraint("taint_level IN ('clean','tainted')", name="taint_valid"),
        CheckConstraint(
            "sanitized_from_run_id IS NULL OR taint_level = 'clean'",
            name="sanitized_runs_are_clean",
        ),
        CheckConstraint("data_class IN ('P0','P1','P2','P3')", name="data_class_valid"),
    )


class RunStep(Base):
    """Zugleich Datenquelle des Aktivitätsprotokolls in der UI — damit kann das
    Protokoll nicht von der tatsächlichen Ausführung abweichen."""

    __tablename__ = "run_steps"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    agent_name: Mapped[str | None] = mapped_column(String(40))
    model_used: Mapped[str | None] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    input: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    output: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    tokens_in: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    tokens_out: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    cost_eur: Mapped[Decimal] = mapped_column(
        Numeric(12, 6), nullable=False, server_default=text("0")
    )
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    run: Mapped[Run] = relationship(back_populates="steps")

    __table_args__ = (UniqueConstraint("run_id", "seq", name="uq_run_steps_run_seq"),)


# ==========================================================================
# Werkzeuge, Bestätigungen, Audit
# ==========================================================================


class ToolInvocation(Base):
    __tablename__ = "tool_invocations"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_seq: Mapped[int | None] = mapped_column(Integer)
    """Der Planschritt dieses Aufrufs — der Anker der Wiederaufnahme.

    ``None`` für ``POST /runs/{id}/steps``: Dort nennt der Aufrufer das
    Werkzeug, und der Aufruf gehört zu keinem geplanten Schritt."""

    tool_name: Mapped[str] = mapped_column(String(80), nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_decision: Mapped[str] = mapped_column(String(16), nullable=False)
    decision_reason: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(120), unique=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="pending")
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    """Wann der ExecutionGrant dieser Invokation eingelöst wurde.

    Getrennt von ``executed_at``, obwohl beide dasselbe Ereignis umgeben:
    ``executed_at`` schreibt das Protokoll fort und wird von ``mark()`` gesetzt,
    also nach der Wirkung. ``consumed_at`` ist der Anspruch und entsteht davor,
    als bedingtes UPDATE. Beides auf dieselbe Spalte zu legen hieße, die
    Einmaligkeitszusage an den Protokollpfad zu hängen — und der darf sich
    ändern, ohne dass jemand an eine Sicherheitseigenschaft denkt.
    """

    __table_args__ = (
        CheckConstraint(
            "policy_decision IN ('allow','confirm','deny')", name="policy_decision_valid"
        ),
        # Die Frage der Wiederaufnahme: „welcher Aufruf gehört zu Schritt N
        # dieses Laufs?" Ohne Index ein Tabellenscan je Lauf.
        Index("ix_tool_invocations_run_step", "run_id", "step_seq"),
    )


class PendingAction(Base):
    __tablename__ = "pending_actions"

    id: Mapped[uuid.UUID] = uuid_pk()
    invocation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("tool_invocations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    preview: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    """Der validierte, tatsächlich auszuführende Payload — nicht eine vom
    Modell formulierte Beschreibung (docs/07-security §5)."""

    tool_name: Mapped[str] = mapped_column(String(80), nullable=False)
    """Welches Werkzeug bestaetigt wird. Geht in den Payload-Hash ein, damit
    eine Bestaetigung nicht auf ein anderes Werkzeug uebertragbar ist."""

    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    """SHA-256 der kanonisierten Argumente zum Zeitpunkt der Anfrage.

    Wird unmittelbar vor der Ausfuehrung erneut gebildet und verglichen. Ohne
    diesen Wert waere die Bestaetigung eine Pauschalfreigabe fuer die
    Aktionsart statt eine Zustimmung zu einem konkreten Inhalt.
    """

    frozen_arguments: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    """Die eingefrorenen Argumente. Getrennt von ``preview`` gehalten: Die
    Vorschau ist fuer Menschen, diese Werte sind fuer die Ausfuehrung."""

    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    session_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    """Bindung an die anfordernde Sitzung — begrenzt den Schaden eines
    gestohlenen Sitzungstokens auf Aktionen dieser Sitzung."""

    requested_channel: Mapped[str] = mapped_column(String(10), nullable=False)
    """Kanal, auf dem die Vorschau angezeigt wurde. Bestaetigt werden darf nur
    dort — eine Geste, die einen ungelesenen Dialog freigibt, ist keine
    informierte Zustimmung."""

    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    response: Mapped[str | None] = mapped_column(String(16))
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    """Der Ausführungsanspruch — gesetzt, sobald eine Bestätigung ihre eine
    Ausführung erwirkt hat.

    Getrennt von ``response``, weil es zwei verschiedene Ereignisse sind: Der
    Nutzer hat zugestimmt (``response``), und die Zustimmung ist eingelöst
    (``executed_at``). Ohne diese Trennung schützt die Nonce nur den
    Bestätigungsschritt, während dieselbe Bestätigung beliebig oft ausgeführt
    werden kann."""
    responded_via: Mapped[str | None] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_pending_open", "user_id", postgresql_where=text("response IS NULL")),
        CheckConstraint(
            "response IS NULL OR response IN ('approved','rejected','expired')",
            name="response_valid",
        ),
        CheckConstraint(
            "responded_via IS NULL OR responded_via IN ('ui','voice','gesture')",
            name="responded_via_valid",
        ),
        CheckConstraint(
            "requested_channel IN ('ui','voice','gesture')", name="requested_channel_valid"
        ),
        # Der Hash ist ein Hexstring fester Laenge. Ein kuerzerer Wert waere
        # ein stiller Ausfall des Vergleichs vor der Ausfuehrung.
        CheckConstraint("payload_hash ~ '^[0-9a-f]{64}$'", name="payload_hash_format"),
        CheckConstraint("length(nonce) >= 32", name="nonce_min_entropy"),
    )


class AuditLog(Base):
    """Append-only, hash-verkettet.

    ``UPDATE`` und ``DELETE`` werden in der Migration auf Datenbankebene
    entzogen — die Unveränderlichkeit hängt nicht von Anwendungsdisziplin ab.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    actor: Mapped[str] = mapped_column(String(80), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    resource: Mapped[str | None] = mapped_column(String(255))
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    trace_id: Mapped[str | None] = mapped_column(String(64))
    prev_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    entry_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


# ==========================================================================
# Gedächtnis
# ==========================================================================


class Memory(Base, TimestampMixin):
    __tablename__ = "memories"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    structured: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    data_class: Mapped[str] = mapped_column(String(2), nullable=False, server_default="P2")

    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    source_ref: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("1.0"))

    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="candidate")
    superseded_by: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("memories.id", ondelete="SET NULL")
    )

    importance: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("0.5"))
    access_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    last_accessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    search_tsv: Mapped[str] = mapped_column(
        TSVECTOR,
        Computed("to_tsvector('german', content)", persisted=True),
        nullable=False,
    )
    """Von der Datenbank gepflegt. Reine Vektorsuche versagt an Eigennamen und
    Aktenzeichen — deshalb hybrid (docs/05-memory-context.md §4)."""

    __table_args__ = (
        Index("ix_memories_user_kind_status", "user_id", "kind", "status"),
        Index("ix_memories_search_tsv", "search_tsv", postgresql_using="gin"),
        Index(
            "ix_memories_retention",
            "retention_until",
            postgresql_where=text("retention_until IS NOT NULL"),
        ),
        CheckConstraint(
            "kind IN ('semantic_fact','preference','episodic','entity','procedure')",
            name="kind_valid",
        ),
        CheckConstraint(
            "status IN ('candidate','active','superseded','rejected')", name="status_valid"
        ),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="confidence_range"),
        CheckConstraint("data_class IN ('P0','P1','P2','P3')", name="data_class_valid"),
    )


class MemoryEmbedding(Base):
    """Getrennt von ``memories``: Ein Embedding-Modellwechsel darf keine Fakten
    anfassen und muss parallel aufbaubar sein."""

    __tablename__ = "memory_embeddings"

    memory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("memories.id", ondelete="CASCADE"), primary_key=True
    )
    model: Mapped[str] = mapped_column(String(80), primary_key=True)
    embedding: Mapped[Any] = mapped_column(Vector(EMBEDDING_DIM), nullable=False)

    __table_args__ = (
        Index(
            "ix_memory_embeddings_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_with={"m": 16, "ef_construction": 64},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )


# ==========================================================================
# Dokumente
# ==========================================================================


class Document(Base, TimestampMixin):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    source_ref: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(120), nullable=False)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    data_class: Mapped[str] = mapped_column(String(2), nullable=False, server_default="P2")
    is_untrusted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    """Fremddokumente können Anweisungen enthalten — Nutzung markiert den Lauf
    als kontaminiert."""

    indexed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    chunks: Mapped[list[DocumentChunk]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("user_id", "content_hash", name="uq_documents_user_hash"),)


class DocumentChunk(Base):
    __tablename__ = "document_chunks"

    id: Mapped[uuid.UUID] = uuid_pk()
    document_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    heading_path: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    """Kapitelpfad — erhält beim Retrieval den Zusammenhang."""

    page: Mapped[int | None] = mapped_column(Integer)
    token_count: Mapped[int] = mapped_column(Integer, nullable=False)

    search_tsv: Mapped[str] = mapped_column(
        TSVECTOR,
        Computed("to_tsvector('german', content)", persisted=True),
        nullable=False,
    )

    document: Mapped[Document] = relationship(back_populates="chunks")

    __table_args__ = (
        UniqueConstraint("document_id", "seq", name="uq_chunks_doc_seq"),
        Index("ix_chunks_search_tsv", "search_tsv", postgresql_using="gin"),
    )


class ChunkEmbedding(Base):
    __tablename__ = "chunk_embeddings"

    chunk_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("document_chunks.id", ondelete="CASCADE"), primary_key=True
    )
    model: Mapped[str] = mapped_column(String(80), primary_key=True)
    embedding: Mapped[Any] = mapped_column(Vector(EMBEDDING_DIM), nullable=False)

    __table_args__ = (
        Index(
            "ix_chunk_embeddings_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_with={"m": 16, "ef_construction": 64},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )


# ==========================================================================
# Aufgaben und Automationen
# ==========================================================================


class Task(Base, TimestampMixin):
    __tablename__ = "tasks"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="open")
    priority: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("3"))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    project: Mapped[str | None] = mapped_column(String(120))
    external_ref: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    __table_args__ = (
        CheckConstraint("status IN ('open','in_progress','done','cancelled')", name="status_valid"),
        CheckConstraint("priority BETWEEN 1 AND 5", name="priority_range"),
    )


class Automation(Base, TimestampMixin):
    __tablename__ = "automations"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    trigger_type: Mapped[str] = mapped_column(String(24), nullable=False)
    trigger_config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    condition: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    action: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    allowed_scopes: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, server_default=text("'{}'::varchar[]")
    )
    """Eine Automation erbt NICHT alle Rechte des Nutzers — nachts ist keine
    Bestätigungsinstanz anwesend."""

    requires_confirmation: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    last_fired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_fire_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_automations_next_fire", "next_fire_at", postgresql_where=text("enabled")),
        CheckConstraint(
            "trigger_type IN ('cron','once','calendar_event','email_match',"
            "'webhook','state_change')",
            name="trigger_type_valid",
        ),
    )


# ==========================================================================
# Plugins und Systemzustand
# ==========================================================================


class Plugin(Base, TimestampMixin):
    __tablename__ = "plugins"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    """Nach der Installation deaktiviert. Installation und Aktivierung sind
    zwei bewusste Schritte."""

    source: Mapped[str] = mapped_column(String(20), nullable=False)


class PluginPermission(Base):
    __tablename__ = "plugin_permissions"

    plugin_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("plugins.id", ondelete="CASCADE"), primary_key=True
    )
    scope: Mapped[str] = mapped_column(String(64), ForeignKey("scopes.name"), primary_key=True)
    granted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))


class SystemHealth(Base):
    __tablename__ = "system_health"

    component: Mapped[str] = mapped_column(String(80), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("status IN ('ok','degraded','down','unknown')", name="status_valid"),
    )


# ==========================================================================
# V1.1 — Identity, Ziele, Entitäten
#
# Siehe docs/16-v1.1-review.md und docs/17-identity-goals.md.
# Diese Schicht ist der Unterschied zwischen einem sicheren Agentensystem und
# einem persönlichen Assistenten.
# ==========================================================================


class DomainPreference(Base, TimestampMixin):
    """Domänenspezifische Präferenz — nur geladen, wenn die Domäne im Spiel ist.

    Getrennt vom Kernprofil in ``users.preferences``, weil dieses bei jedem
    Turn mitfährt und deshalb hart budgetiert ist (400 Token).
    """

    __tablename__ = "domain_preferences"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    domain: Mapped[str] = mapped_column(String(24), nullable=False)
    key: Mapped[str] = mapped_column(String(80), nullable=False)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("1.0"))

    __table_args__ = (
        UniqueConstraint("user_id", "domain", "key", name="uq_domain_pref"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="confidence_range"),
    )


class BehaviourRule(Base, TimestampMixin):
    """Do/Don't-Regel für Stil und Verhalten.

    Steuert ausdrücklich **keine** Berechtigungen — sonst wäre eine per
    Injection eingeschleuste Regel ein Weg zur Rechteerweiterung. Die
    Durchsetzung liegt in der Anwendungsvalidierung; die Policy Engine liest
    diese Tabelle gar nicht erst.
    """

    __tablename__ = "behaviour_rules"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    rule: Mapped[str] = mapped_column(String(200), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(24))
    priority: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("3"))
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))

    __table_args__ = (
        CheckConstraint("kind IN ('do','dont')", name="kind_valid"),
        CheckConstraint("priority BETWEEN 1 AND 5", name="priority_range"),
    )


class Goal(Base, TimestampMixin):
    """Ziel, Projekt oder Meilenstein.

    Bewusst keine Memory-Zeile: Ein Ziel hat Zustand, Horizont, Fortschritt und
    Randbedingungen — ein Retrieval-Treffer beantwortet „Wie weit bin ich?" nicht.
    """

    __tablename__ = "goals"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    horizon: Mapped[str] = mapped_column(String(12), nullable=False, server_default="offen")
    status: Mapped[str] = mapped_column(String(12), nullable=False, server_default="aktiv")
    priority: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("3"))
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("goals.id", ondelete="SET NULL")
    )
    constraints: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, server_default=text("'{}'::varchar[]")
    )
    target_date: Mapped[date | None] = mapped_column(Date)
    progress_note: Mapped[str | None] = mapped_column(Text)
    data_class: Mapped[str] = mapped_column(String(2), nullable=False, server_default="P2")
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    search_tsv: Mapped[str] = mapped_column(
        TSVECTOR,
        Computed(
            "to_tsvector('german', title || ' ' || coalesce(description, ''))", persisted=True
        ),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_goals_user_status", "user_id", "status"),
        Index("ix_goals_search_tsv", "search_tsv", postgresql_using="gin"),
        CheckConstraint(
            "horizon IN ('tag','woche','monat','quartal','jahr','offen')", name="horizon_valid"
        ),
        CheckConstraint(
            "status IN ('aktiv','pausiert','erreicht','verworfen')", name="status_valid"
        ),
        CheckConstraint("priority BETWEEN 1 AND 5", name="priority_range"),
        CheckConstraint("data_class IN ('P0','P1','P2','P3')", name="data_class_valid"),
        # Ein erreichtes Ziel ohne Abschlussdatum wäre eine unbelegte Behauptung.
        CheckConstraint(
            "status <> 'erreicht' OR completed_at IS NOT NULL", name="completed_needs_date"
        ),
        CheckConstraint("parent_id IS NULL OR parent_id <> id", name="no_self_parent"),
    )


class Entity(Base, TimestampMixin):
    """Eine benannte Sache, auf die sich Gespräche und Objekte beziehen.

    Trägt drei getrennt entstandene Anforderungen zugleich: Referenzauflösung,
    Ziele/Projekte und präzises Retrieval ohne Vektorrauschen. Genau deshalb
    braucht es keinen zusätzlichen Graph-Layer (docs/16-v1.1-review.md §3+4).
    """

    __tablename__ = "entities"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    canonical_name: Mapped[str] = mapped_column(String(200), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, server_default=text("'{}'::varchar[]")
    )
    gender: Mapped[str] = mapped_column(String(8), nullable=False, server_default="unknown")
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    data_class: Mapped[str] = mapped_column(String(2), nullable=False, server_default="P2")
    goal_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("goals.id", ondelete="CASCADE")
    )
    last_mentioned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    mention_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))

    __table_args__ = (
        UniqueConstraint("user_id", "kind", "canonical_name", name="uq_entity_identity"),
        Index("ix_entities_user_kind", "user_id", "kind"),
        # Salienz-Abfrage der Referenzauflösung läuft über diesen Index.
        Index("ix_entities_salience", "user_id", "last_mentioned_at"),
        Index("ix_entities_aliases", "aliases", postgresql_using="gin"),
        CheckConstraint(
            "kind IN ('person','organisation','projekt','ort','goal','thema')", name="kind_valid"
        ),
        CheckConstraint("gender IN ('m','f','n','unknown')", name="gender_valid"),
        CheckConstraint("data_class IN ('P0','P1','P2','P3')", name="data_class_valid"),
        CheckConstraint("kind <> 'goal' OR goal_id IS NOT NULL", name="goal_kind_needs_goal"),
    )


class EntityLink(Base):
    """Verknüpfung einer Entität mit einem beliebigen Objekt.

    „Was habe ich letzte Woche mit Thomas besprochen?" ist ein Join über diese
    Tabelle plus Zeitfilter — kein Ähnlichkeitsproblem.

    Bewusst ohne Fremdschlüssel auf das Ziel: Die Zieltabelle wechselt je
    ``target_kind``. Die referentielle Integrität wird beim Löschen über die
    Aufräumroutine hergestellt, nicht über sechs sich ausschließende Spalten.
    """

    __tablename__ = "entity_links"

    entity_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True
    )
    target_kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    target_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    role: Mapped[str | None] = mapped_column(String(60))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_entity_links_target", "target_kind", "target_id"),
        CheckConstraint(
            "target_kind IN ('memory','document','task','goal','message','event')",
            name="target_kind_valid",
        ),
    )


class EntityRelation(Base):
    """Gerichtete Beziehung zwischen zwei Entitäten.

    Bewusst schlicht: reicht für „Thomas arbeitet an Projekt X", ohne eine
    zweite Abfragesprache einzuführen.
    """

    __tablename__ = "entity_relations"

    from_entity_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True
    )
    to_entity_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True
    )
    relation: Mapped[str] = mapped_column(String(60), primary_key=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("1.0"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("from_entity_id <> to_entity_id", name="no_self_relation"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="confidence_range"),
    )
