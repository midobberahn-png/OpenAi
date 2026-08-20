"""calendar events

Revision ID: a1c7f2b90e44
Revises: 03b46c72ab8a
Erstellt: 2026-08-20

Der lokale Kalender. Bewusst eine eigene Tabelle und kein Fremdsystem: Das
erste schreibende Werkzeug soll die Bestätigungskette erproben, nicht die
Eigenheiten von CalDAV. Ein späterer Adapter für Google oder Apple erfüllt
denselben Port und lässt alles darüber unberührt.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a1c7f2b90e44"
down_revision: str | None = "03b46c72ab8a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "calendar_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("location", sa.String(length=300), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "attendees",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_calendar_events_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_calendar_events")),
        # Ein Termin, der endet, bevor er beginnt, ist keine Eingabe, die eine
        # Anwendungsschicht abfangen "sollte" — er ist auf Datenbankebene
        # ausgeschlossen. Dieselbe Überlegung wie bei den übrigen CHECKs des
        # Schemas: Was strukturell unmöglich sein soll, gehört ins DDL.
        sa.CheckConstraint("ends_at > starts_at", name=op.f("ck_calendar_events_time_order")),
    )
    op.create_index(
        op.f("ix_calendar_events_user_start"),
        "calendar_events",
        ["user_id", "starts_at"],
        unique=False,
    )
    # Kein Fremdschlüssel auf ``tool_invocations``: Ein Termin kann auch von
    # Hand entstehen, und ein Kalendereintrag, der ohne Werkzeugaufruf nicht
    # existieren darf, wäre eine Kopplung an den Weg statt an die Sache.


def downgrade() -> None:
    op.drop_index(op.f("ix_calendar_events_user_start"), table_name="calendar_events")
    op.drop_table("calendar_events")
