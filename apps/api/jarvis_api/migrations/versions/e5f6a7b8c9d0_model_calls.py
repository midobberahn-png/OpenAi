"""model_calls — das Kostenhauptbuch

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Erstellt: 2026-08-25

Eine Zeile je Modellaufruf. Die Begründung steht im Port
(``jarvis_core.ports.spend``); hier stehen die Entscheidungen, die das Schema
trägt:

* **``occurred_at`` kommt aus ``now()``.** Nach der Lehre desselben Tages: Was
  gegen eine Frist oder eine Tagesgrenze verglichen wird, gehört auf die Uhr,
  die auch vergleicht. Ein Zeitstempel aus dem Prozess hätte den Tageswechsel
  wieder von zwei Uhren abhängig gemacht — und genau den sollte dieses
  Hauptbuch geradebiegen.
* **``cost_eur`` als ``numeric``**, nicht als Fließkomma. Geld in ``double
  precision`` ist ein Fehler, der erst bei der dritten Nachkommastelle auffällt.
* **``ON DELETE CASCADE`` am Lauf, ``SET NULL`` am Nutzer.** Wird ein Lauf
  gelöscht, verschwinden seine Aufrufe mit ihm — sie beschreiben ihn. Eine
  DSGVO-Löschung des Nutzers darf die Summen dagegen nicht verfälschen:
  Dieselbe Entscheidung wie beim Audit-Log, wo die Pseudonymisierung die Kette
  nicht bricht.
* **Kein ``UNIQUE``.** Zwei gleiche Aufrufe hintereinander sind kein Fehler,
  sondern zwei Aufrufe. Wer hier eine Eindeutigkeit erzwänge, verlöre echte
  Kosten.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e5f6a7b8c9d0"
down_revision: str | None = "d4e5f6a7b8c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "model_calls",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("model", sa.String(length=120), nullable=False),
        sa.Column("purpose", sa.String(length=40), nullable=False),
        sa.Column("tokens_in", sa.Integer(), server_default="0", nullable=False),
        sa.Column("tokens_out", sa.Integer(), server_default="0", nullable=False),
        sa.Column("cached_tokens_in", sa.Integer(), server_default="0", nullable=False),
        sa.Column("cache_write_tokens_in", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "cost_eur", sa.Numeric(precision=12, scale=6), server_default="0", nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.id"], name=op.f("fk_model_calls_run_id_runs"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_model_calls_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_model_calls")),
        sa.CheckConstraint("cost_eur >= 0", name=op.f("ck_model_calls_cost_not_negative")),
    )
    # Die Tagesabrechnung fragt „was hat dieser Nutzer seit X ausgegeben" —
    # genau diese Reihenfolge.
    op.create_index(
        op.f("ix_model_calls_user_occurred"),
        "model_calls",
        ["user_id", "occurred_at"],
        unique=False,
    )
    # Und die Gegenprobe fragt je Lauf.
    op.create_index(op.f("ix_model_calls_run"), "model_calls", ["run_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_model_calls_run"), table_name="model_calls")
    op.drop_index(op.f("ix_model_calls_user_occurred"), table_name="model_calls")
    op.drop_table("model_calls")
