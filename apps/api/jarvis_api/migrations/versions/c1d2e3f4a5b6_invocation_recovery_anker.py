"""Das Werkzeugprotokoll als Recovery-Anker: step_seq statt step_id.

Ein Lauf, der mit belegtem ``current_step`` steht, ist entweder in Arbeit oder
hängengeblieben. Die Wiederaufnahme kann das nur beantworten, wenn sie
nachsehen kann, was aus dem Aufruf **dieses Schrittes** geworden ist.

``step_id`` war eine UUID auf ``run_steps``, die niemand je gesetzt hat — und
sie passte auch nicht: Ein Planschritt trägt eine Nummer innerhalb seines
Laufs, keine eigene Kennung. Ersetzt durch ``step_seq``.

Kein Datenerhalt nötig: Die Spalte war ausnahmslos NULL.

Revision ID: c1d2e3f4a5b6
Revises: a1c7f2b90e44
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "c1d2e3f4a5b6"
down_revision = "a1c7f2b90e44"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "fk_tool_invocations_step_id_run_steps", "tool_invocations", type_="foreignkey"
    )
    op.drop_column("tool_invocations", "step_id")
    op.add_column("tool_invocations", sa.Column("step_seq", sa.Integer(), nullable=True))
    # Der Index, über den die Wiederaufnahme sucht: „welcher Aufruf gehört zu
    # Schritt N dieses Laufs?". Ohne ihn wäre die Frage ein Tabellenscan je Lauf.
    op.create_index(
        "ix_tool_invocations_run_step",
        "tool_invocations",
        ["run_id", "step_seq"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_tool_invocations_run_step", table_name="tool_invocations")
    op.drop_column("tool_invocations", "step_seq")
    op.add_column("tool_invocations", sa.Column("step_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_tool_invocations_step_id_run_steps",
        "tool_invocations",
        "run_steps",
        ["step_id"],
        ["id"],
        ondelete="SET NULL",
    )
