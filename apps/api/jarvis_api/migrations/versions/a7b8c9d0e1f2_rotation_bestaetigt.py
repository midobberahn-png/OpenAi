"""sessions — wann der Ersatztoken zum ersten Mal benutzt wurde

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Erstellt: 2026-08-26

Eine Spalte für den Nachtrag zu ADR-020. Sie beantwortet die Frage, an der die
Wiederverwendungserkennung sonst zwei verschiedene Lagen gleich behandelt:
**Kam der Ersatz je an?**

* ``NULL`` heißt „nie benutzt". Das ist der Zustand unmittelbar nach jeder
  Rotation und der Grund, warum ein alter Token danach noch tragen darf: Der
  Client hat den neuen möglicherweise nie gesehen.
* Gesetzt heißt „der rechtmäßige Client führt den neuen Token". Ein alter, der
  danach auftaucht, ist eine Kopie.

``now()`` wieder von der Datenbank, aus demselben Grund wie bei ``rotated_at``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "a7b8c9d0e1f2"
down_revision = "f6a7b8c9d0e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "sessions", sa.Column("rotation_confirmed_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("sessions", "rotation_confirmed_at")
