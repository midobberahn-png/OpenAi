"""sessions — der vorige Token und der Zeitpunkt der Rotation

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Erstellt: 2026-08-26

Zwei Spalten für ADR-020. Die Entscheidungen dahinter stehen dort; hier die
drei, die das Schema tragen:

* **Ein Vorgänger, keine Kette.** ``prev_token_hash`` ist eine Spalte und keine
  Tabelle. Bei einem Rotationstakt von 15 Minuten und einem
  Überlappungsfenster von 60 Sekunden kann es keinen zweiten Vorgänger geben,
  der noch gälte. Eine Kette wäre Vorrat für einen Fall, den die Entscheidung
  darüber ausschließt.
* **Kein ``UNIQUE`` auf dem Vorgänger.** Der aktuelle Hash ist eindeutig, weil
  er ein Geheimnis ist, das genau eine Sitzung öffnet. Beim Vorgänger wäre die
  Eindeutigkeit eine Zusage über die *Vergangenheit* — und die erste
  Kollision, so unwahrscheinlich sie ist, wäre eine fehlgeschlagene Rotation
  statt einer abgewiesenen Anmeldung. Gesucht wird darauf trotzdem, deshalb
  ein Index.
* **``rotated_at`` gehört auf die Uhr der Datenbank.** Das Überlappungsfenster
  wird gegen diesen Zeitstempel gerechnet; käme er aus dem Prozess und der
  Vergleich aus ``now()``, hinge die Gültigkeit eines Tokens an der Uhrendrift
  zwischen beiden. Diese Lehre hat das Projekt eine Sitzung gekostet
  (Leerlaufmessung, ``runs.last_step_at``).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "f6a7b8c9d0e1"
down_revision = "e5f6a7b8c9d0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("sessions", sa.Column("prev_token_hash", sa.String(length=64), nullable=True))
    op.add_column("sessions", sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True))
    # Teilindex: Gesucht wird nur, solange es einen Vorgänger gibt, und das ist
    # die Ausnahme. Ein voller Index über überwiegend NULL wäre Ballast.
    op.create_index(
        "ix_sessions_prev_token_hash",
        "sessions",
        ["prev_token_hash"],
        unique=False,
        postgresql_where=sa.text("prev_token_hash IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_sessions_prev_token_hash", table_name="sessions")
    op.drop_column("sessions", "rotated_at")
    op.drop_column("sessions", "prev_token_hash")
