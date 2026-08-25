"""last_step_at — der Leerlauf misst auf einer Uhr

Revision ID: d4e5f6a7b8c9
Revises: c1d2e3f4a5b6
Erstellt: 2026-08-25

Der Arbeiter sucht Läufe, die mitten im Plan stillstehen. Wie lange sie
stillstehen, las er bis hierher aus dem Zustandsdokument: dem ``finished_at``
des letzten erledigten Schrittes — geschrieben vom **Prozess**, verglichen
gegen ``now()`` aus der **Datenbank**.

**Zwei Uhren in einem Vergleich, und der Unterschied ist messbar.** Am
25.08.2026 lief die Datenbankuhr der Entwicklungs-VM erst 100 ms vor, Stunden
später 42 ms nach. Im zweiten Fall liegt ein gerade beendeter Schritt aus Sicht
der Datenbank in der **Zukunft** und ist nie „vorbei" — der Lauf wird nicht
gefunden. Ein Test hat das zweimal aufgedeckt (8/8 grün bei positivem Versatz,
3/3 rot bei negativem).

Dieselbe Überlegung steht seit jeher beim Anspruch: ``claimed_at`` kommt aus
``now()``, „damit Anfang und Ende der Messung auf **derselben** Uhr stehen".
Diese Spalte zieht die Leerlaufmessung auf denselben Stand. Sie gehört
bewusst **nicht** ins Zustandsdokument: Was eine Frist misst, soll nicht davon
abhängen, welcher Prozess das Dokument zuletzt geschrieben hat.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d4e5f6a7b8c9"
down_revision: str | None = "c1d2e3f4a5b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("last_step_at", sa.DateTime(timezone=True), nullable=True))
    # Bestand nachziehen: Was im Dokument steht, ist die beste vorhandene
    # Auskunft — ab jetzt schreibt die Datenbank. ``started_at`` als
    # Rückfallebene, damit kein Lauf mit erledigten Schritten ohne Zeitstempel
    # bleibt und damit unauffindbar würde.
    op.execute(
        """
        UPDATE runs
           SET last_step_at = COALESCE(
                   (state -> 'completed_steps' -> -1 ->> 'finished_at')::timestamptz,
                   started_at
               )
         WHERE jsonb_array_length(COALESCE(state -> 'completed_steps', '[]'::jsonb)) > 0
        """
    )


def downgrade() -> None:
    op.drop_column("runs", "last_step_at")
