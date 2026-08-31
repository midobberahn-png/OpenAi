"""oauth_authorizations - der Anspruch auf einen Rueckruf

Revision ID: a33249f0dbd7
Revises: a7b8c9d0e1f2
Erstellt: 2026-08-31

**Von Hand gekuerzt, und das gehoert dazu.** ``--autogenerate`` schlug
zusaetzlich vor, ``model_calls`` und ``calendar_events`` zu loeschen, dazu
``runs.last_step_at`` und die drei Rotationsspalten von ``sessions``. Alle
existieren in der Datenbank und in frueheren Migrationen, aber **nicht** in
``models.py`` — sie wurden nie als ORM-Modell nachgetragen. Autogenerate
vergleicht gegen die Modelle und haelt darum alles, was dort fehlt, fuer
ueberfluessig. Wer hier eine Migration erzeugt, liest sie und streicht.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a33249f0dbd7"
down_revision: str | None = "a7b8c9d0e1f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oauth_authorizations",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("state_hash", sa.LargeBinary(), nullable=False),
        sa.Column("verifier_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("verifier_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("verifier_wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("verifier_kek_id", sa.String(length=64), nullable=False),
        sa.Column("requested_scopes", sa.ARRAY(sa.String()), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_oauth_authorizations_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth_authorizations")),
        sa.UniqueConstraint("state_hash", name=op.f("uq_oauth_authorizations_state_hash")),
    )
    op.create_index(
        op.f("ix_oauth_authorizations_created_at"),
        "oauth_authorizations",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oauth_authorizations_user_id"), "oauth_authorizations", ["user_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_oauth_authorizations_user_id"), table_name="oauth_authorizations")
    op.drop_index(op.f("ix_oauth_authorizations_created_at"), table_name="oauth_authorizations")
    op.drop_table("oauth_authorizations")
