"""SQLAlchemy-Basis und gemeinsame Spaltentypen."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, ClassVar

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = ["Base", "TimestampMixin", "created_at", "jsonb", "updated_at", "uuid_pk"]


# Benennungskonvention: sorgt dafür, dass Alembic Constraints stabil benennt
# und Migrationen nicht bei jedem Lauf neu erfunden werden.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    type_annotation_map: ClassVar[dict[Any, Any]] = {
        dict[str, Any]: JSONB,
    }


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )


def created_at() -> Mapped[datetime]:
    return mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )


def updated_at() -> Mapped[datetime]:
    return mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


def jsonb(default: str = "'{}'::jsonb") -> Mapped[dict[str, Any]]:
    return mapped_column(JSONB, nullable=False, server_default=default)


class TimestampMixin:
    """Alle Zeitstempel sind ``TIMESTAMPTZ`` in UTC.

    Lokale Zeitzone ist ausschließlich Präsentationslogik — ein Assistent, der
    Termine verwaltet, darf sich hier keine Unschärfe leisten.
    """

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()
