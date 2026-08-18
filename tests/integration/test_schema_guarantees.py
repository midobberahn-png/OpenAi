"""Zusicherungen, die ausschließlich auf Datenbankebene gelten.

Diese Tests prüfen keine Anwendungslogik, sondern die Eigenschaften, auf die
sich die Anwendung *verlässt*. Fällt einer davon aus, sind Aussagen in
docs/07-security-permissions.md und docs/03-datenmodell.md nicht mehr wahr.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


class TestAuditLogUnveraenderlichkeit:
    """docs/07-security-permissions.md §8 — das Audit-Log ist append-only.

    Die Zusicherung hängt bewusst nicht von Anwendungsdisziplin ab: Wer die
    Anwendung kompromittiert, könnte sonst seine Spuren beseitigen.
    """

    async def test_insert_ist_erlaubt(self, conn: AsyncConnection) -> None:
        result = await conn.execute(
            text(
                "INSERT INTO audit_log (actor, action, entry_hash) "
                "VALUES ('test', 'tool.execute', :h) RETURNING id"
            ),
            {"h": b"\x00" * 32},
        )
        assert result.scalar_one() > 0

    @pytest.mark.invariant("audit-append-only")
    async def test_update_wird_abgelehnt(self, conn: AsyncConnection) -> None:
        await conn.execute(
            text("INSERT INTO audit_log (actor, action, entry_hash) VALUES ('test', 'x', :h)"),
            {"h": b"\x01" * 32},
        )
        with pytest.raises(DBAPIError, match="append-only"):
            await conn.execute(text("UPDATE audit_log SET action = 'manipuliert'"))

    @pytest.mark.invariant("audit-append-only")
    async def test_delete_wird_abgelehnt(self, conn: AsyncConnection) -> None:
        await conn.execute(
            text("INSERT INTO audit_log (actor, action, entry_hash) VALUES ('test', 'x', :h)"),
            {"h": b"\x02" * 32},
        )
        with pytest.raises(DBAPIError, match="append-only"):
            await conn.execute(text("DELETE FROM audit_log"))

    @pytest.mark.invariant("audit-append-only")
    async def test_pseudonymisierung_darf_nichts_anderes_aendern(
        self, conn: AsyncConnection
    ) -> None:
        """Die Ausnahme für die DSGVO-Löschung muss eng bleiben.

        Erlaubt ist ausschließlich user_id → NULL bei sonst identischer Zeile.
        Ein UPDATE, das dabei zusätzlich Inhalte verändert, wäre genau der
        Schlupfweg, über den sich Spuren beseitigen ließen.
        """
        user_id = uuid.uuid4()
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:id, :m, 'X')"),
            {"id": user_id, "m": f"{user_id}@example.test"},
        )
        await conn.execute(
            text(
                "INSERT INTO audit_log (user_id, actor, action, entry_hash) "
                "VALUES (:uid, 'jarvis', 'mail.send', :h)"
            ),
            {"uid": user_id, "h": b"\x04" * 32},
        )

        # user_id nullen UND action ändern → muss scheitern
        with pytest.raises(DBAPIError, match="append-only"):
            await conn.execute(
                text(
                    "UPDATE audit_log SET user_id = NULL, action = 'harmlos' WHERE user_id = :uid"
                ),
                {"uid": user_id},
            )

    async def test_user_id_neu_setzen_ist_unzulaessig(self, conn: AsyncConnection) -> None:
        """Nur NOT NULL → NULL ist erlaubt, nicht die Gegenrichtung."""
        await conn.execute(
            text("INSERT INTO audit_log (actor, action, entry_hash) VALUES ('jarvis', 'x', :h)"),
            {"h": b"\x05" * 32},
        )
        with pytest.raises(DBAPIError, match="append-only"):
            await conn.execute(
                text("UPDATE audit_log SET user_id = :uid WHERE user_id IS NULL"),
                {"uid": uuid.uuid4()},
            )


class TestVollstaendigeLoeschung:
    """docs/03-datenmodell.md §10 — Löschung in einer Transaktion.

    Das ist der praktische Grund für ADR-003 (eine Datenbank statt zwei
    Systeme): Ein Löschauftrag, der über zwei Systeme laufen müsste, bleibt
    irgendwann unvollständig.
    """

    async def test_nutzerloeschung_raeumt_alle_abhaengigen_daten(
        self, conn: AsyncConnection
    ) -> None:
        user_id = uuid.uuid4()
        conv_id = uuid.uuid4()
        mem_id = uuid.uuid4()

        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:id, :mail, 'Testnutzer')"),
            {"id": user_id, "mail": f"{user_id}@example.test"},
        )
        await conn.execute(
            text("INSERT INTO conversations (id, user_id, channel) VALUES (:cid, :uid, 'text')"),
            {"cid": conv_id, "uid": user_id},
        )
        await conn.execute(
            text(
                "INSERT INTO messages (conversation_id, role, content) "
                "VALUES (:cid, 'user', 'Hallo')"
            ),
            {"cid": conv_id},
        )
        await conn.execute(
            text(
                "INSERT INTO memories (id, user_id, kind, content, source_type, status) "
                "VALUES (:mid, :uid, 'preference', 'Nenn mich Mirek.', 'user_stated', 'active')"
            ),
            {"mid": mem_id, "uid": user_id},
        )
        await conn.execute(
            text(
                "INSERT INTO memory_embeddings (memory_id, model, embedding) "
                "VALUES (:mid, 'test', :emb)"
            ),
            {"mid": mem_id, "emb": "[" + ",".join(["0.0"] * 1024) + "]"},
        )

        await conn.execute(text("DELETE FROM users WHERE id = :uid"), {"uid": user_id})

        for table, column, value in [
            ("conversations", "user_id", user_id),
            ("messages", "conversation_id", conv_id),
            ("memories", "user_id", user_id),
            ("memory_embeddings", "memory_id", mem_id),
        ]:
            remaining = await conn.execute(
                text(f"SELECT count(*) FROM {table} WHERE {column} = :v"), {"v": value}
            )
            assert remaining.scalar_one() == 0, f"{table} nicht mitgelöscht"

    async def test_audit_log_ueberlebt_pseudonymisiert(self, conn: AsyncConnection) -> None:
        """Der Audit-Eintrag bleibt erhalten, verliert aber den Personenbezug —
        sonst bräche die Hash-Kette."""
        user_id = uuid.uuid4()
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:id, :m, 'X')"),
            {"id": user_id, "m": f"{user_id}@example.test"},
        )
        await conn.execute(
            text(
                "INSERT INTO audit_log (user_id, actor, action, entry_hash) "
                "VALUES (:uid, 'jarvis', 'tool.execute', :h)"
            ),
            {"uid": user_id, "h": b"\x03" * 32},
        )
        await conn.execute(text("DELETE FROM users WHERE id = :uid"), {"uid": user_id})

        row = await conn.execute(
            text("SELECT count(*) FROM audit_log WHERE action = 'tool.execute' AND user_id IS NULL")
        )
        assert row.scalar_one() >= 1


class TestSchemaEigenschaften:
    async def test_hnsw_indizes_existieren(self, conn: AsyncConnection) -> None:
        """Ohne HNSW ist Vektorsuche ein sequenzieller Scan."""
        rows = await conn.execute(
            text("SELECT indexname FROM pg_indexes WHERE indexdef LIKE '%hnsw%'")
        )
        names = {r[0] for r in rows}
        assert "ix_memory_embeddings_hnsw" in names
        assert "ix_chunk_embeddings_hnsw" in names

    async def test_volltextspalten_werden_automatisch_gepflegt(self, conn: AsyncConnection) -> None:
        user_id = uuid.uuid4()
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:id, :m, 'X')"),
            {"id": user_id, "m": f"{user_id}@example.test"},
        )
        await conn.execute(
            text(
                "INSERT INTO memories (user_id, kind, content, source_type, status) "
                "VALUES (:uid, 'semantic_fact', "
                "'Der Steuerberater heißt Michael Krause.', 'user_stated', 'active')"
            ),
            {"uid": user_id},
        )
        hit = await conn.execute(
            text(
                "SELECT count(*) FROM memories "
                "WHERE user_id = :uid AND search_tsv @@ plainto_tsquery('german', 'Steuerberater')"
            ),
            {"uid": user_id},
        )
        assert hit.scalar_one() == 1

    async def test_datenklasse_ist_auf_datenbankebene_beschraenkt(
        self, conn: AsyncConnection
    ) -> None:
        """Ein Tippfehler in der Klassifikation darf nicht persistiert werden."""
        user_id = uuid.uuid4()
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:id, :m, 'X')"),
            {"id": user_id, "m": f"{user_id}@example.test"},
        )
        with pytest.raises(DBAPIError):
            await conn.execute(
                text(
                    "INSERT INTO memories (user_id, kind, content, source_type, data_class) "
                    "VALUES (:uid, 'preference', 'x', 'user_stated', 'P9')"
                ),
                {"uid": user_id},
            )

    async def test_wiederaufnahme_index_existiert(self, conn: AsyncConnection) -> None:
        """Der Worker sucht beim Neustart genau über diesen Teilindex."""
        rows = await conn.execute(
            text("SELECT indexname FROM pg_indexes WHERE indexname = 'ix_runs_resumable'")
        )
        assert rows.scalar_one_or_none() == "ix_runs_resumable"
