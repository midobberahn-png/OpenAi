"""Datenbankzusicherungen der V1.1-Erweiterungen.

Die Invarianten sind an zwei Stellen verankert — in Pydantic und in der
Datenbank. Das ist Absicht: Die Anwendungsvalidierung gibt gute Fehlermeldungen,
die CHECK-Constraints halten auch dann, wenn jemand an der Anwendung vorbei
schreibt (Migration, Reparaturskript, Direktzugriff).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def _user(conn: AsyncConnection) -> uuid.UUID:
    uid = uuid.uuid4()
    await conn.execute(
        text("INSERT INTO users (id, email, display_name) VALUES (:id, :m, 'Test')"),
        {"id": uid, "m": f"{uid}@example.test"},
    )
    return uid


class TestSanitisierteLaeufe:
    """docs/16-v1.1-review.md §1 — das Gate darf den Schutz nicht umgehen."""

    @pytest.mark.invariant("taint-cross-run-isolation")
    async def test_sanierter_lauf_darf_nicht_kontaminiert_sein(self, conn: AsyncConnection) -> None:
        uid = await _user(conn)
        origin = uuid.uuid4()
        await conn.execute(
            text(
                "INSERT INTO runs (id, user_id, trace_id, budget, taint_level) "
                "VALUES (:id, :uid, 'trace-1', '{}'::jsonb, 'tainted')"
            ),
            {"id": origin, "uid": uid},
        )
        with pytest.raises(DBAPIError):
            await conn.execute(
                text(
                    "INSERT INTO runs (user_id, trace_id, budget, taint_level, "
                    "sanitized_from_run_id) "
                    "VALUES (:uid, 'trace-2', '{}'::jsonb, 'tainted', :origin)"
                ),
                {"uid": uid, "origin": origin},
            )

    async def test_sanierter_lauf_mit_sauberem_zustand_ist_zulaessig(
        self, conn: AsyncConnection
    ) -> None:
        uid = await _user(conn)
        origin = uuid.uuid4()
        await conn.execute(
            text(
                "INSERT INTO runs (id, user_id, trace_id, budget, taint_level) "
                "VALUES (:id, :uid, 'trace-1', '{}'::jsonb, 'tainted')"
            ),
            {"id": origin, "uid": uid},
        )
        result = await conn.execute(
            text(
                "INSERT INTO runs (user_id, trace_id, budget, taint_level, "
                "sanitized_from_run_id) "
                "VALUES (:uid, 'trace-2', '{}'::jsonb, 'clean', :origin) RETURNING id"
            ),
            {"uid": uid, "origin": origin},
        )
        assert result.scalar_one() is not None


class TestZiele:
    async def test_erreichtes_ziel_ohne_abschlussdatum_wird_abgelehnt(
        self, conn: AsyncConnection
    ) -> None:
        uid = await _user(conn)
        with pytest.raises(DBAPIError):
            await conn.execute(
                text(
                    "INSERT INTO goals (user_id, title, status) "
                    "VALUES (:uid, 'Business aufbauen', 'erreicht')"
                ),
                {"uid": uid},
            )

    async def test_ziel_kann_nicht_sein_eigenes_oberziel_sein(self, conn: AsyncConnection) -> None:
        uid = await _user(conn)
        gid = uuid.uuid4()
        with pytest.raises(DBAPIError):
            await conn.execute(
                text(
                    "INSERT INTO goals (id, user_id, title, parent_id) "
                    "VALUES (:gid, :uid, 'Ziel', :gid)"
                ),
                {"gid": gid, "uid": uid},
            )

    async def test_volltextsuche_ueber_titel_und_beschreibung(self, conn: AsyncConnection) -> None:
        uid = await _user(conn)
        await conn.execute(
            text(
                "INSERT INTO goals (user_id, title, description) "
                "VALUES (:uid, 'Cybersecurity-Business aufbauen', "
                "'Nebenberuflich starten, erste Mandanten gewinnen.')"
            ),
            {"uid": uid},
        )
        hit = await conn.execute(
            text(
                "SELECT count(*) FROM goals WHERE user_id = :uid "
                "AND search_tsv @@ plainto_tsquery('german', 'Mandanten')"
            ),
            {"uid": uid},
        )
        assert hit.scalar_one() == 1


class TestEntitaeten:
    async def test_zielentitaet_ohne_zielverweis_wird_abgelehnt(
        self, conn: AsyncConnection
    ) -> None:
        uid = await _user(conn)
        with pytest.raises(DBAPIError):
            await conn.execute(
                text(
                    "INSERT INTO entities (user_id, kind, canonical_name) "
                    "VALUES (:uid, 'goal', 'Business')"
                ),
                {"uid": uid},
            )

    async def test_selbstbeziehung_wird_abgelehnt(self, conn: AsyncConnection) -> None:
        uid = await _user(conn)
        eid = uuid.uuid4()
        await conn.execute(
            text(
                "INSERT INTO entities (id, user_id, kind, canonical_name) "
                "VALUES (:eid, :uid, 'person', 'Thomas Müller')"
            ),
            {"eid": eid, "uid": uid},
        )
        with pytest.raises(DBAPIError):
            await conn.execute(
                text(
                    "INSERT INTO entity_relations (from_entity_id, to_entity_id, relation) "
                    "VALUES (:eid, :eid, 'kennt')"
                ),
                {"eid": eid},
            )

    async def test_aliassuche_nutzt_den_gin_index(self, conn: AsyncConnection) -> None:
        """Namensauflösung über Aliase — die Grundlage von 'schreib ihm'."""
        uid = await _user(conn)
        await conn.execute(
            text(
                "INSERT INTO entities (user_id, kind, canonical_name, aliases, gender) "
                "VALUES (:uid, 'person', 'Thomas Müller', "
                "ARRAY['Thomas','Herr Müller'], 'm')"
            ),
            {"uid": uid},
        )
        hit = await conn.execute(
            text("SELECT canonical_name FROM entities WHERE :alias = ANY(aliases)"),
            {"alias": "Thomas"},
        )
        assert hit.scalar_one() == "Thomas Müller"

    async def test_entitaetsverknuepfung_loest_die_beispielanfrage(
        self, conn: AsyncConnection
    ) -> None:
        """„Was habe ich letzte Woche mit Thomas besprochen?" — ein Join mit
        Zeitfilter, kein Ähnlichkeitsproblem (Beschluss gegen Graph-RAG)."""
        uid = await _user(conn)
        eid, mid = uuid.uuid4(), uuid.uuid4()
        await conn.execute(
            text(
                "INSERT INTO entities (id, user_id, kind, canonical_name) "
                "VALUES (:eid, :uid, 'person', 'Thomas Müller')"
            ),
            {"eid": eid, "uid": uid},
        )
        await conn.execute(
            text(
                "INSERT INTO memories (id, user_id, kind, content, source_type, status) "
                "VALUES (:mid, :uid, 'episodic', 'Angebot Projekt X besprochen.', "
                "'user_stated', 'active')"
            ),
            {"mid": mid, "uid": uid},
        )
        await conn.execute(
            text(
                "INSERT INTO entity_links (entity_id, target_kind, target_id, role) "
                "VALUES (:eid, 'memory', :mid, 'Teilnehmer')"
            ),
            {"eid": eid, "mid": mid},
        )

        rows = await conn.execute(
            text(
                "SELECT m.content FROM memories m "
                "JOIN entity_links l ON l.target_id = m.id AND l.target_kind = 'memory' "
                "JOIN entities e ON e.id = l.entity_id "
                "WHERE e.canonical_name = 'Thomas Müller' "
                "  AND m.valid_from > now() - interval '7 days'"
            )
        )
        assert rows.scalar_one() == "Angebot Projekt X besprochen."


class TestLoeschungBleibtVollstaendig:
    async def test_neue_tabellen_werden_mitgeloescht(self, conn: AsyncConnection) -> None:
        """Die V1.1-Schicht darf die Löschzusicherung aus Doc 03 §10 nicht
        aufweichen."""
        uid = await _user(conn)
        gid, eid = uuid.uuid4(), uuid.uuid4()

        await conn.execute(
            text("INSERT INTO goals (id, user_id, title) VALUES (:gid, :uid, 'Ziel')"),
            {"gid": gid, "uid": uid},
        )
        await conn.execute(
            text(
                "INSERT INTO entities (id, user_id, kind, canonical_name) "
                "VALUES (:eid, :uid, 'person', 'Thomas')"
            ),
            {"eid": eid, "uid": uid},
        )
        await conn.execute(
            text(
                "INSERT INTO entity_links (entity_id, target_kind, target_id) "
                "VALUES (:eid, 'goal', :gid)"
            ),
            {"eid": eid, "gid": gid},
        )
        await conn.execute(
            text(
                "INSERT INTO behaviour_rules (user_id, kind, rule, source_type) "
                "VALUES (:uid, 'do', 'Antworte knapp.', 'user_stated')"
            ),
            {"uid": uid},
        )
        await conn.execute(
            text(
                "INSERT INTO domain_preferences (user_id, domain, key, value, source_type) "
                "VALUES (:uid, 'mail', 'signature', '\"Viele Grüße\"'::jsonb, 'user_stated')"
            ),
            {"uid": uid},
        )

        await conn.execute(text("DELETE FROM users WHERE id = :uid"), {"uid": uid})

        for table, column, value in [
            ("goals", "user_id", uid),
            ("entities", "user_id", uid),
            ("entity_links", "entity_id", eid),
            ("behaviour_rules", "user_id", uid),
            ("domain_preferences", "user_id", uid),
        ]:
            left = await conn.execute(
                text(f"SELECT count(*) FROM {table} WHERE {column} = :v"), {"v": value}
            )
            assert left.scalar_one() == 0, f"{table} nicht mitgelöscht"
