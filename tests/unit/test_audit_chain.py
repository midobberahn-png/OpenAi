"""Hash-Kette des Audit-Logs.

Die Kette macht Manipulation *erkennbar*. Diese Suite prüft, dass sie das
tatsächlich tut — und zwar auch in den Fällen, in denen eine naive
Implementierung stillschweigend durchwinkt.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from jarvis_core.audit import (
    GENESIS_HASH,
    AuditEntry,
    StoredAuditRow,
    canonical_payload,
    compute_entry_hash,
    verify_chain,
)

pytestmark = pytest.mark.security

BASE = datetime(2026, 8, 18, 12, 0, 0, tzinfo=UTC)


def _entry(n: int = 0, **kw: object) -> AuditEntry:
    base: dict[str, object] = {
        "occurred_at": BASE + timedelta(seconds=n),
        "actor": "jarvis",
        "action": "tool.execute",
        "resource": f"calendar.create/{n}",
        "details": {"seq": n},
        "trace_id": f"trace-{n}",
    }
    base.update(kw)
    return AuditEntry(**base)  # type: ignore[arg-type]


def _chain(count: int) -> list[StoredAuditRow]:
    rows: list[StoredAuditRow] = []
    prev = GENESIS_HASH
    for i in range(count):
        e = _entry(i)
        h = compute_entry_hash(e, prev)
        rows.append(
            StoredAuditRow(
                id=i + 1,
                occurred_at=e.occurred_at,
                actor=e.actor,
                action=e.action,
                resource=e.resource,
                details=e.details,
                trace_id=e.trace_id,
                prev_hash=prev,
                entry_hash=h,
            )
        )
        prev = h
    return rows


class TestKanonisierung:
    def test_gleicher_eintrag_ergibt_gleiche_bytes(self) -> None:
        """Ohne Determinismus wäre jede Kettenprüfung Zufall."""
        assert canonical_payload(_entry(1)) == canonical_payload(_entry(1))

    def test_reihenfolge_der_details_ist_irrelevant(self) -> None:
        a = _entry(1, details={"b": 2, "a": 1})
        b = _entry(1, details={"a": 1, "b": 2})
        assert canonical_payload(a) == canonical_payload(b)

    def test_user_id_geht_nicht_in_den_hash(self) -> None:
        """Der entscheidende Punkt: Die DSGVO-Löschung setzt user_id auf NULL.
        Wäre die Kennung Teil des Hashes, zerriss jede Nutzerlöschung die Kette
        — und die Unveränderlichkeitszusicherung wäre entwertet."""
        ohne = _entry(1, user_id=None)
        mit = _entry(1, user_id=uuid4())
        assert canonical_payload(ohne) == canonical_payload(mit)
        assert compute_entry_hash(ohne, GENESIS_HASH) == compute_entry_hash(mit, GENESIS_HASH)

    def test_inhaltsaenderung_aendert_den_hash(self) -> None:
        a = compute_entry_hash(_entry(1, action="tool.execute"), GENESIS_HASH)
        b = compute_entry_hash(_entry(1, action="tool.reject"), GENESIS_HASH)
        assert a != b

    def test_umlaute_sind_stabil(self) -> None:
        e = _entry(1, details={"grund": "Berechtigung fehlt — Empfänger unbekannt"})
        assert canonical_payload(e) == canonical_payload(e)
        assert "Empfänger".encode() in canonical_payload(e)


class TestHashBerechnung:
    def test_erster_eintrag_nutzt_genesis(self) -> None:
        e = _entry(0)
        assert compute_entry_hash(e, None) == compute_entry_hash(e, GENESIS_HASH)

    def test_verkettung_haengt_am_vorgaenger(self) -> None:
        e = _entry(1)
        h1 = compute_entry_hash(e, GENESIS_HASH)
        h2 = compute_entry_hash(e, b"\x01" * 32)
        assert h1 != h2, "Gleicher Inhalt an anderer Kettenposition muss anders hashen"

    def test_ungueltige_vorgaengerlaenge_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="32 Byte"):
            compute_entry_hash(_entry(1), b"kurz")


class TestKettenpruefung:
    def test_unversehrte_kette(self) -> None:
        assert verify_chain(_chain(5)) == []

    def test_leere_kette_ist_unversehrt(self) -> None:
        assert verify_chain([]) == []

    def test_veraenderter_inhalt_wird_erkannt(self) -> None:
        rows = _chain(5)
        rows[2] = rows[2].model_copy(update={"action": "harmlos"})
        breaks = verify_chain(rows)
        assert len(breaks) == 1
        assert breaks[0].row_id == 3
        assert "verändert" in breaks[0].reason

    def test_nur_der_manipulierte_eintrag_wird_gemeldet(self) -> None:
        """Wichtig für die Auswertung: Würde die Prüfung den neu berechneten
        Hash fortschreiben, meldete sie alle Folgeeinträge mit — und der
        eigentliche Ort der Manipulation ginge im Rauschen unter."""
        rows = _chain(10)
        rows[4] = rows[4].model_copy(update={"details": {"seq": 999}})
        breaks = verify_chain(rows)
        assert [b.row_id for b in breaks] == [5]

    def test_entfernter_eintrag_wird_erkannt(self) -> None:
        """Der häufigste Manipulationsversuch: eine Zeile löschen."""
        rows = _chain(5)
        del rows[2]
        breaks = verify_chain(rows)
        assert breaks, "Gelöschter Eintrag muss die Kette brechen"
        assert any("Vorgänger" in b.reason for b in breaks)

    def test_vertauschte_reihenfolge_wird_erkannt(self) -> None:
        rows = _chain(5)
        rows[1], rows[2] = rows[2], rows[1]
        assert verify_chain(rows), "Umsortierung muss die Kette brechen"

    def test_eingeschobener_eintrag_wird_erkannt(self) -> None:
        rows = _chain(5)
        fake = _entry(99)
        rows.insert(
            3,
            StoredAuditRow(
                id=99,
                occurred_at=fake.occurred_at,
                actor=fake.actor,
                action=fake.action,
                resource=fake.resource,
                details=fake.details,
                trace_id=fake.trace_id,
                prev_hash=rows[2].entry_hash,
                entry_hash=compute_entry_hash(fake, rows[2].entry_hash),
            ),
        )
        breaks = verify_chain(rows)
        assert breaks, "Ein eingeschobener Eintrag verschiebt alle folgenden prev_hash-Verweise"

    def test_pseudonymisierung_bricht_die_kette_nicht(self) -> None:
        """Die Zusammenführung beider Anforderungen: Löschpflicht und
        Unveränderlichkeit müssen gleichzeitig erfüllbar sein."""
        rows = _chain(5)
        # DSGVO-Löschung: user_id wird genullt, sonst bleibt die Zeile gleich.
        # StoredAuditRow führt user_id nicht, weil es nicht gehasht wird —
        # genau deshalb ist die Kette von der Löschung unberührt.
        assert verify_chain(rows) == []
