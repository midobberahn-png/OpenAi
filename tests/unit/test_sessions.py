"""Sitzungen — die Zusicherung hinter ``session_id``.

Bis zu diesem Paket war die Sitzungsbindung einer Bestätigung ein Vergleich
zweier UUIDs. Diese Suite prüft, was jetzt dahintersteht: Fristen, Widerruf,
und dass aus dem Gespeicherten kein Zugang zu gewinnen ist.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from jarvis_contracts import IssuedSession, Session
from jarvis_core.auth import SessionManager, token_fingerprint

pytestmark = pytest.mark.security

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
USER = UUID("11111111-1111-1111-1111-111111111111")
FREMDER = UUID("99999999-9999-9999-9999-999999999999")


class InMemorySessions:
    """Bildet den Speicher nach — bewusst ohne Gültigkeitsfilter.

    Der Port schreibt das vor: Ob eine gefundene Sitzung noch gilt, entscheidet
    der Manager. Ein Speicher, der selbst filtert, wäre die zweite Meinung
    darüber — und die eine davon vergisst irgendwann den Widerruf.
    """

    def __init__(self) -> None:
        self.rows: dict[str, Session] = {}

    async def create(self, session: Session, token_hash: str) -> None:
        self.rows[token_hash] = session

    async def by_token_hash(self, token_hash: str) -> Session | None:
        return self.rows.get(token_hash)

    async def touch(self, session_id: UUID, now: datetime) -> None:
        for key, session in self.rows.items():
            if session.id == session_id:
                self.rows[key] = session.model_copy(update={"last_seen_at": now})

    async def revoke(self, session_id: UUID, now: datetime) -> None:
        for key, session in self.rows.items():
            if session.id == session_id:
                self.rows[key] = session.model_copy(update={"revoked_at": now})

    async def revoke_all_for_user(self, user_id: UUID, now: datetime) -> int:
        count = 0
        for key, session in list(self.rows.items()):
            if session.user_id == user_id and session.revoked_at is None:
                self.rows[key] = session.model_copy(update={"revoked_at": now})
                count += 1
        return count

    async def active_for_user(self, user_id: UUID, now: datetime) -> list[Session]:
        return [s for s in self.rows.values() if s.user_id == user_id and s.revoked_at is None]


def _manager(store: InMemorySessions | None = None, **kw: object) -> SessionManager:
    return SessionManager(store or InMemorySessions(), **kw)  # type: ignore[arg-type]


class TestAusgabe:
    async def test_sitzung_gilt_unmittelbar_nach_der_ausgabe(self) -> None:
        store = InMemorySessions()
        manager = _manager(store)
        issued = await manager.issue(USER, client="MacBook, Safari", now=NOW)

        verified = await manager.verify(issued.token, now=NOW + timedelta(minutes=1))
        assert verified is not None
        assert verified.user_id == USER

    async def test_in_der_datenbank_liegt_kein_token(self) -> None:
        """Die eigentliche Zusicherung: Wer die Tabelle liest — über ein
        Backup, eine fehlgeleitete Abfrage —, findet nichts, womit er sich
        anmelden könnte."""
        store = InMemorySessions()
        issued = await _manager(store).issue(USER, now=NOW)

        assert issued.token not in store.rows
        assert list(store.rows) == [token_fingerprint(issued.token)]
        gespeichert = str(next(iter(store.rows.values())).model_dump())
        assert issued.token not in gespeichert

    def test_token_erscheint_nicht_in_der_darstellung(self) -> None:
        """Kein Sicherheitsmechanismus, sondern die Beseitigung eines
        häufigen Unfalls: Tokens in Tracebacks und Logs."""
        issued = IssuedSession(
            session=Session(
                id=uuid4(),
                user_id=USER,
                created_at=NOW,
                last_seen_at=NOW,
                expires_at=NOW + timedelta(days=1),
            ),
            token="t" * 40,
        )
        assert "tttt" not in repr(issued)
        assert "tttt" not in str(issued)

    async def test_zwei_sitzungen_haben_verschiedene_token(self) -> None:
        manager = _manager()
        a = await manager.issue(USER, now=NOW)
        b = await manager.issue(USER, now=NOW)
        assert a.token != b.token
        assert a.session.id != b.session.id


class TestFristen:
    async def test_abgelaufene_sitzung_gilt_nicht(self) -> None:
        manager = _manager(ttl=timedelta(days=14))
        issued = await manager.issue(USER, now=NOW)
        assert await manager.verify(issued.token, now=NOW + timedelta(days=14, seconds=1)) is None

    async def test_leerlauf_beendet_die_sitzung(self) -> None:
        """Ein Gerät, das einen halben Tag schweigt, meldet sich neu an."""
        manager = _manager(idle_timeout=timedelta(hours=12))
        issued = await manager.issue(USER, now=NOW)
        assert await manager.verify(issued.token, now=NOW + timedelta(hours=13)) is None

    async def test_nutzung_verschiebt_den_leerlauf_aber_nicht_die_frist(self) -> None:
        """Der Kern der Doppelfrist: Wer eine gestohlene Sitzung aktiv hält,
        hält sie nicht unbegrenzt am Leben."""
        store = InMemorySessions()
        manager = _manager(store, ttl=timedelta(days=2), idle_timeout=timedelta(hours=12))
        issued = await manager.issue(USER, now=NOW)

        # Alle acht Stunden benutzt — der Leerlauf greift nie …
        moment = NOW
        for _ in range(5):
            moment += timedelta(hours=8)
            assert await manager.verify(issued.token, now=moment) is not None

        # … die absolute Frist trotzdem.
        assert await manager.verify(issued.token, now=NOW + timedelta(days=2, minutes=1)) is None

    async def test_letzter_zugriff_wird_fortgeschrieben(self) -> None:
        store = InMemorySessions()
        manager = _manager(store)
        issued = await manager.issue(USER, now=NOW)

        später = NOW + timedelta(hours=3)
        verified = await manager.verify(issued.token, now=später)
        assert verified is not None
        assert verified.last_seen_at == später
        assert store.rows[token_fingerprint(issued.token)].last_seen_at == später


class TestWiderruf:
    async def test_widerruf_wirkt_sofort(self) -> None:
        store = InMemorySessions()
        manager = _manager(store)
        issued = await manager.issue(USER, now=NOW)

        await manager.revoke(issued.session.id, now=NOW + timedelta(minutes=1))
        assert await manager.verify(issued.token, now=NOW + timedelta(minutes=2)) is None

    async def test_alle_sitzungen_beenden(self) -> None:
        """Der Knopf für den Verlustfall — bedienbar ohne Kenntnis einzelner
        Sitzungen, weil wer sein Telefon sucht, keine Sitzungs-IDs kennt."""
        manager = _manager()
        tokens = [(await manager.issue(USER, now=NOW)).token for _ in range(3)]
        fremd = await manager.issue(FREMDER, now=NOW)

        beendet = await manager.revoke_all(USER, now=NOW + timedelta(minutes=1))
        assert beendet == 3
        for token in tokens:
            assert await manager.verify(token, now=NOW + timedelta(minutes=2)) is None
        assert await manager.verify(fremd.token, now=NOW + timedelta(minutes=2)) is not None


class TestBindung:
    @pytest.mark.invariant("approval-channel-bound")
    async def test_fremde_sitzung_desselben_nutzers_passt_nicht(self) -> None:
        """Die Frage, die das Approval Gateway stellen muss, ist enger als
        „ist der Token gültig“: Eine zweite, ebenfalls gültige Sitzung desselben
        Nutzers darf eine Bestätigung nicht einlösen, die woanders angezeigt
        wurde."""
        manager = _manager()
        erste = await manager.issue(USER, now=NOW)
        zweite = await manager.issue(USER, now=NOW)

        assert await manager.belongs_to(
            erste.token, user_id=USER, session_id=erste.session.id, now=NOW
        )
        assert not await manager.belongs_to(
            zweite.token, user_id=USER, session_id=erste.session.id, now=NOW
        )

    @pytest.mark.invariant("approval-channel-bound")
    async def test_fremder_nutzer_passt_nicht(self) -> None:
        manager = _manager()
        issued = await manager.issue(USER, now=NOW)
        assert not await manager.belongs_to(
            issued.token, user_id=FREMDER, session_id=issued.session.id, now=NOW
        )

    async def test_widerrufene_sitzung_bindet_nichts_mehr(self) -> None:
        manager = _manager()
        issued = await manager.issue(USER, now=NOW)
        await manager.revoke(issued.session.id, now=NOW)
        assert not await manager.belongs_to(
            issued.token, user_id=USER, session_id=issued.session.id, now=NOW
        )


class TestUnbekannteToken:
    async def test_erfundener_token_wird_abgewiesen(self) -> None:
        assert await _manager().verify("x" * 43, now=NOW) is None

    async def test_alle_fehlerfaelle_sehen_gleich_aus(self) -> None:
        """Nach außen keine Unterscheidung: Ob ein Token unbekannt, abgelaufen
        oder widerrufen ist, wäre für einen Angreifer ein Aufzählungsorakel."""
        manager = _manager(ttl=timedelta(hours=1))
        abgelaufen = await manager.issue(USER, now=NOW)
        widerrufen = await manager.issue(USER, now=NOW)
        await manager.revoke(widerrufen.session.id, now=NOW)

        später = NOW + timedelta(hours=2)
        assert await manager.verify(abgelaufen.token, now=später) is None
        assert await manager.verify(widerrufen.token, now=NOW) is None
        assert await manager.verify("unbekannt" * 5, now=NOW) is None


class TestFingerabdruck:
    def test_gleicher_token_gleicher_abdruck(self) -> None:
        assert token_fingerprint("abc") == token_fingerprint("abc")

    def test_verschiedene_token_verschiedene_abdruecke(self) -> None:
        assert token_fingerprint("abc") != token_fingerprint("abd")

    def test_abdruck_ist_nicht_umkehrbar_lesbar(self) -> None:
        abdruck = token_fingerprint("geheim")
        assert "geheim" not in abdruck
        assert len(abdruck) == 64
