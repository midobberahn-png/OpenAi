"""Sitzungen — die Zusicherung hinter ``session_id``.

Bis zu diesem Paket war die Sitzungsbindung einer Bestätigung ein Vergleich
zweier UUIDs. Diese Suite prüft, was jetzt dahintersteht: Fristen, Widerruf,
und dass aus dem Gespeicherten kein Zugang zu gewinnen ist.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from jarvis_contracts import IssuedSession, Session
from jarvis_core.auth import SessionManager, SessionRejection, token_fingerprint
from jarvis_core.ports.sessions import SessionLookup

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
        self.vorgaenger: dict[str, UUID] = {}
        """Ersetzte Hashes → Sitzung. Die Spalte ``prev_token_hash``, nachgebaut."""

        self.rotated: dict[UUID, datetime] = {}
        """Wann zuletzt rotiert wurde — die Grundlage des Überlappungsfensters."""

        self.uhr = NOW
        """Was die Datenbank als ``now()`` einsetzen würde. Der Test stellt sie,
        weil ein Fenster von 60 Sekunden sonst nicht prüfbar wäre."""

    async def create(self, session: Session, token_hash: str) -> None:
        self.rows[token_hash] = session

    async def by_token_hash(self, token_hash: str) -> Session | None:
        return self.rows.get(token_hash)

    async def lookup(self, token_hash: str) -> SessionLookup | None:
        """Bildet ``_LOOKUP`` nach: aktueller **oder** voriger Hash.

        Die Attrappe führt den Vorgänger genauso wie die Tabelle — sonst
        prüften die Tests eine Rotation, die es in der Datenbank nicht gibt.
        """
        if (session := self.rows.get(token_hash)) is not None:
            return self._befund(session, ist_vorgaenger=False)
        for vorher, sid in self.vorgaenger.items():
            if vorher == token_hash:
                for kandidat in self.rows.values():
                    if kandidat.id == sid:
                        return self._befund(kandidat, ist_vorgaenger=True)
        return None

    def _befund(self, session: Session, *, ist_vorgaenger: bool) -> SessionLookup:
        """Bildet die **Alter** nach, die die Abfrage rechnet.

        Nicht die Zeitstempel: Der echte Speicher gibt ``now() - rotated_at``
        zurück, weil beide Seiten der Frist auf derselben Uhr stehen müssen.
        Eine Attrappe, die stattdessen Zeitpunkte liefert, prüfte eine andere
        Bauart als die, die im Betrieb läuft — und genau diese Abweichung hat
        ein Integrationstest schon einmal aufgedeckt.
        """
        rotiert = self.rotated.get(session.id)
        return SessionLookup(
            session=session,
            ist_vorgaenger=ist_vorgaenger,
            token_alter=self.uhr - (rotiert if rotiert is not None else session.created_at),
            rotation_alter=None if rotiert is None else self.uhr - rotiert,
        )

    async def rotate(self, session_id: UUID, *, alt_hash: str, neu_hash: str) -> bool:
        """Vergleiche-und-setze — der Kern des Wettlaufs.

        Trifft nur, solange ``alt_hash`` noch der **aktuelle** ist. Genau das
        macht den zweiten gleichzeitigen Aufruf wirkungslos, ohne ihn
        abzumelden.
        """
        session = self.rows.get(alt_hash)
        if session is None or session.id != session_id:
            return False
        del self.rows[alt_hash]
        self.rows[neu_hash] = session
        self.vorgaenger[alt_hash] = session_id
        self.rotated[session_id] = self.uhr
        return True

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


class TestDerGrundEinerAblehnung:
    """Vier Wege zu einem 401 — und bis zu diesem Block waren sie ununterscheidbar.

    Der Docstring von ``verify()`` sagt seit jeher, die Fälle seien „nach innen
    unterscheidbar, weil das Audit sie braucht". Innen unterschied sie
    niemand: Alle vier endeten in demselben ``None``.

    Aufgefallen beim Nachgehen eines Testflackerns. Die Anmeldung gelang
    vollständig — ``login/finish`` mit 200 —, und der unmittelbar folgende
    ``/auth/me`` antwortete 401. Ob das Cookie nicht ankam oder die Sitzung
    beim Lesen noch nicht sichtbar war, verlangt entgegengesetzte
    Untersuchungen und sah identisch aus.
    """

    async def test_ohne_token_heisst_es_so(self) -> None:
        """Der wichtigste der vier: Er unterscheidet ein Browserproblem von
        einem Datenbankproblem."""
        assert (await _manager().pruefen("", now=NOW)).grund is SessionRejection.KEIN_TOKEN

    async def test_ein_unbekannter_token_heisst_unbekannt(self) -> None:
        assert (await _manager().pruefen("x" * 40, now=NOW)).grund is SessionRejection.UNBEKANNT

    async def test_eine_widerrufene_sitzung_heisst_widerrufen(self) -> None:
        store = InMemorySessions()
        manager = _manager(store)
        issued = await manager.issue(USER, now=NOW)
        await manager.revoke(issued.session.id, now=NOW)

        geprueft = await manager.pruefen(issued.token, now=NOW + timedelta(minutes=1))

        assert geprueft.grund is SessionRejection.WIDERRUFEN

    async def test_eine_abgelaufene_sitzung_heisst_abgelaufen(self) -> None:
        manager = _manager(ttl=timedelta(days=14))
        issued = await manager.issue(USER, now=NOW)

        geprueft = await manager.pruefen(issued.token, now=NOW + timedelta(days=14, seconds=1))

        assert geprueft.grund is SessionRejection.ABGELAUFEN

    async def test_leerlauf_heisst_leerlauf(self) -> None:
        manager = _manager(idle_timeout=timedelta(hours=12))
        issued = await manager.issue(USER, now=NOW)

        geprueft = await manager.pruefen(issued.token, now=NOW + timedelta(hours=13))

        assert geprueft.grund is SessionRejection.LEERLAUF

    async def test_eine_gueltige_sitzung_traegt_keinen_grund(self) -> None:
        """Genau eines von beidem ist gesetzt. Ein Grund neben einer gültigen
        Sitzung wäre eine Aussage, die niemand einlösen kann."""
        manager = _manager()
        issued = await manager.issue(USER, now=NOW)

        geprueft = await manager.pruefen(issued.token, now=NOW + timedelta(minutes=1))

        assert geprueft.session is not None
        assert geprueft.grund is None

    async def test_verify_antwortet_weiterhin_genau_wie_vorher(self) -> None:
        """Die Wache gegen ein Aufzählungsorakel.

        ``verify()`` bleibt die Auskunft nach außen und sagt nach wie vor nur
        ja oder nein. Wer den Grund will, fragt ausdrücklich danach — und die
        HTTP-Schicht legt ihn ins Protokoll, nicht in die Antwort.
        """
        manager = _manager(ttl=timedelta(days=14))
        issued = await manager.issue(USER, now=NOW)

        assert await manager.verify("", now=NOW) is None
        assert await manager.verify("x" * 40, now=NOW) is None
        assert await manager.verify(issued.token, now=NOW + timedelta(days=15)) is None
        assert await manager.verify(issued.token, now=NOW) is not None

    async def test_der_grund_stimmt_mit_der_pruefung_daneben_ueberein(self) -> None:
        """**Zwei Wahrheiten über dieselbe Frage wären der eigentliche Fehler.**

        ``pruefen()`` bildet die Reihenfolge von ``is_valid_at`` nach. Liefe
        sie auseinander, meldete das Protokoll einen Grund, den die Prüfung
        nicht anwendet — und die nächste Untersuchung liefe in die falsche
        Richtung.
        """
        manager = _manager(ttl=timedelta(days=14), idle_timeout=timedelta(hours=12))
        issued = await manager.issue(USER, now=NOW)

        for versatz in (timedelta(hours=13), timedelta(days=15)):
            moment = NOW + versatz
            geprueft = await manager.pruefen(issued.token, now=moment)
            gilt = issued.session.is_valid_at(moment, idle_timeout=timedelta(hours=12))

            assert (geprueft.grund is None) is gilt


class TestRotation:
    """Der Schutz, der bisher fehlte — und der Wettlauf, der ihn aufgehalten hat.

    ADR-020. Die Invariante ``session-token-rotation`` stand seit dem ersten
    Entwurf auf `PLANNED`, mit genau einer Begründung: **Zwei gleichzeitige
    Anfragen mit demselben Token dürfen nicht dazu führen, dass eine davon
    abgemeldet wird.** Rotation ohne Sorgfalt ist schlechter als keine — wer
    zufällig abgemeldet wird, baut sich einen Weg daran vorbei.
    """

    @pytest.mark.invariant("session-token-rotation")
    async def test_ein_benutzter_token_wird_ersetzt(self) -> None:
        store = InMemorySessions()
        manager = _manager(store, rotation_interval=timedelta(minutes=15))
        issued = await manager.issue(USER, now=NOW)

        store.uhr = NOW + timedelta(minutes=20)
        geprueft = await manager.pruefen(issued.token, now=store.uhr, rotieren=True)

        assert geprueft.session is not None
        assert geprueft.neuer_token is not None
        assert geprueft.neuer_token != issued.token

    @pytest.mark.invariant("session-token-rotation")
    async def test_der_alte_token_ist_danach_wertlos(self) -> None:
        """Der ganze Zweck: Eine Kopie verliert ihren Wert, sobald der
        rechtmäßige Nutzer arbeitet."""
        store = InMemorySessions()
        manager = _manager(
            store, rotation_interval=timedelta(minutes=15), overlap=timedelta(seconds=60)
        )
        issued = await manager.issue(USER, now=NOW)
        store.uhr = NOW + timedelta(minutes=20)
        await manager.pruefen(issued.token, now=store.uhr, rotieren=True)

        # Weit nach dem Fenster — der Dieb meldet sich. Gestellt wird die Uhr
        # des **Speichers**: Das Überlappungsfenster rechnet gegen ein Alter
        # aus der Datenbank, und die Prozessuhr erreicht es nicht.
        store.uhr += timedelta(minutes=5)
        geprueft = await manager.pruefen(issued.token, now=store.uhr)

        assert geprueft.session is None

    async def test_vor_dem_takt_wird_nicht_rotiert(self) -> None:
        """Nicht bei jedem Aufruf: Sonst wäre jeder der drei Takte dieser
        Oberfläche ein Wettlauf."""
        store = InMemorySessions()
        manager = _manager(store, rotation_interval=timedelta(minutes=15))
        issued = await manager.issue(USER, now=NOW)

        geprueft = await manager.pruefen(
            issued.token, now=NOW + timedelta(minutes=5), rotieren=True
        )

        assert geprueft.session is not None
        assert geprueft.neuer_token is None

    async def test_ohne_ausdrueckliches_rotieren_geschieht_nichts(self) -> None:
        """Wer keinen Ersatz zurückgeben kann, darf keinen erzeugen — sonst
        hat die Datenbank einen neuen Token und der Client den alten."""
        store = InMemorySessions()
        manager = _manager(store, rotation_interval=timedelta(minutes=15))
        issued = await manager.issue(USER, now=NOW)

        store.uhr = NOW + timedelta(minutes=20)
        geprueft = await manager.pruefen(issued.token, now=store.uhr)

        assert geprueft.neuer_token is None
        assert (await manager.verify(issued.token, now=store.uhr)) is not None


class TestDerWettlauf:
    """**Der Grund, warum diese Invariante zwei Monate lag.**"""

    @pytest.mark.invariant("session-token-rotation")
    async def test_zwei_gleichzeitige_anfragen_melden_niemanden_ab(self) -> None:
        """Beide Anfragen tragen denselben Token. Genau eine rotiert; die
        andere arbeitet weiter — und zwar **erfolgreich**."""
        store = InMemorySessions()
        manager = _manager(
            store, rotation_interval=timedelta(minutes=15), overlap=timedelta(seconds=60)
        )
        issued = await manager.issue(USER, now=NOW)
        store.uhr = NOW + timedelta(minutes=20)

        erste, zweite = await asyncio.gather(
            manager.pruefen(issued.token, now=store.uhr, rotieren=True),
            manager.pruefen(issued.token, now=store.uhr, rotieren=True),
        )

        assert erste.session is not None, "Die erste Anfrage wurde abgemeldet."
        assert zweite.session is not None, "Die zweite Anfrage wurde abgemeldet."
        ersatzstuecke = [g.neuer_token for g in (erste, zweite) if g.neuer_token is not None]
        assert len(ersatzstuecke) == 1, (
            f"Genau einer darf rotieren, es waren {len(ersatzstuecke)}. Zwei Ersatztoken "
            "hießen: Der zweite überschreibt den ersten, und dessen Empfänger fliegt raus."
        )

    async def test_der_verlierer_arbeitet_im_fenster_weiter(self) -> None:
        """Die Anfrage, die zum Zeitpunkt der Rotation schon unterwegs war."""
        store = InMemorySessions()
        manager = _manager(
            store, rotation_interval=timedelta(minutes=15), overlap=timedelta(seconds=60)
        )
        issued = await manager.issue(USER, now=NOW)
        store.uhr = NOW + timedelta(minutes=20)
        await manager.pruefen(issued.token, now=store.uhr, rotieren=True)

        # 30 Sekunden später, noch im Fenster, mit dem alten Token:
        geprueft = await manager.pruefen(issued.token, now=store.uhr + timedelta(seconds=30))

        assert geprueft.session is not None
        assert geprueft.grund is None

    @pytest.mark.invariant("session-token-rotation")
    async def test_nach_dem_fenster_endet_die_sitzung(self) -> None:
        """Wiederverwendungserkennung: Wer eine Kopie benutzt, soll damit nicht
        weiterkommen, sondern auffallen.

        Und die schärfere Zusage steht in der zweiten Zusicherung: Danach gilt
        auch der **neue** Token nicht mehr — die Sitzung ist beendet, nicht nur
        der eine Aufruf abgelehnt.
        """
        store = InMemorySessions()
        manager = _manager(
            store, rotation_interval=timedelta(minutes=15), overlap=timedelta(seconds=60)
        )
        issued = await manager.issue(USER, now=NOW)
        store.uhr = NOW + timedelta(minutes=20)
        gedreht = await manager.pruefen(issued.token, now=store.uhr, rotieren=True)
        assert gedreht.neuer_token is not None

        store.uhr += timedelta(seconds=61)
        geprueft = await manager.pruefen(issued.token, now=store.uhr)

        assert geprueft.grund is SessionRejection.WIEDERVERWENDET
        assert await manager.verify(gedreht.neuer_token, now=store.uhr) is None, (
            "Nach einer erkannten Kopie muss die ganze Sitzung enden — sonst arbeitet "
            "der Dieb mit dem neuen Token weiter, falls er auch den hat."
        )

    async def test_ein_vorgaenger_ohne_zeitpunkt_gilt_nicht(self) -> None:
        """Die strengere Antwort auf einen Datensatz, den niemand erklären kann."""
        store = InMemorySessions()
        manager = _manager(store, overlap=timedelta(seconds=60))
        issued = await manager.issue(USER, now=NOW)
        store.uhr = NOW + timedelta(minutes=20)
        await manager.pruefen(issued.token, now=store.uhr, rotieren=True)
        store.rotated.clear()

        geprueft = await manager.pruefen(issued.token, now=store.uhr)

        assert geprueft.grund is SessionRejection.WIEDERVERWENDET
