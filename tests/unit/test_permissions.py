"""Berechtigungen, Risikoordnung und Einschränkungen.

Ein Fehler in dieser Schicht bedeutet eine falsch gesendete E-Mail oder einen
gelöschten Termin. Entsprechend dicht sind die Tests.
"""

from __future__ import annotations

from datetime import UTC, datetime, time, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from jarvis_contracts import (
    ActionPreview,
    ApprovalChannel,
    FilesConstraints,
    MailSendConstraints,
    PendingAction,
    PolicyDecision,
    PolicyEffect,
    RiskLevel,
    TimeWindow,
)


class TestRiskLevel:
    def test_ordnung_ist_nicht_lexikografisch(self) -> None:
        """Die naive String-Ordnung wäre falsch: 'critical' < 'high' < 'low'."""
        assert RiskLevel.LOW < RiskLevel.MEDIUM < RiskLevel.HIGH < RiskLevel.CRITICAL
        assert sorted(RiskLevel, key=lambda r: r.level)[-1] is RiskLevel.CRITICAL

    def test_bestaetigungspflicht(self) -> None:
        assert not RiskLevel.LOW.needs_confirmation
        assert not RiskLevel.MEDIUM.needs_confirmation
        assert RiskLevel.HIGH.needs_confirmation
        assert RiskLevel.CRITICAL.needs_confirmation

    @pytest.mark.invariant("approval-critical-ui-only")
    def test_critical_nur_in_der_ui(self) -> None:
        assert RiskLevel.CRITICAL.ui_only_confirmation
        assert not RiskLevel.HIGH.ui_only_confirmation

    def test_vergleich_mit_string_faellt_nicht_still_auf_str_zurueck(self) -> None:
        """Regressionstest.

        RiskLevel erbt von str. Gäbe __lt__ bei Fremdtypen NotImplemented
        zurück, verglich Python lexikografisch — und 'critical' < 'high' ist
        als String wahr, semantisch aber das Gegenteil. Ein solcher Vergleich
        muss laut scheitern, nicht leise falsch sein.
        """
        with pytest.raises(TypeError, match="semantisch falsch"):
            _ = RiskLevel.CRITICAL < "high"  # type: ignore[operator]
        with pytest.raises(TypeError):
            _ = RiskLevel.LOW >= "medium"  # type: ignore[operator]


class TestMailSendConstraints:
    def test_leere_allowlist_erlaubt_alle(self) -> None:
        c = MailSendConstraints()
        assert c.check({"to": ["fremd@example.com"]}) is None

    def test_allowlist_blockiert_unbekannte_empfaenger(self) -> None:
        c = MailSendConstraints(recipients_allowlist=["team@firma.de"])
        assert c.check({"to": ["team@firma.de"]}) is None

        v = c.check({"to": ["angreifer@example.com"]})
        assert v is not None
        assert "angreifer@example.com" in v.message

    def test_allowlist_prueft_auch_cc_und_bcc(self) -> None:
        """Ein Angreifer würde genau hier ansetzen: Empfänger in cc statt to."""
        c = MailSendConstraints(recipients_allowlist=["team@firma.de"])
        v = c.check({"to": ["team@firma.de"], "cc": ["exfil@example.com"]})
        assert v is not None
        assert "exfil@example.com" in v.message

        v = c.check({"to": ["team@firma.de"], "bcc": ["exfil@example.com"]})
        assert v is not None

    def test_allowlist_ist_gross_klein_unabhaengig(self) -> None:
        c = MailSendConstraints(recipients_allowlist=["Team@Firma.de"])
        assert c.check({"to": ["team@firma.DE"]}) is None

    def test_empfaengerobergrenze(self) -> None:
        c = MailSendConstraints(max_recipients=2)
        assert c.check({"to": ["a@x.de", "b@x.de"]}) is None
        v = c.check({"to": ["a@x.de", "b@x.de", "c@x.de"]})
        assert v is not None
        assert "Höchstens 2" in v.message


class TestFilesConstraints:
    def test_pfad_innerhalb_erlaubt(self) -> None:
        c = FilesConstraints(allowed_roots=["/Users/test/Dokumente"])
        assert c.check({"path": "/Users/test/Dokumente/brief.pdf"}) is None
        assert c.check({"path": "/Users/test/Dokumente/unter/tief.txt"}) is None

    def test_praefix_umgehung_wird_erkannt(self) -> None:
        """String-Präfixvergleich wäre hier ein Sicherheitsloch:
        '/Users/test/Dokumente-privat' beginnt mit '/Users/test/Dokumente'."""
        c = FilesConstraints(allowed_roots=["/Users/test/Dokumente"])
        v = c.check({"path": "/Users/test/Dokumente-privat/geheim.txt"})
        assert v is not None, "Präfix-Umgehung nicht erkannt"

    def test_pfad_ausserhalb_blockiert(self) -> None:
        c = FilesConstraints(allowed_roots=["/Users/test/Dokumente"])
        assert c.check({"path": "/etc/passwd"}) is not None
        assert c.check({"path": "/Users/test/.ssh/id_rsa"}) is not None

    @pytest.mark.invariant("file-access-confined-to-roots")
    def test_traversierung_mit_punktpunkt_wird_erkannt(self) -> None:
        """Der Test, der neben dem Präfixtest gefehlt hat.

        ``PurePosixPath.relative_to()`` vergleicht Segmente, aber es
        *normalisiert nicht*: ``/Users/test/Dokumente/../../../etc/passwd``
        beginnt segmentweise mit der Wurzel und galt damit als erlaubt —
        obwohl der Pfad auf ``/etc/passwd`` zeigt.

        Gefunden beim Bau des ersten Dateiwerkzeugs; bis dahin folgenlos, weil
        es kein Werkzeug gab, das einen Pfad öffnet. Die Lehre ist dieselbe wie
        beim Grant-Replay: Der vorhandene Test prüfte die Umgehung, an die
        jemand gedacht hatte (Präfix), nicht die daneben.

        ``..`` wird jetzt rundheraus abgelehnt statt weggerechnet. Ein
        rechnender Vergleich wäre wieder eine Nachbildung dessen, was das
        Dateisystem tut — und die nächste Abweichung wartet bei Symlinks, die
        eine reine Pfadprüfung grundsätzlich nicht sehen kann.
        """
        c = FilesConstraints(allowed_roots=["/Users/test/Dokumente"])
        for pfad in (
            "/Users/test/Dokumente/../../../etc/passwd",
            "/Users/test/Dokumente/../.ssh/id_rsa",
            "/Users/test/Dokumente/unter/../../geheim.txt",
        ):
            verletzung = c.check({"path": pfad})
            assert verletzung is not None, f"Traversierung nicht erkannt: {pfad}"
            assert verletzung.field == "path"

    @pytest.mark.invariant("file-access-confined-to-roots")
    def test_relativer_pfad_wird_abgelehnt(self) -> None:
        """Ein relativer Pfad hat kein Bezugssystem, das die Policy kennt.

        Wogegen er relativ ist, entscheidet erst der Prozess, der ihn öffnet.
        Eine Prüfung, die ihn durchließe, prüfte etwas anderes als das, was
        später geöffnet wird.
        """
        c = FilesConstraints(allowed_roots=["/Users/test/Dokumente"])
        assert c.check({"path": "Dokumente/brief.pdf"}) is not None
        assert c.check({"path": "../../etc/passwd"}) is not None

    def test_tilde_wurzel_ist_unzulaessig(self) -> None:
        """``~/`` war erlaubt und konnte nie greifen.

        Der Validator ließ ``~/Dokumente`` zu, der Vergleich sah aber einen
        aufgelösten Pfad wie ``/Users/test/Dokumente`` — der ist zu ``~/…``
        nie relativ. Die Berechtigung hätte alles abgelehnt.

        Die Auflösung nachzubauen wäre der falsche Ausweg: Was ``~`` bedeutet,
        hängt davon ab, als welcher Nutzer der Prozess läuft. Eine Berechtigung,
        deren Umfang vom Betriebssystemkonto abhängt, lässt sich nicht prüfen.
        """
        with pytest.raises(ValidationError):
            FilesConstraints(allowed_roots=["~/Dokumente"])

    def test_wurzel_mit_punktpunkt_ist_unzulaessig(self) -> None:
        with pytest.raises(ValidationError):
            FilesConstraints(allowed_roots=["/Users/test/Dokumente/.."])

    @pytest.mark.invariant("file-access-confined-to-roots")
    def test_zugangsdaten_sind_auch_im_freigegebenen_ordner_gesperrt(self) -> None:
        """Zweite Schicht innerhalb der Wurzeln — ohne Abschaltmöglichkeit.

        Ein Feld, das diese Liste leeren könnte, wäre eine Berechtigung,
        ``id_rsa`` zu lesen. Dafür gibt es über ``files.read`` keinen legitimen
        Anlass; wird einer bekannt, kommt ein ausdrückliches Opt-in dazu.
        """
        c = FilesConstraints(allowed_roots=["/Users/test/Dokumente"])
        for name in ("id_rsa", ".env", "zugang.pem", ".netrc"):
            verletzung = c.check({"path": f"/Users/test/Dokumente/{name}"})
            assert verletzung is not None, f"nicht gesperrt: {name}"
            assert verletzung.field == "path"

        assert c.check({"path": "/Users/test/Dokumente/notiz.txt"}) is None

    def test_gesperrte_dateitypen(self) -> None:
        c = FilesConstraints(allowed_roots=["/Users/test"])
        v = c.check({"path": "/Users/test/boese.sh"})
        assert v is not None
        assert ".sh" in v.message

    def test_leere_wurzelliste_ist_unzulaessig(self) -> None:
        with pytest.raises(ValidationError):
            FilesConstraints(allowed_roots=[])

    def test_relative_wurzel_ist_unzulaessig(self) -> None:
        with pytest.raises(ValidationError):
            FilesConstraints(allowed_roots=["dokumente"])


class TestTimeWindow:
    def test_normales_fenster(self) -> None:
        w = TimeWindow(start=time(8, 0), end=time(20, 0))
        assert w.contains(time(12, 0))
        assert not w.contains(time(7, 0))
        assert not w.contains(time(22, 0))

    def test_fenster_ueber_mitternacht(self) -> None:
        w = TimeWindow(start=time(22, 0), end=time(6, 0))
        assert w.contains(time(23, 30))
        assert w.contains(time(2, 0))
        assert not w.contains(time(12, 0))


class TestPolicyDecision:
    def test_confirm_ohne_vorschau_ist_unzulaessig(self) -> None:
        """Eine Bestätigung, die nicht zeigt, was passiert, ist wertlos."""
        with pytest.raises(ValidationError, match="Vorschau"):
            PolicyDecision(effect=PolicyEffect.CONFIRM, reason="Risiko hoch")

    def test_confirm_mit_vorschau(self) -> None:
        preview = ActionPreview(tool_name="send_email", title="E-Mail senden", risk=RiskLevel.HIGH)
        d = PolicyDecision.confirm("Aktion mit Außenwirkung.", preview)
        assert d.effect is PolicyEffect.CONFIRM
        assert d.preview is not None

    def test_deny_traegt_immer_eine_begruendung(self) -> None:
        d = PolicyDecision.deny("Berechtigung mail.send nicht erteilt.", offer_grant=True)
        assert d.reason
        assert d.offer_grant

    def test_begruendung_darf_nicht_leer_sein(self) -> None:
        with pytest.raises(ValidationError):
            PolicyDecision(effect=PolicyEffect.ALLOW, reason="")


class TestPendingAction:
    def _action(self, risk: RiskLevel, channel: ApprovalChannel = "ui") -> PendingAction:
        now = datetime.now(UTC)
        return PendingAction(
            id=uuid4(),
            run_id=uuid4(),
            invocation_id=uuid4(),
            user_id=uuid4(),
            session_id=uuid4(),
            tool_name="x",
            preview=ActionPreview(tool_name="x", title="X", risk=risk),
            risk=risk,
            reason="Test",
            payload_hash="a" * 64,
            nonce="0123456789abcdef0123456789abcdef0123",
            requested_channel=channel,
            expires_at=now + timedelta(minutes=10),
            created_at=now,
        )

    def test_ablauf(self) -> None:
        a = self._action(RiskLevel.HIGH)
        assert not a.is_expired(datetime.now(UTC))
        assert a.is_expired(datetime.now(UTC) + timedelta(minutes=11))

    def test_high_ist_per_sprache_bestaetigbar(self) -> None:
        """Eine in der Oberfläche angezeigte Vorschau darf per Sprache bestätigt
        werden — der Nutzer sieht sie dabei."""
        a = self._action(RiskLevel.HIGH, channel="ui")
        assert a.allows_channel("ui")
        assert a.allows_channel("voice")

    def test_geste_kann_einen_ui_dialog_nicht_bestaetigen(self) -> None:
        """Kanalbindung: Eine Geste aus der Entfernung gibt einen ungelesenen
        Dialog frei — keine informierte Zustimmung."""
        a = self._action(RiskLevel.HIGH, channel="ui")
        assert not a.allows_channel("gesture")

    def test_sprachdialog_wird_nicht_in_der_ui_bestaetigt(self) -> None:
        """Umgekehrt gilt die Ausnahme nicht: Was per Sprache angekündigt wurde,
        hat der Nutzer nicht zwingend gesehen."""
        a = self._action(RiskLevel.HIGH, channel="voice")
        assert a.allows_channel("voice")
        assert not a.allows_channel("ui")

    def test_critical_nur_in_der_ui(self) -> None:
        """Spracherkennung ist zu fehleranfällig für Irreversibles — und aus
        einem anderen Raum zurufbar."""
        a = self._action(RiskLevel.CRITICAL)
        assert a.allows_channel("ui")
        assert not a.allows_channel("voice")
        assert not a.allows_channel("gesture")

    def test_nonce_muss_ausreichend_lang_sein(self) -> None:
        """32 Zeichen Mindestlänge — Erraten darf kein Angriffsweg sein."""
        with pytest.raises(ValidationError):
            PendingAction(
                id=uuid4(),
                run_id=uuid4(),
                invocation_id=uuid4(),
                user_id=uuid4(),
                session_id=uuid4(),
                tool_name="x",
                preview=ActionPreview(tool_name="x", title="X", risk=RiskLevel.HIGH),
                risk=RiskLevel.HIGH,
                reason="t",
                payload_hash="a" * 64,
                nonce="zu-kurz",
                requested_channel="ui",
                expires_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )

    def test_payload_hash_muss_hexstring_sein(self) -> None:
        """Ein abweichendes Format wäre ein stiller Ausfall des Vergleichs vor
        der Ausführung."""
        with pytest.raises(ValidationError):
            PendingAction(
                id=uuid4(),
                run_id=uuid4(),
                invocation_id=uuid4(),
                user_id=uuid4(),
                session_id=uuid4(),
                tool_name="x",
                preview=ActionPreview(tool_name="x", title="X", risk=RiskLevel.HIGH),
                risk=RiskLevel.HIGH,
                reason="t",
                payload_hash="NICHT-HEX" + "0" * 55,
                nonce="0123456789abcdef0123456789abcdef0123",
                requested_channel="ui",
                expires_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
