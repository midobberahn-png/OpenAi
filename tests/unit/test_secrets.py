"""Hochstufung der Datenklasse bei Zugangsdaten im Ergebnis.

Der Test, der hier am meisten trägt, ist nicht „erkennt einen Schlüssel",
sondern **„stuft nie herab"**. Erkennung ist eine Heuristik und darf es sein,
solange ihr Versagen den Ausgangszustand herstellt. Sobald sie eine Klasse
senken könnte, wäre sie ein Sicherheitsmechanismus, der auf Mustererkennung
ruht — und genau das lehnt dieses Projekt ab.
"""

from __future__ import annotations

import pytest

from jarvis_contracts import DataClass
from jarvis_core.policy import data_class_for_content, looks_like_secret

SCHLUESSEL = [
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "export TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "SLACK=xoxb-1234567890-abcdefghij",
    "Authorization: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27u",
    'password = "hunter2hunter2"',
    "DATABASE_URL=postgresql://nutzer:geheimwort@localhost:5432/db",
]

UNVERDAECHTIG = [
    "# Plan\nMittwoch: Fokuszeit",
    "Die Besprechung beginnt um 14 Uhr.",
    "kontakt@example.com",  # personenbezogen, aber kein Zugangsdatum
    "Telefon: 030 123456",
    "Der Schlüssel zum Erfolg ist Ausdauer.",
    "password reset instructions were sent",  # Wort ohne Wert dahinter
]


class TestErkennung:
    @pytest.mark.parametrize("text", SCHLUESSEL)
    def test_zugangsdaten_werden_erkannt(self, text: str) -> None:
        assert looks_like_secret(text), f"nicht erkannt: {text[:40]!r}"

    @pytest.mark.parametrize("text", UNVERDAECHTIG)
    def test_harmloser_text_loest_nicht_aus(self, text: str) -> None:
        """Falsch positive kosten hier echte Nutzbarkeit.

        Jede Fehlauslösung hebt den Inhalt auf P3 und schließt damit alle
        Cloud-Modelle aus. Eine Heuristik, die bei jeder Mailadresse anschlägt,
        macht die Stufe wertlos — deshalb steht bewusst kein Muster für
        personenbezogene Daten in der Liste. Personenbezug ist P2, und den
        vergibt das Werkzeug ohnehin.
        """
        assert not looks_like_secret(text), f"Fehlauslösung: {text[:40]!r}"


class TestEinbahnstrasse:
    """Die eigentliche Zusicherung dieses Moduls."""

    @pytest.mark.parametrize("deklariert", list(DataClass))
    def test_ohne_treffer_bleibt_die_klasse_unveraendert(self, deklariert: DataClass) -> None:
        assert data_class_for_content("harmloser Text", declared=deklariert) is deklariert

    @pytest.mark.parametrize("deklariert", list(DataClass))
    def test_mit_treffer_wird_nie_gesenkt(self, deklariert: DataClass) -> None:
        """Auch von P3 aus — ``escalate`` nimmt das Maximum, nicht den Treffer.

        Wäre hier ein ``return DataClass.P3`` statt der Maximumsbildung, fiele
        es bei P3 nicht auf. Der Test steht trotzdem: Er hält die Eigenschaft
        fest, nicht den heutigen Zufall, dass P3 die höchste Stufe ist.
        """
        ergebnis = data_class_for_content("-----BEGIN PRIVATE KEY-----", declared=deklariert)
        assert ergebnis.level >= deklariert.level
        assert ergebnis is DataClass.P3

    def test_p3_verlaesst_das_geraet_nicht(self) -> None:
        """Warum die Hochstufung überhaupt etwas bewirkt.

        Ohne diese Eigenschaft wäre das Modul Kosmetik: Die Stufe hätte einen
        anderen Namen und dieselbe Wirkung.
        """
        assert (
            data_class_for_content("AKIAIOSFODNN7EXAMPLE", declared=DataClass.P1).cloud_allowed
            is False
        )


class TestUmgebungsvariablenSchreibweise:
    """Zugangsdaten in `NAME=WERT`-Form — der häufigste Fall in echten Dateien.

    **Gefunden beim Abnahmetest zu ADR-014**, und zwar erst, nachdem ein grüner
    Haken sich als falsch erwies: Der Testlauf meldete die erwartete
    Hochstufung auf P3, aber sie kam vom *Klassifikator* — pytest leitet
    ``tmp_path`` vom Testnamen ab, der Name enthielt „zugangsdaten", der Pfad
    stand im Lauf-Input. Der Dateiinhalt war unbeteiligt.

    Beim Nachmessen zeigte sich die eigentliche Lücke: Das allgemeine Muster
    verlangte das Schlüsselwort **unmittelbar** vor ``=`` oder ``:``. Bei
    ``AWS_SECRET_ACCESS_KEY="…"`` steht zwischen ``SECRET`` und ``=`` noch
    ``_ACCESS_KEY`` — und damit fiel ein echter AWS-Schlüssel durch.

    **Warum das jetzt mehr wiegt als vorher.** Seit Werkzeugdaten in den Prompt
    fließen (ADR-014), entscheidet diese Heuristik mit, ob ein gelesener
    Dateiinhalt ein Cloud-Modell erreichen darf. Solange nur Ollama existiert,
    ist der Unterschied folgenlos — lokal bleibt lokal. Mit dem ersten
    Cloud-Anbieter ist er es nicht mehr.

    Die Heuristik bleibt eine Heuristik. Sie *entfernt* nichts, sie stuft ein;
    was Zugangsdaten festhält, ist P3 — und P3 verlässt das Gerät nicht.
    """

    @pytest.mark.parametrize(
        "zeile",
        [
            'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            "DATABASE_PASSWORD=supergeheim123",
            "MY_API_KEY_PROD: abcdefgh12345678",
            "STRIPE_CLIENT_SECRET = 'sk_live_abcdefghijkl'",
        ],
    )
    def test_umgebungsvariable_mit_schluesselwort_im_namen(self, zeile: str) -> None:
        assert looks_like_secret(zeile), zeile

    @pytest.mark.parametrize(
        "zeile",
        [
            "Das Passwort habe ich vergessen.",
            "Der Termin ist am Mittwoch um 10 Uhr.",
            "secret: ok",
            "api_key fehlt",
        ],
    )
    def test_prosa_wird_nicht_hochgestuft(self, zeile: str) -> None:
        """Die Gegenprobe, und sie ist die wichtigere Hälfte.

        Eine Heuristik, die alles hochstuft, macht das lokale Modell zum
        einzigen Gesprächspartner und die Stufe wertlos — genau das, wovor der
        Modulkopf warnt.
        """
        assert not looks_like_secret(zeile), zeile
