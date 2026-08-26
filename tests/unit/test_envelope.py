"""Envelope Encryption — die Zusagen, nicht die Bibliothek.

Geprüft wird **nicht**, ob AES-GCM funktioniert; das ist die Aufgabe von
``cryptography``. Geprüft wird, was diese Bauart darüber hinaus verspricht
(ADR-008):

1. In der Zeile steht kein Klartext — auch nicht in Teilen.
2. Ein veränderter Geheimtext öffnet sich nicht.
3. Ein **verschobener** Geheimtext öffnet sich nicht: Wer die Datenbank
   erreicht, soll die Zeile eines fremden Kontos nicht in die eigene kopieren
   und vom System entschlüsseln lassen.
4. Ein Datensatz überlebt eine KEK-Rotation, ohne neu verschlüsselt zu werden.

Der Befund davor: Die Tabelle ``oauth_credentials`` führt seit dem ersten
Schema ``ciphertext``, ``nonce``, ``wrapped_dek`` und ``kek_id`` — und es gab
keine Zeile Code dazu. Dieselbe Form wie die Audit-Kette vor ``a67dd30``:
vollständig geschaffen, nirgends benutzt.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from jarvis_core.crypto import SealedSecret, SecretTampered, oeffnen, versiegeln
from jarvis_core.ports.keys import UnknownKek
from jarvis_integrations import DateiSchluessel, schluesseldatei_anlegen
from jarvis_integrations.dateischluessel import KEK_BYTES

pytestmark = [pytest.mark.asyncio, pytest.mark.security]

TOKEN = b"ya29.a0AfB_byC-nicht-echt-nur-ein-Testtoken"
KONTO = b"konto-4711"


@pytest.fixture
def schluessel(tmp_path: Path) -> DateiSchluessel:
    return DateiSchluessel(schluesseldatei_anlegen(tmp_path / "kek.json"))


class TestWasInDerZeileSteht:
    @pytest.mark.invariant("secrets-sealed-at-rest")
    async def test_der_klartext_steht_nirgends(self, schluessel: DateiSchluessel) -> None:
        """**Der ganze Zweck.** Ein Datenbank-Dump ohne den KEK ist wertlos.

        Geprüft wird die *ganze* Serialisierung und nicht nur das
        Geheimtextfeld: Ein Klartext, der versehentlich in einer Nebenspalte
        landet, wäre genauso preisgegeben.
        """
        siegel = await versiegeln(TOKEN, bindung=KONTO, schluessel=schluessel)

        # Alle Feldwerte aneinander, nicht nur der Geheimtext: Ein Klartext,
        # der versehentlich in einer Nebenspalte landet, wäre genauso
        # preisgegeben. (``model_dump_json`` scheitert an rohen Bytes — was
        # hier gebraucht wird, ist ohnehin der Rohinhalt.)
        alles = b"".join(
            wert if isinstance(wert, bytes) else str(wert).encode()
            for wert in siegel.model_dump().values()
        )
        assert TOKEN not in alles
        assert b"ya29" not in alles

    async def test_der_datenschluessel_steht_nur_verpackt_da(
        self, schluessel: DateiSchluessel
    ) -> None:
        """Sonst wäre die ganze Konstruktion eine aufwendige Kopie des Klartexts."""
        siegel = await versiegeln(TOKEN, bindung=KONTO, schluessel=schluessel)

        dek = await schluessel.unwrap(siegel.wrapped_dek, kek_id=siegel.kek_id)

        assert dek not in siegel.wrapped_dek
        assert len(dek) == 32

    async def test_zweimal_dasselbe_ergibt_zwei_verschiedene_zeilen(
        self, schluessel: DateiSchluessel
    ) -> None:
        """Ein DEK je Datensatz — und damit auch eine Nonce je Datensatz.

        Wären sie gleich, ließe sich aus zwei Zeilen ablesen, dass dasselbe
        Geheimnis darin steht. Bei AES-GCM wäre eine wiederholte Nonce mit
        demselben Schlüssel außerdem das Ende jeder Zusage.
        """
        a = await versiegeln(TOKEN, bindung=KONTO, schluessel=schluessel)
        b = await versiegeln(TOKEN, bindung=KONTO, schluessel=schluessel)

        assert a.ciphertext != b.ciphertext
        assert a.nonce != b.nonce
        assert a.wrapped_dek != b.wrapped_dek

    async def test_der_rundlauf_liefert_denselben_klartext(
        self, schluessel: DateiSchluessel
    ) -> None:
        siegel = await versiegeln(TOKEN, bindung=KONTO, schluessel=schluessel)

        assert await oeffnen(siegel, bindung=KONTO, schluessel=schluessel) == TOKEN


class TestWerDieZeileVeraendert:
    async def test_ein_veraenderter_geheimtext_oeffnet_sich_nicht(
        self, schluessel: DateiSchluessel
    ) -> None:
        siegel = await versiegeln(TOKEN, bindung=KONTO, schluessel=schluessel)
        verdreht = siegel.model_copy(
            update={"ciphertext": siegel.ciphertext[:-1] + bytes([siegel.ciphertext[-1] ^ 1])}
        )

        with pytest.raises(SecretTampered):
            await oeffnen(verdreht, bindung=KONTO, schluessel=schluessel)

    async def test_eine_fremde_nonce_oeffnet_nichts(self, schluessel: DateiSchluessel) -> None:
        a = await versiegeln(TOKEN, bindung=KONTO, schluessel=schluessel)
        b = await versiegeln(TOKEN, bindung=KONTO, schluessel=schluessel)

        with pytest.raises(SecretTampered):
            await oeffnen(
                a.model_copy(update={"nonce": b.nonce}), bindung=KONTO, schluessel=schluessel
            )

    async def test_ein_fremder_datenschluessel_oeffnet_nichts(
        self, schluessel: DateiSchluessel
    ) -> None:
        a = await versiegeln(TOKEN, bindung=KONTO, schluessel=schluessel)
        b = await versiegeln(TOKEN, bindung=KONTO, schluessel=schluessel)

        with pytest.raises(SecretTampered):
            await oeffnen(
                a.model_copy(update={"wrapped_dek": b.wrapped_dek}),
                bindung=KONTO,
                schluessel=schluessel,
            )


class TestDieBindungAnDenPlatz:
    """**Die Entscheidung, die ADR-008 nicht trifft.**

    Wer die Datenbank direkt erreicht, kann eine Zeile nicht entschlüsseln —
    aber er könnte sie verschieben: den Geheimtext eines fremden Kontos in die
    eigene Zeile kopieren und ihn vom System öffnen lassen. Dieselbe
    Überlegung, aus der das Audit-Log einen Trigger hat.
    """

    @pytest.mark.invariant("secrets-sealed-at-rest")
    async def test_ein_verschobener_geheimtext_oeffnet_sich_nicht(
        self, schluessel: DateiSchluessel
    ) -> None:
        siegel = await versiegeln(TOKEN, bindung=b"konto-des-opfers", schluessel=schluessel)

        with pytest.raises(SecretTampered):
            await oeffnen(siegel, bindung=b"konto-des-angreifers", schluessel=schluessel)

    async def test_ohne_bindung_geht_es_auch_nicht_auf(self, schluessel: DateiSchluessel) -> None:
        """Die Bindung wegzulassen ist kein Umweg um sie herum."""
        siegel = await versiegeln(TOKEN, bindung=KONTO, schluessel=schluessel)

        with pytest.raises(SecretTampered):
            await oeffnen(siegel, bindung=b"", schluessel=schluessel)


class TestRotation:
    """Der Grund, warum ``kek_id`` je Datensatz gespeichert wird.

    Ohne diese Kennung hieße jede Rotation: alle Zeilen neu verschlüsseln — und
    damit etwas, das niemand macht. Was niemand macht, findet nicht statt.
    """

    @staticmethod
    def _zweite_kennung(pfad: Path, kennung: str) -> None:
        """Legt einen zweiten KEK an und macht ihn zum aktuellen."""
        roh = json.loads(pfad.read_text(encoding="utf-8"))
        roh["schluessel"][kennung] = base64.b64encode(os.urandom(KEK_BYTES)).decode("ascii")
        roh["aktuell"] = kennung
        pfad.write_text(json.dumps(roh), encoding="utf-8")

    async def test_ein_alter_datensatz_bleibt_lesbar(self, tmp_path: Path) -> None:
        pfad = schluesseldatei_anlegen(tmp_path / "kek.json")
        alt = await versiegeln(TOKEN, bindung=KONTO, schluessel=DateiSchluessel(pfad))
        assert alt.kek_id == "kek-1"

        self._zweite_kennung(pfad, "kek-2")
        nachher = DateiSchluessel(pfad)

        assert nachher.kek_id == "kek-2"
        assert await oeffnen(alt, bindung=KONTO, schluessel=nachher) == TOKEN

    async def test_neue_datensaetze_tragen_den_neuen_schluessel(self, tmp_path: Path) -> None:
        pfad = schluesseldatei_anlegen(tmp_path / "kek.json")
        self._zweite_kennung(pfad, "kek-2")

        neu = await versiegeln(TOKEN, bindung=KONTO, schluessel=DateiSchluessel(pfad))

        assert neu.kek_id == "kek-2"

    async def test_ein_fehlender_schluessel_ist_ein_betriebsproblem(self, tmp_path: Path) -> None:
        """``UnknownKek`` und nicht ``SecretTampered``: Die Zeile ist in
        Ordnung, der Schlüssel fehlt. Die beiden verlangen entgegengesetzte
        Untersuchungen — die eine im Betrieb, die andere an den Daten."""
        pfad = schluesseldatei_anlegen(tmp_path / "kek.json")
        siegel = await versiegeln(TOKEN, bindung=KONTO, schluessel=DateiSchluessel(pfad))
        fremd = SealedSecret(
            ciphertext=siegel.ciphertext,
            nonce=siegel.nonce,
            wrapped_dek=siegel.wrapped_dek,
            kek_id="gibt-es-nicht",
        )

        with pytest.raises(UnknownKek):
            await oeffnen(fremd, bindung=KONTO, schluessel=DateiSchluessel(pfad))


class TestDieSchluesseldatei:
    async def test_ein_aktueller_schluessel_ohne_eintrag_wird_beim_bau_abgewiesen(
        self, tmp_path: Path
    ) -> None:
        """Sonst schlüge erst das nächste Verpacken fehl — mit einem Datensatz,
        der schon halb entstanden ist."""
        pfad = tmp_path / "kek.json"
        pfad.write_text(json.dumps({"aktuell": "kek-9", "schluessel": {}}), encoding="utf-8")

        with pytest.raises(ValueError, match="kek-9"):
            DateiSchluessel(pfad)

    async def test_ein_zu_kurzer_schluessel_wird_abgewiesen(self, tmp_path: Path) -> None:
        pfad = tmp_path / "kek.json"
        pfad.write_text(
            json.dumps(
                {"aktuell": "kek-1", "schluessel": {"kek-1": base64.b64encode(b"kurz").decode()}}
            ),
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="Bytes"):
            DateiSchluessel(pfad)

    async def test_die_datei_gehoert_nur_ihrem_besitzer(self, tmp_path: Path) -> None:
        pfad = schluesseldatei_anlegen(tmp_path / "kek.json")

        assert pfad.stat().st_mode & 0o077 == 0


class TestDerDateiKekIstEntwicklungssache:
    """ADR-008 V1.1 — die Prüfung steht beim **Start**.

    Ein Adapter, der sich selbst verbietet, greift erst, wenn zum ersten Mal
    ein Token geschrieben wird; dann läuft das System längst, und jemand hat
    sich darauf verlassen.
    """

    @pytest.mark.invariant("kek-never-leaves-its-instance")
    def test_in_produktion_startet_der_prozess_nicht(self) -> None:
        from pydantic import ValidationError

        from jarvis_api.settings import Settings

        with pytest.raises(ValidationError, match="ADR-008"):
            Settings(JARVIS_ENV="production", KEY_PROVIDER="file")

    def test_in_der_entwicklung_ist_er_zugelassen(self) -> None:
        from jarvis_api.settings import Settings

        assert Settings(JARVIS_ENV="development", KEY_PROVIDER="file").key_provider == "file"

    @pytest.mark.invariant("kek-never-leaves-its-instance")
    def test_der_port_gibt_keinen_schluessel_heraus(self) -> None:
        """Die Signatur trägt die Zusage.

        Ein ``kek()``-Verfahren wäre von Vault Transit nicht implementierbar —
        dort verlässt das Schlüsselmaterial die Instanz nie. Diese Prüfung
        hält fest, dass niemand es später „für den Notfall" ergänzt.
        """
        from jarvis_core.ports.keys import KeyProvider

        verfahren = {n for n in dir(KeyProvider) if not n.startswith("_")}

        assert verfahren == {"kek_id", "wrap", "unwrap"}, (
            f"Der Port führt {verfahren} — wer hier ein Verfahren ergänzt, das den "
            "Schlüssel herausgibt, hebt ADR-008 V1.1 auf."
        )
