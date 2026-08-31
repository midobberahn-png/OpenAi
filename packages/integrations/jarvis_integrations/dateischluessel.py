"""Der KEK aus einer Datei — **ausschließlich für die Entwicklung** (ADR-008).

Erfüllt ``KeyProvider``. Die Zusage ist bescheiden und soll es sein: Ein
Datenbank-Dump ohne diese Datei ist wertlos. Was er **nicht** leistet, steht in
ADR-008 V1.1 und ist der Grund, warum dieser Provider nur in der Entwicklung
zugelassen ist:

> Bei ``KEY_PROVIDER=file`` läge der KEK im Speicher desselben Prozesses, der
> HTTP annimmt — eine Schwachstelle im Web-Layer gäbe damit alle
> Postfach-Tokens preis.

Genau deshalb weist ``Settings`` diesen Provider in Produktion beim Start ab.
Die Prüfung steht dort und nicht hier: Ein Adapter, der sich selbst verbietet,
wäre erst zur Laufzeit wirksam — also möglicherweise erst, wenn zum ersten Mal
ein Token geschrieben wird.

**Mehrere Schlüssel, nicht einer.** Die Datei führt ein Verzeichnis von Kennung
→ Schlüssel und dazu, welcher der aktuelle ist. Ohne das wäre die Rotation, die
``kek_id`` in der Tabelle vorsieht, gar nicht durchführbar: Wer rotiert,
braucht für eine Weile **beide** Schlüssel — den neuen zum Verpacken und den
alten zum Öffnen dessen, was schon liegt.

Das Format ist bewusst schlicht (JSON, Schlüssel base64)::

    {"aktuell": "kek-2", "schluessel": {"kek-1": "…", "kek-2": "…"}}
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from jarvis_core.ports.keys import UnknownKek

__all__ = ["KEK_BYTES", "DateiSchluessel", "schluesseldatei_anlegen"]

KEK_BYTES = 32
"""256 Bit, wie der DEK. Ein KEK, der schwächer ist als das, was er schützt,
verschiebt das Problem nur."""

_NONCE_BYTES = 12


class DateiSchluessel:
    """Liest die Schlüssel **einmal beim Bau** und hält sie im Speicher.

    Einmal, weil ein Neulesen je Aufruf die Datei zur Laufzeitabhängigkeit
    machte: Wer sie während des Betriebs ersetzt oder löscht, hielte damit die
    Entschlüsselung an, ohne dass es beim Start jemand bemerkt hätte. Die Datei
    fehlt entweder sofort — dann startet der Prozess nicht — oder gar nicht.
    """

    def __init__(self, pfad: str | Path) -> None:
        roh = json.loads(Path(pfad).expanduser().read_text(encoding="utf-8"))
        self._aktuell: str = str(roh["aktuell"])
        self._schluessel: dict[str, bytes] = {
            str(kennung): base64.b64decode(wert) for kennung, wert in roh["schluessel"].items()
        }
        if self._aktuell not in self._schluessel:
            # Sonst schlüge erst das nächste Verpacken fehl — und zwar mit
            # einem Datensatz, der schon halb entstanden ist.
            raise ValueError(f"Der aktuelle KEK {self._aktuell!r} steht nicht in der Datei.")
        for kennung, wert in self._schluessel.items():
            if len(wert) != KEK_BYTES:
                raise ValueError(f"KEK {kennung!r} hat {len(wert)} statt {KEK_BYTES} Bytes.")

    @property
    def kek_id(self) -> str:
        return self._aktuell

    async def wrap(self, dek: bytes) -> bytes:
        """Verpackt mit dem aktuellen KEK.

        Die Nonce steht **vor** dem Geheimtext im Ergebnis. Sie ist kein
        Geheimnis, sie muss nur einmalig sein — und sie hier mitzuführen spart
        eine weitere Spalte in einer Tabelle, deren Bedeutung ohnehin an vier
        Feldern hängt.
        """
        nonce = os.urandom(_NONCE_BYTES)
        return nonce + AESGCM(self._schluessel[self._aktuell]).encrypt(nonce, dek, None)

    async def unwrap(self, wrapped_dek: bytes, *, kek_id: str) -> bytes:
        """Entpackt mit **dem** KEK, der verpackt hat.

        Ein unbekannter ist ``UnknownKek`` und kein Entschlüsselungsfehler: Der
        Datensatz ist in Ordnung, der Schlüssel fehlt. Die beiden Fälle
        verlangen entgegengesetzte Untersuchungen — der eine im Betrieb, der
        andere an den Daten.
        """
        kek = self._schluessel.get(kek_id)
        if kek is None:
            raise UnknownKek(f"Kein Schlüssel mit der Kennung {kek_id!r}.")
        nonce, rest = wrapped_dek[:_NONCE_BYTES], wrapped_dek[_NONCE_BYTES:]
        try:
            return AESGCM(kek).decrypt(nonce, rest, None)
        except InvalidTag as ungueltig:
            raise UnknownKek(
                f"Der Datenschlüssel ließ sich mit {kek_id!r} nicht entpacken."
            ) from ungueltig


def schluesseldatei_anlegen(pfad: str | Path, *, kennung: str = "kek-1") -> Path:
    """Erzeugt eine Schlüsseldatei mit einem frischen KEK.

    Für die Einrichtung und für Tests. Die Datei bekommt Rechte ``0600`` —
    nicht als Schutz gegen einen Angreifer mit Systemzugang, sondern damit sie
    nicht versehentlich in einem Ordner landet, den jemand teilt.
    """
    ziel = Path(pfad).expanduser()
    inhalt = {
        "aktuell": kennung,
        "schluessel": {kennung: base64.b64encode(os.urandom(KEK_BYTES)).decode("ascii")},
    }
    ziel.write_text(json.dumps(inhalt, indent=2), encoding="utf-8")
    ziel.chmod(0o600)
    return ziel
