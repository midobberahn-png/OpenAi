"""Das Token-Bündel: zwei Geheimnisse in einem Geheimtext.

Klein, und trotzdem eine eigene Datei — weil hier ein **Format** festgelegt
ist. Ein Format ohne Test ist eine Verabredung, an die sich der nächste Leser
nur erinnert, solange er sie geschrieben hat.
"""

from __future__ import annotations

import pytest

from jarvis_api.tokenbuendel import buendeln, zerlegen

pytestmark = [pytest.mark.security]


def test_hin_und_zurueck() -> None:
    assert zerlegen(buendeln("at", "rt")) == ("at", "rt")


def test_ohne_erneuerungstoken_kommt_none_zurueck() -> None:
    """Und nicht ``""``.

    Es gibt keinen Erneuerungstoken der Länge null; einen leeren Wert
    weiterzureichen hieße, dem Anbieter einen leeren Token vorzulegen — und
    dessen Antwort wäre ``invalid_grant``, also ausgerechnet die, die ein
    Konto für tot erklärt.
    """
    assert zerlegen(buendeln("at", None)) == ("at", None)


def test_ein_umbruch_im_zweiten_teil_zerschneidet_ihn_nicht() -> None:
    """``partition`` trennt am **ersten** Umbruch.

    Ein unbegrenztes ``split`` zerschnitte einen Erneuerungstoken, der wider
    Erwarten einen Umbruch enthielte, still in der Mitte — und der Fehler
    zeigte sich Stunden später als „Zustimmung besteht nicht mehr".
    """
    assert zerlegen(b"at\nrt-teil1\nrt-teil2") == ("at", "rt-teil1\nrt-teil2")
