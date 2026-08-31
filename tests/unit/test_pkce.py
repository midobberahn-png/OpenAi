"""PKCE — die Challenge, und warum sie nicht der Verifier sein darf.

Eigene Datei und nicht bei ``test_tokentausch.py``: Diese Prüfungen sind
synchron, und die dortige ``pytestmark`` markiert alles als ``asyncio``. Ein
synchroner Test unter einem asyncio-Marker läuft zwar, aber pytest warnt — und
eine Warnung, die man gewöhnt ist, liest niemand mehr.
"""

from __future__ import annotations

import pytest

from jarvis_core.crypto import pkce_challenge

pytestmark = [pytest.mark.security]


class TestPkce:
    def test_die_challenge_ist_der_hash_und_nicht_der_verifier(self) -> None:
        """``plain`` sendet den Verifier durch den Browser und hebt damit auf,
        wozu es PKCE gibt."""
        verifier = "ein-hinreichend-langer-verifier-wert-1234567890"

        challenge = pkce_challenge(verifier)

        assert challenge != verifier
        assert verifier not in challenge

    def test_ohne_fuellzeichen(self) -> None:
        """RFC 7636 §4.2 verlangt base64url ohne ``=`` — mit Füllzeichen
        erkennen manche Anbieter die Challenge nicht wieder, und der Fehler
        sieht aus wie „ungültiger Code"."""
        assert "=" not in pkce_challenge("x" * 43)

    def test_gleicher_verifier_gleiche_challenge(self) -> None:
        assert pkce_challenge("abc") == pkce_challenge("abc")
