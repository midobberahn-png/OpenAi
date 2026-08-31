"""PKCE — der Nachweis, dass der Einlöser auch der Anfrager war (RFC 7636).

**Wogegen das schützt und wogegen nicht.** Der Autorisierungscode reist durch
den Browser: über eine Weiterleitung, durch die Adresszeile, in den Verlauf,
möglicherweise in einen ``Referer``. Wer ihn dort abgreift, konnte ihn früher
einlösen, weil zum Einlösen nur der Code und das Client-Geheimnis nötig waren
— und Letzteres ist bei einem öffentlichen Client keins.

PKCE fügt ein Geheimnis hinzu, das **nie durch den Browser geht**: Beim Start
sendet der Client den *Hash* eines frisch erzeugten Verifiers, beim Einlösen
den Verifier selbst — über die Rückseite, direkt an den Token-Endpunkt. Ein
abgefangener Code allein ist damit wertlos.

**Wogegen es nicht schützt: die Zuordnung des Rückrufs zu einem Nutzer.** Das
leistet der ``state``, und die beiden werden gern verwechselt. PKCE verhindert,
dass ein Dritter *unseren* Code einlöst; ``state`` verhindert, dass wir *seinen*
Code für unseren halten. Beide sind nötig, keiner ersetzt den anderen.
"""

from __future__ import annotations

import base64
import hashlib

__all__ = ["pkce_challenge"]


def pkce_challenge(verifier: str) -> str:
    """Die Challenge zu einem Verifier — ``S256``, nie ``plain``.

    ``plain`` steht in RFC 7636 und ist hier bewusst nicht wählbar: Es sendet
    den Verifier im ersten Schritt durch den Browser und hebt damit genau die
    Eigenschaft auf, wegen der es PKCE gibt. Ein Schalter dafür wäre eine
    Einstellung, die einen Schutz abschaltet — und irgendwann steht sie in
    einer Konfiguration, weil ein Anbieter sich beschwert hat.

    Base64url **ohne** Füllzeichen: RFC 7636 §4.2 verlangt das, und ein ``=``
    am Ende lässt manche Anbieter die Challenge nicht wiedererkennen — ein
    Fehler, der wie „ungültiger Code" aussieht und woanders gesucht wird.
    """
    abdruck = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(abdruck).decode("ascii").rstrip("=")
