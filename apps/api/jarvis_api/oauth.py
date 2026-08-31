"""Welche Anbieter verbindbar sind — und warum die Liste leer sein darf.

**Ein Anbieter ohne Zugangsdaten steht nicht im Katalog.** Dieselbe Bedingung
wie im Modellkatalog: Ein Eintrag, den niemand aufrufen kann, ist keine
Vollständigkeit, sondern eine Falschaussage nach außen. Die Oberfläche böte
ein „Konto verbinden" an, das beim Anbieter mit einem Fehler endet — und der
Nutzer sucht die Ursache bei sich.

Ohne konfigurierte Zugangsdaten ist die Liste leer und `/accounts/authorize`
antwortet mit 404. Das ist die ehrliche Auskunft: Diesen Anbieter gibt es in
dieser Installation nicht.
"""

from __future__ import annotations

from jarvis_api.settings import Settings
from jarvis_core.ports.oauth import OAuthProvider

__all__ = ["oauth_providers"]

GOOGLE_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
"""Die Adressen des Anbieters, im Quelltext und nicht in der Konfiguration.

Anders als Kennung, Geheimnis und Rückrufadresse sind sie keine Eigenschaft
**dieser** Installation, sondern von Google. Eine konfigurierbare Token-Adresse
wäre außerdem eine Stelle, an der sich das Client-Geheimnis umleiten ließe —
per Umgebungsvariable, ohne Codeänderung und ohne Spur im Repository.
"""


def oauth_providers(settings: Settings) -> dict[str, OAuthProvider]:
    """Die verbindbaren Anbieter dieser Installation."""
    katalog: dict[str, OAuthProvider] = {}

    if settings.google_client_id and settings.google_client_secret:
        katalog["google"] = OAuthProvider(
            name="google",
            authorize_url=GOOGLE_AUTHORIZE,
            token_url=GOOGLE_TOKEN,
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            redirect_uri=settings.google_redirect_uri,
            scopes=tuple(settings.google_scopes),
        )

    return katalog
