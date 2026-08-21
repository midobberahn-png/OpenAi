"""Konfiguration der API.

Die WebAuthn-Werte stehen hier und **nicht** im Request. ``rp_id`` und
``origins`` sind die Verankerung, die Passkeys phishing-resistent macht: Eine
Signatur, die für ``https://jarvis.local`` ausgestellt wurde, ist auf einer
nachgebauten Seite wertlos. Ein aus dem Request übernommener Origin wäre die
Aufhebung genau dieser Eigenschaft — deshalb ist er Konfiguration.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

__all__ = ["Settings", "get_settings"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: str = Field(default="development", alias="JARVIS_ENV")
    database_url: str = Field(
        default="postgresql+asyncpg://jarvis:jarvis_dev@localhost:5432/jarvis",
        alias="DATABASE_URL",
    )

    webauthn_rp_id: str = Field(default="localhost", alias="WEBAUTHN_RP_ID")
    webauthn_rp_name: str = Field(default="JARVIS", alias="WEBAUTHN_RP_NAME")
    webauthn_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"], alias="WEBAUTHN_ORIGINS"
    )

    session_cookie_name: str = Field(default="jarvis_session", alias="SESSION_COOKIE_NAME")
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    ollama_url: str = Field(default="http://localhost:11434", alias="OLLAMA_URL")
    """Wo Ollama läuft.

    Vorgabe ist der lokale Dienst, und das ist die einzige Adresse, die zur
    Zusage passt: ``models.py`` führt das Modell mit ``is_local=True``, und
    daran macht das Model Gateway fest, dass P3 das Gerät nicht verlässt. Wer
    hier einen fremden Rechner einträgt, hebelt diese Zusage aus, ohne dass
    eine Prüfung anschlägt — der Katalog beschreibt das Deployment, er misst
    es nicht.
    """

    ollama_model: str = Field(default="llama3.1:8b", alias="OLLAMA_MODEL")
    """Das lokale Modell. Einziger Eintrag des Katalogs (``models.py``)."""

    ollama_context_window: int = Field(default=128_000, alias="OLLAMA_CONTEXT_WINDOW")
    ollama_p50_latency_ms: int = Field(default=250, alias="OLLAMA_P50_LATENCY_MS")
    """Gehen als Gewichte in die Modellwahl ein. Geschätzte Werte sind
    zulässig — das Routing ist deterministisch, nicht exakt."""

    files_allowed_roots: Annotated[list[str], NoDecode] = Field(
        default_factory=list, alias="FILES_ALLOWED_ROOTS"
    )
    """Ordner, aus denen ``files.read`` überhaupt lesen darf — die Grenze des
    **Prozesses**.

    Nicht zu verwechseln mit ``FilesConstraints.allowed_roots``: Das ist die
    Grenze einer *Berechtigung* und steht je Nutzer in der Datenbank. Diese
    hier gilt unabhängig davon, was jemand erteilt bekommen hat, und wird erst
    dort geprüft, wo der Pfad aufgelöst und geöffnet wird.

    Zwei Grenzen sind hier keine Doppelung. Die Berechtigung beantwortet „darf
    dieser Nutzer diesen Pfad nennen?"; der Adapter beantwortet „wohin zeigt er
    wirklich?". Ein Symlink ist auf der ersten Ebene unsichtbar.

    Leer bedeutet: nichts ist lesbar. Das ist der richtige Vorgabewert — eine
    Dateifreigabe entsteht durch eine Entscheidung, nicht durch eine
    Voreinstellung.
    """

    trusted_proxies: Annotated[list[str], NoDecode] = Field(
        default_factory=list, alias="TRUSTED_PROXIES"
    )
    """Adressen, deren ``X-Forwarded-For`` geglaubt wird.

    Leer bedeutet: keinem. Das ist der sichere Standard — ohne
    vorgeschalteten, konfigurierten Proxy ist der Header ein frei erfundenes
    Feld, und ein Rate-Limit, das daran hängt, kostet einen Angreifer eine
    Zeile Code. Wer hinter einem Reverse Proxy betreibt, trägt dessen Adresse
    hier ein und weiß dann auch, warum."""

    @property
    def cookie_secure(self) -> bool:
        """Außerhalb der Entwicklung nur über HTTPS.

        Als abgeleitete Eigenschaft statt als Schalter: Ein Feld
        ``COOKIE_SECURE=false`` in einer Produktionsumgebung wäre ein
        Einzeiler, den niemand bemerkt.
        """
        return self.env != "development"

    @field_validator("webauthn_origins", "trusted_proxies", "files_allowed_roots", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Kommagetrennt aus der Umgebung, Liste im Code.

        ``NoDecode`` an den Feldern ist dafür notwendig und war es immer:
        pydantic-settings versucht bei Listenfeldern zuerst ``json.loads`` auf
        den Umgebungswert — **bevor** dieser Validator läuft — und wirft bei
        ``a,b`` einen ``SettingsError``. Der Fehler war latent, weil bis zum
        ersten Werkzeugschritt niemand eine dieser Listen tatsächlich über die
        Umgebung gesetzt hat. ``NoDecode`` reicht den Rohwert durch, und erst
        hier entscheidet sich, wie er zerlegt wird.
        """
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
