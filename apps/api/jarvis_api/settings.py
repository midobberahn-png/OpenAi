"""Konfiguration der API.

Die WebAuthn-Werte stehen hier und **nicht** im Request. ``rp_id`` und
``origins`` sind die Verankerung, die Passkeys phishing-resistent macht: Eine
Signatur, die für ``https://jarvis.local`` ausgestellt wurde, ist auf einer
nachgebauten Seite wertlos. Ein aus dem Request übernommener Origin wäre die
Aufhebung genau dieser Eigenschaft — deshalb ist er Konfiguration.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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
    webauthn_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173"], alias="WEBAUTHN_ORIGINS"
    )

    session_cookie_name: str = Field(default="jarvis_session", alias="SESSION_COOKIE_NAME")
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    trusted_proxies: list[str] = Field(default_factory=list, alias="TRUSTED_PROXIES")
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

    @field_validator("webauthn_origins", "trusted_proxies", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Kommagetrennt aus der Umgebung, Liste im Code."""
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
