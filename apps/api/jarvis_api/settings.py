"""Konfiguration der API.

Die WebAuthn-Werte stehen hier und **nicht** im Request. ``rp_id`` und
``origins`` sind die Verankerung, die Passkeys phishing-resistent macht: Eine
Signatur, die für ``https://jarvis.local`` ausgestellt wurde, ist auf einer
nachgebauten Seite wertlos. Ein aus dem Request übernommener Origin wäre die
Aufhebung genau dieser Eigenschaft — deshalb ist er Konfiguration.
"""

from __future__ import annotations

from decimal import Decimal
from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator, model_validator
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

    key_provider: str = Field(default="file", alias="KEY_PROVIDER")
    """Woher der KEK kommt (ADR-008): ``file`` in der Entwicklung, später
    ``keychain`` oder ``vault``.

    **``file`` ist in Produktion verboten**, und die Prüfung steht im Validator
    unten — nicht im Adapter. Ein Adapter, der sich selbst verbietet, greift
    erst, wenn zum ersten Mal ein Token geschrieben wird; dann läuft das System
    längst und jemand hat sich darauf verlassen."""

    key_file: str = Field(default="~/.jarvis/kek.json", alias="KEY_FILE")
    """Wo die Schlüsseldatei liegt. Außerhalb des Repositorys, mit Vorgabe im
    Heimatverzeichnis — ein Vorgabewert innerhalb des Projekts wäre eine
    Einladung, ihn einzuchecken."""

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

    # -- Fremde Anbieter ---------------------------------------------------
    #
    # **Ohne Schlüssel und ohne Modellnamen gibt es keinen Eintrag im
    # Katalog.** Beides ist Absicht und nicht Bequemlichkeit: Ein Vorgabewert
    # für den Modellnamen wäre eine Behauptung dieses Repositorys darüber, was
    # es bei einem Anbieter gerade gibt — und ein Katalogeintrag, den niemand
    # aufrufen kann, führt das Routing in die Irre. Es wählte ein Modell und
    # scheiterte danach.
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="", alias="ANTHROPIC_MODEL")
    anthropic_context_window: int = Field(default=128_000, alias="ANTHROPIC_CONTEXT_WINDOW")
    anthropic_p50_latency_ms: int = Field(default=2_000, alias="ANTHROPIC_P50_LATENCY_MS")
    anthropic_cost_per_1m_in: Decimal = Field(
        default=Decimal("0"), alias="ANTHROPIC_COST_PER_1M_IN"
    )
    anthropic_cost_per_1m_out: Decimal = Field(
        default=Decimal("0"), alias="ANTHROPIC_COST_PER_1M_OUT"
    )
    anthropic_cost_per_1m_cached_in: Decimal | None = Field(
        default=None, alias="ANTHROPIC_COST_PER_1M_CACHED_IN"
    )
    anthropic_cost_per_1m_cache_write: Decimal | None = Field(
        default=None, alias="ANTHROPIC_COST_PER_1M_CACHE_WRITE"
    )

    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    openai_model: str = Field(default="", alias="OPENAI_MODEL")
    openai_context_window: int = Field(default=128_000, alias="OPENAI_CONTEXT_WINDOW")
    openai_p50_latency_ms: int = Field(default=2_000, alias="OPENAI_P50_LATENCY_MS")
    openai_cost_per_1m_in: Decimal = Field(default=Decimal("0"), alias="OPENAI_COST_PER_1M_IN")
    openai_cost_per_1m_out: Decimal = Field(default=Decimal("0"), alias="OPENAI_COST_PER_1M_OUT")
    openai_cost_per_1m_cached_in: Decimal | None = Field(
        default=None, alias="OPENAI_COST_PER_1M_CACHED_IN"
    )
    openai_cost_per_1m_cache_write: Decimal | None = Field(
        default=None, alias="OPENAI_COST_PER_1M_CACHE_WRITE"
    )
    """Preise in **Euro je einer Million Tokens**.

    Ohne sie entsteht kein Katalogeintrag — dieselbe Bedingung wie Schlüssel
    und Modellname, und aus demselben Grund: Ein Modell, dessen Kosten niemand
    kennt, macht aus der Kostengrenze eines Laufs eine Statistik. Der Preis
    steht in der Konfiguration und nicht im Repository, weil eine Preisliste im
    Quelltext beim nächsten Anbieterrundbrief falsch ist und niemand es merkt.

    ``*_CACHED_IN`` ist optional; ohne Angabe werden aus dem Cache gelesene
    Tokens zum vollen Eingabepreis verbucht. Das ist die vorsichtige Richtung:
    zu früh anhalten ist ärgerlich, zu spät kostet Geld.
    """

    cloud_zero_retention: Annotated[list[str], NoDecode] = Field(
        default_factory=list, alias="CLOUD_ZERO_RETENTION"
    )
    """Anbieter, für die eine Zero-Retention-Vereinbarung **vorliegt**.

    Kommagetrennt, etwa ``anthropic,openai``. Leer heißt: keine — und dann
    sieht ein fremder Anbieter ausschließlich P0 (docs/00-uebersicht.md §8,
    durchgesetzt im Model Gateway).

    **Diese Angabe beschreibt einen Vertrag, sie misst ihn nicht.** Dieselbe
    Bauart wie ``is_local``: Wer hier einen Anbieter einträgt, ohne die
    Vereinbarung zu haben, hebelt die Zusage aus, ohne dass eine Prüfung
    anschlägt. Deshalb ist die Vorgabe leer und nicht „vertrauen wir mal".
    """

    daily_budget_eur: Decimal = Field(
        default=Decimal("5.00"), alias="JARVIS_DAILY_BUDGET_EUR", gt=0
    )
    """Was ein Nutzer an einem Tag bei fremden Anbietern ausgeben darf.

    **Kein Ausschalter, und das ist Absicht.** Ein Wert von null hieße „keine
    Grenze" und sähe aus wie „nicht konfiguriert" — genau die stille Null, die
    dieses Projekt schon zweimal teuer bezahlt hat. Wer mehr braucht, trägt
    mehr ein; die Grenze bleibt dann eine Aussage.

    Die Vorgabe stand als Beispiel in ``.env.example`` und wurde von nichts
    gelesen. Sie ist nicht ausgedacht, sondern die Zahl, die dort seit dem
    ersten Entwurf steht.

    Lokale Modelle zählen nicht mit: Sie kosten Strom, keine Rechnung — und ein
    erschöpftes Tagesbudget verengt genau auf sie.
    """

    timezone: str = Field(default="Europe/Berlin", alias="JARVIS_TIMEZONE")
    """Welcher Tag gemeint ist, wenn vom Tagesbudget die Rede ist.

    Der UTC-Tag wäre bequem und falsch: Er setzte das Budget im Sommer um
    02:00 Ortszeit zurück. Eine unbekannte Zone scheitert beim Start, nicht bei
    der ersten Abrechnung.
    """

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

    # -- Verbundene Konten (OAuth) ----------------------------------------
    #
    # **Ohne Client-Kennung und Geheimnis gibt es den Anbieter nicht.**
    # Dieselbe Bedingung wie bei den Modellanbietern und aus demselben Grund:
    # Ein Eintrag, den niemand aufrufen kann, führt die Oberfläche in die Irre
    # — sie böte ein „Konto verbinden" an, das mit einem Fehler des Anbieters
    # endet, und der Nutzer sucht die Ursache bei sich.
    google_client_id: str = Field(default="", alias="GOOGLE_CLIENT_ID")
    google_client_secret: str = Field(default="", alias="GOOGLE_CLIENT_SECRET")
    google_redirect_uri: str = Field(
        default="http://localhost:8000/accounts/callback", alias="GOOGLE_REDIRECT_URI"
    )
    """Die Rückrufadresse, exakt wie beim Anbieter hinterlegt.

    Sie steht hier und wird nie aus einem Request übernommen — dieselbe
    Verankerung wie ``WEBAUTHN_ORIGINS``. Eine wählbare Rückrufadresse machte
    aus diesem Endpunkt einen offenen Weiterleiter und aus dem
    Autorisierungscode etwas, das man sich zuschicken lassen kann."""

    google_scopes: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "openid",
            "email",
            "https://www.googleapis.com/auth/calendar.events",
        ],
        alias="GOOGLE_SCOPES",
    )
    """Was gefragt wird. Was **bewilligt** ist, meldet der Anbieter zurück und
    steht in ``connected_accounts.granted_scopes`` — zwei Aussagen, und die
    zweite ist die verbindliche."""

    @model_validator(mode="after")
    def _kek_quelle_passt_zur_umgebung(self) -> Settings:
        """Der Datei-KEK ist Entwicklungssache (ADR-008 V1.1).

        Bei ``KEY_PROVIDER=file`` liegt der Schlüssel im Speicher desselben
        Prozesses, der HTTP annimmt — eine Schwachstelle im Web-Layer gäbe
        damit alle Postfach-Tokens preis. In Produktion entpackt eine eigene
        Instanz, und bis es sie gibt, **startet der Prozess dort gar nicht**.

        Beim Start und nicht beim ersten Zugriff: Eine Fehlkonfiguration soll
        auffallen, bevor jemand ihr Tokens anvertraut.
        """
        if self.env != "development" and self.key_provider == "file":
            raise ValueError(
                "KEY_PROVIDER=file ist nur in der Entwicklung zulässig (ADR-008 V1.1): "
                "Der KEK läge im Speicher des Prozesses, der HTTP annimmt. In Produktion "
                "gehört das Entpacken in eine eigene Instanz."
            )
        return self

    @property
    def cookie_secure(self) -> bool:
        """Außerhalb der Entwicklung nur über HTTPS.

        Als abgeleitete Eigenschaft statt als Schalter: Ein Feld
        ``COOKIE_SECURE=false`` in einer Produktionsumgebung wäre ein
        Einzeiler, den niemand bemerkt.
        """
        return self.env != "development"

    @field_validator(
        "webauthn_origins",
        "trusted_proxies",
        "files_allowed_roots",
        "cloud_zero_retention",
        "google_scopes",
        mode="before",
    )
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
