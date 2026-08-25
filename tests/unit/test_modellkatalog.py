"""Der Modellkatalog — was dieses Deployment tatsächlich aufrufen kann.

Der Katalog ist die Antwort auf „welches Modell darf was sehen", und er ist
Konfiguration. Diese Suite hält zwei Dinge fest, die dabei leicht abrutschen:

* **Ein Eintrag ohne Adapter ist schlimmer als kein Eintrag.** Das Routing
  wählte ein Modell, und der Aufruf scheiterte danach — mit einer Meldung, die
  nach einem Fehler aussieht statt nach fehlender Konfiguration.
* **Eine Obergrenze entsteht nicht aus Bequemlichkeit.** Ein fremder Anbieter
  bekommt P1 nur, wenn eine Zero-Retention-Zusage hinterlegt ist; ohne sie
  bleibt es bei P0 (docs/00-uebersicht.md §8).
"""

from __future__ import annotations

import pytest

from jarvis_api.models import model_catalog
from jarvis_api.providers import provider_map
from jarvis_api.settings import Settings
from jarvis_contracts import DataClass

pytestmark = pytest.mark.security


PREISE_ANTHROPIC: dict[str, object] = {
    "ANTHROPIC_COST_PER_1M_IN": "2.70",
    "ANTHROPIC_COST_PER_1M_OUT": "13.50",
}
PREISE_OPENAI: dict[str, object] = {
    "OPENAI_COST_PER_1M_IN": "2.00",
    "OPENAI_COST_PER_1M_OUT": "8.00",
}
"""Beispielpreise in Euro je einer Million Tokens.

Erfunden und als solche kenntlich: Der Katalog liest sie aus der
Konfiguration, und dieser Test prüft die Mechanik, nicht die Preisliste eines
Anbieters."""


def _settings(**kw: object) -> Settings:
    """Konfiguration ohne Umgebung und ohne ``.env``.

    ``_env_file=None``: Sonst läse dieser Test die Datei des Entwicklers mit —
    und wäre grün oder rot, je nachdem, wer ihn ausführt.
    """
    grund: dict[str, object] = {
        "_env_file": None,
        "OLLAMA_MODEL": "llama3.1:8b",
    }
    grund.update(kw)
    return Settings(**grund)  # type: ignore[arg-type]


class TestWasImKatalogSteht:
    def test_ohne_konfiguration_gibt_es_nur_das_lokale_modell(self) -> None:
        katalog = model_catalog(_settings())

        assert [m.provider for m in katalog] == ["ollama"]
        assert katalog[0].is_local is True
        assert katalog[0].max_data_class is DataClass.P3

    def test_ein_schluessel_ohne_modellnamen_erzeugt_keinen_eintrag(self) -> None:
        """Und ein Modellname ohne Schlüssel ebenso wenig.

        Beides ist derselbe Fehler aus zwei Richtungen: ein Katalogeintrag, den
        niemand aufrufen kann.
        """
        nur_schluessel = model_catalog(_settings(ANTHROPIC_API_KEY="sk-test"))
        nur_name = model_catalog(_settings(ANTHROPIC_MODEL="claude-sonnet-5"))

        assert [m.provider for m in nur_schluessel] == ["ollama"]
        assert [m.provider for m in nur_name] == ["ollama"]

    def test_mit_schluessel_und_namen_steht_der_anbieter_drin(self) -> None:
        katalog = model_catalog(
            _settings(
                ANTHROPIC_API_KEY="sk-test",
                ANTHROPIC_MODEL="claude-sonnet-5",
                **PREISE_ANTHROPIC,
            )
        )

        eintrag = next(m for m in katalog if m.provider == "anthropic")
        assert eintrag.name == "claude-sonnet-5"
        assert eintrag.is_local is False
        assert eintrag.is_priced is True

    def test_ohne_zusage_bleibt_ein_fremder_anbieter_bei_p0(self) -> None:
        """Die Obergrenze ist keine Vorsicht, sondern die Tabelle."""
        katalog = model_catalog(
            _settings(OPENAI_API_KEY="sk-test", OPENAI_MODEL="gpt-test", **PREISE_OPENAI)
        )

        eintrag = next(m for m in katalog if m.provider == "openai")
        assert eintrag.max_data_class is DataClass.P0
        assert eintrag.zero_retention is False

    def test_ohne_preis_gibt_es_keinen_eintrag(self) -> None:
        """Die dritte Bedingung neben Schlüssel und Modellname.

        Ein Modell, dessen Kosten niemand kennt, macht aus der Kostengrenze
        eines Laufs eine Statistik: Der Tracker zählte bei jedem Aufruf null,
        und ``max_cost_eur`` schlüge nie an.
        """
        ohne_preis = model_catalog(_settings(OPENAI_API_KEY="sk-test", OPENAI_MODEL="gpt-test"))
        nur_eingabe = model_catalog(
            _settings(
                OPENAI_API_KEY="sk-test",
                OPENAI_MODEL="gpt-test",
                OPENAI_COST_PER_1M_IN="2.00",
            )
        )

        assert [m.provider for m in ohne_preis] == ["ollama"]
        assert [m.provider for m in nur_eingabe] == ["ollama"]

    def test_das_lokale_modell_braucht_keinen_preis(self) -> None:
        """Es kostet Strom, keine Rechnung. Ein erfundener Preis machte das
        Budget unschärfer statt ehrlicher."""
        katalog = model_catalog(_settings())

        assert katalog[0].is_local is True
        assert katalog[0].is_priced is False

    def test_mit_zusage_darf_er_p1(self) -> None:
        katalog = model_catalog(
            _settings(
                OPENAI_API_KEY="sk-test",
                OPENAI_MODEL="gpt-test",
                CLOUD_ZERO_RETENTION="openai",
                **PREISE_OPENAI,
            )
        )

        eintrag = next(m for m in katalog if m.provider == "openai")
        assert eintrag.max_data_class is DataClass.P1
        assert eintrag.zero_retention is True

    def test_die_zusage_gilt_nur_dem_genannten_anbieter(self) -> None:
        """Eine Zusage für einen Anbieter ist keine für den anderen."""
        katalog = model_catalog(
            _settings(
                OPENAI_API_KEY="sk-test",
                OPENAI_MODEL="gpt-test",
                ANTHROPIC_API_KEY="sk-test",
                ANTHROPIC_MODEL="claude-sonnet-5",
                CLOUD_ZERO_RETENTION="anthropic",
                **PREISE_OPENAI,
                **PREISE_ANTHROPIC,
            )
        )

        nach_anbieter = {m.provider: m for m in katalog}
        assert nach_anbieter["anthropic"].max_data_class is DataClass.P1
        assert nach_anbieter["openai"].max_data_class is DataClass.P0

    def test_kein_fremder_anbieter_fuehrt_je_p2_oder_p3(self) -> None:
        """Ein Strukturtest, weil genau diese Zeile beiläufig steigt.

        Die Prüfung im Model Gateway hängt nicht daran — sie steht dort gerade
        deshalb, weil der Katalog Konfiguration ist. Dieser Test hält fest,
        dass die Konfiguration es hier gar nicht erst anbietet.
        """
        katalog = model_catalog(
            _settings(
                OPENAI_API_KEY="sk-test",
                OPENAI_MODEL="gpt-test",
                ANTHROPIC_API_KEY="sk-test",
                ANTHROPIC_MODEL="claude-sonnet-5",
                CLOUD_ZERO_RETENTION="anthropic,openai",
                **PREISE_OPENAI,
                **PREISE_ANTHROPIC,
            )
        )

        for eintrag in katalog:
            if not eintrag.is_local:
                assert eintrag.max_data_class <= DataClass.P1, eintrag.name


class TestKatalogUndAdapter:
    def test_zu_jedem_eintrag_gibt_es_einen_adapter(self) -> None:
        """Die Bedingung steht zweimal geschrieben — hier wird sie gemessen.

        Wäre die Zuordnung enger als der Katalog, gäbe es ein Modell ohne
        Adapter: Das Routing wählte es, und das Gateway meldete danach
        ``provider-missing``.
        """
        settings = _settings(
            OPENAI_API_KEY="sk-test",
            OPENAI_MODEL="gpt-test",
            ANTHROPIC_API_KEY="sk-test",
            ANTHROPIC_MODEL="claude-sonnet-5",
            **PREISE_OPENAI,
            **PREISE_ANTHROPIC,
        )

        adapter = provider_map(settings)
        for eintrag in model_catalog(settings):
            assert eintrag.provider in adapter, eintrag.name

    def test_ohne_schluessel_wird_kein_adapter_eingerichtet(self) -> None:
        assert set(provider_map(_settings())) == {"ollama"}
