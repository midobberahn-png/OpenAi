"""Der Modellkatalog der Anwendung.

Dasselbe Muster wie ``tools.py``, und aus demselben Anlass: ``ModelGateway``
und ``route()`` nehmen einen Katalog entgegen, aber niemand hat je einen
gebaut — außerhalb von ``tests/fakes.py``. Aufgefallen ist das beim ersten
Werkzeugschritt über HTTP, und zwar als Blockade:

Ohne Routing gilt als Obergrenze eines Laufs seine **eigene** Datenklasse
(``executor._ceiling``, „die engere Annahme"). Ein Lauf, dessen Eingabe als P1
eingestuft wurde, darf damit kein Werkzeug ausführen, das P2 liefert — also
kein ``files.read``. Das ist kein Fehler in der Prüfung, sondern die Folge
eines fehlenden Schritts: **Der Lauf muss geroutet werden, bevor Werkzeuge
laufen.** Erst die Routing-Entscheidung hält fest, was das tatsächlich gewählte
Modell verarbeiten darf, und erst dann ist die Obergrenze eine Aussage über die
Wirklichkeit statt eine Vorsichtsannahme.

**Was hier steht, ist genau das, was dieses Deployment aufrufen kann.** Das
lokale Modell über Ollama steht immer im Katalog; Anthropic und OpenAI stehen
darin **nur, wenn Schlüssel und Modellname konfiguriert sind**. Ein Katalog mit
erfundenen Cloud-Modellen sähe reicher aus und führte das Routing in die Irre:
Es würde ein Modell wählen, das niemand aufrufen kann.

Deshalb gibt es auch keinen Vorgabewert für die Modellnamen. Was es bei einem
Anbieter gerade gibt, weiß die Konfiguration und nicht dieses Repository — ein
geratener Name führte zu einem Katalogeintrag, der bei jedem Aufruf mit 404
scheitert, und zwar erst nach der Modellwahl.

**Und die Obergrenze eines fremden Anbieters ist nicht verhandelbar.** P0
immer, P1 nur mit hinterlegter Zero-Retention-Zusage, P2 gar nicht (die
Freigabe je Domäne aus docs/00-uebersicht.md §8 gibt es nicht), P3 nie. Was
hier gesetzt wird, ist die *Beschreibung*; durchgesetzt wird sie im Model
Gateway, weil dieser Katalog Konfiguration ist und ein Tippfehler keine Daten
außer Haus geben darf.

**Warum ein lokales Modell P3 führen darf.** ``max_data_class=P3`` ist keine
Großzügigkeit, sondern die Definition: P3 verlässt das Gerät nie — verarbeiten
darf es genau ein Modell, das das Gerät nicht verlässt. ``is_local=True`` ist
dabei die Eigenschaft, an der das Model Gateway die Zulassung festmacht, und
sie ist bewusst eine Aussage über das Deployment, nicht über die Konfiguration.
"""

from __future__ import annotations

from jarvis_api.settings import Settings
from jarvis_contracts import DataClass, ModelCapability

__all__ = ["model_catalog"]


def model_catalog(settings: Settings) -> tuple[ModelCapability, ...]:
    """Die Modelle, die dieses System tatsächlich aufrufen kann.

    Ein leerer Katalog wäre die andere denkbare Vorgabe und die schlechtere:
    ``route()`` wirft dann ``NoEligibleModel``, und jeder Lauf scheiterte an
    derselben Stelle mit einer Meldung, die nach einem Fehler aussieht statt
    nach fehlender Konfiguration.
    """
    katalog: list[ModelCapability] = [
        ModelCapability(
            name=settings.ollama_model,
            provider="ollama",
            max_data_class=DataClass.P3,
            context_window=settings.ollama_context_window,
            p50_latency_ms=settings.ollama_p50_latency_ms,
            is_local=True,
        )
    ]

    for anbieter, modell, fenster, latenz in (
        (
            "anthropic",
            settings.anthropic_model,
            settings.anthropic_context_window,
            settings.anthropic_p50_latency_ms,
        ),
        (
            "openai",
            settings.openai_model,
            settings.openai_context_window,
            settings.openai_p50_latency_ms,
        ),
    ):
        if not modell or not _schluessel(settings, anbieter):
            continue
        ohne_vorhaltung = anbieter in settings.cloud_zero_retention
        katalog.append(
            ModelCapability(
                name=modell,
                provider=anbieter,
                # Ohne Zusage bleibt es bei P0. Das ist keine Vorsicht, sondern
                # die Tabelle: P1 verlangt eine Zero-Retention-Vereinbarung.
                max_data_class=DataClass.P1 if ohne_vorhaltung else DataClass.P0,
                context_window=fenster,
                p50_latency_ms=latenz,
                zero_retention=ohne_vorhaltung,
                is_local=False,
            )
        )

    return tuple(katalog)


def _schluessel(settings: Settings, anbieter: str) -> str:
    """Der Schlüssel eines Anbieters — und sonst gibt dieses Modul keinen aus.

    Er wird hier **nur auf Anwesenheit** geprüft. Gebraucht wird er in
    ``providers.py``; ein Katalog, der Schlüssel weiterreichte, hätte einen
    Grund, sie zu kennen, den er nicht hat.
    """
    return {
        "anthropic": settings.anthropic_api_key,
        "openai": settings.openai_api_key,
    }.get(anbieter, "")
