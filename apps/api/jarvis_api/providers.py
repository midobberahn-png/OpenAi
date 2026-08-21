"""Die Anbieteradapter der Anwendung.

Dasselbe Muster wie ``tools.py`` und ``models.py``, und aus demselben Anlass:
``ModelGateway`` nimmt eine Zuordnung ``Anbietername → Adapter`` entgegen, und
gebaut hat sie bislang nur ``tests/fakes.py``. Der Adapter existierte, das
Gateway existierte, verbunden war beides nie — und deshalb hat der
Ollama-Adapter bis zu diesem Commit nie mit einem laufenden Ollama gesprochen.

**Warum die Zuordnung hier entsteht und nicht im Gateway.** Das Gateway
entscheidet über Zulässigkeit; welche Adapter es überhaupt gibt, ist eine Frage
des Deployments. Ein Gateway, das sich seine Anbieter selbst zusammensucht,
entschiede damit auch, welche es gibt — und die Zusage „P3 verlässt das Gerät
nicht" hinge daran, dass es dabei nichts Falsches findet.

**Ein Anbieter, und der Name ist bedeutungstragend.** Der Schlüssel ``"ollama"``
muss zu ``ModelCapability.provider`` in ``models.py`` passen; stimmt er nicht
überein, meldet das Gateway ``provider-missing`` und führt nichts aus. Das ist
der gewollte Ausgang: fail closed, nicht Rückfall auf irgendetwas Verfügbares.
"""

from __future__ import annotations

from jarvis_api.models import model_catalog
from jarvis_api.settings import Settings
from jarvis_core.ports.llm import LLMProvider
from jarvis_core.providers import ModelGateway
from jarvis_providers import OllamaProvider

__all__ = ["model_gateway", "provider_map"]


def provider_map(settings: Settings) -> dict[str, LLMProvider]:
    """Die Adapter, die dieser Prozess tatsächlich aufrufen kann.

    Ohne eigenen ``httpx``-Client: Der Adapter öffnet je Aufruf einen und
    schließt ihn wieder. Ein Pool wäre schneller und hinge am Event-Loop, der
    ihn erzeugt hat — derselbe Fallstrick wie bei Datenbank-Engine und
    Redis-Client, und für einen lokalen Dienst auf demselben Rechner ist der
    Gewinn den Modulzustand nicht wert.
    """
    return {"ollama": OllamaProvider(base_url=settings.ollama_url)}


def model_gateway(settings: Settings) -> ModelGateway:
    """Der einzige Weg zu einem Sprachmodell — mit Katalog und Adaptern.

    Katalog und Adapter kommen aus zwei Quellen und werden hier
    zusammengeführt. Der Katalog sagt, was ein Modell *darf*; die Zuordnung,
    ob es überhaupt erreichbar ist. Beides getrennt zu halten ist die
    Voraussetzung dafür, dass ein fehlender Adapter zu einer Abweisung führt
    und nicht zu einer stillen Ersatzwahl.
    """
    return ModelGateway(provider_map(settings), model_catalog(settings))
