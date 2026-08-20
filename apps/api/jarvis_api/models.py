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

**Was hier steht, ist ehrlich klein.** Ein lokales Modell über Ollama. Das ist
das einzige, das wir tatsächlich haben; Anthropic und OpenAI fehlen noch. Ein
Katalog mit erfundenen Cloud-Modellen sähe reicher aus und führte das Routing
in die Irre: Es würde ein Modell wählen, das niemand aufrufen kann.

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
    return (
        ModelCapability(
            name=settings.ollama_model,
            provider="ollama",
            max_data_class=DataClass.P3,
            context_window=settings.ollama_context_window,
            p50_latency_ms=settings.ollama_p50_latency_ms,
            is_local=True,
        ),
    )
