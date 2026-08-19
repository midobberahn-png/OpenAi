"""Zugriffsgrenzen — zweistufig, weil eine Stufe umgehbar ist.

Der Auftrag kam aus dem Review, und der schwierigste Punkt darin ist der
dritte: *Das Limit darf sich nicht durch wechselnde Adressen umgehen lassen,
soweit diese nicht vertrauenswürdig sind.*

Genau das ist der Normalfall. Ohne vorgeschalteten, konfigurierten Proxy ist
``X-Forwarded-For`` ein frei erfundenes Feld — ein Limit, das allein daran
hängt, kostet einen Angreifer eine Zeile Code. Und selbst eine echte
Peer-Adresse ist bei IPv6 kein knappes Gut: Ein /64-Präfix umfasst mehr
Adressen, als das Limit je zählen könnte.

Deshalb zwei Stufen, die zusammen wirken:

* **je Client** — hält den einzelnen Absender auf, ist die feinere Bremse und
  trifft den Normalfall,
* **global je Route** — hält die *Wirkung* auf, unabhängig von der Zahl der
  Absender. Diese Stufe ist die eigentliche Antwort auf Punkt 3.

Der Preis der globalen Stufe ist ehrlich zu benennen: Sie ist selbst ein
Denial-of-Service-Werkzeug — wer sie füllt, sperrt auch den rechtmäßigen
Nutzer aus. Deshalb liegt sie hoch genug, dass sie im Alltag nie greift, und
sie gilt nur für die Zeremonie-Endpunkte, an denen ungebremster Zulauf
Datenbankzustand erzeugt. Ausgesperrt zu sein ist unangenehm; eine volle
Challenge-Tabelle ist es mehr.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["GLOBAL_CLIENT", "RateLimitDecision", "RateLimitPolicy", "RateLimitRule"]


GLOBAL_CLIENT = "*"
"""Kennung der globalen Stufe. Bewusst ein Zeichen, das keine Adresse sein
kann — sonst ließe sich die globale Stufe durch einen passend gewählten
Client-Wert fälschen."""


class RateLimitRule(BaseModel):
    """Ein Fenster: so viele Anfragen in so vielen Sekunden."""

    model_config = ConfigDict(frozen=True)

    limit: int = Field(gt=0)
    window_s: int = Field(gt=0)

    def __str__(self) -> str:
        return f"{self.limit}/{self.window_s}s"


@dataclass(frozen=True)
class RateLimitDecision:
    """Ergebnis einer Prüfung.

    ``retry_after_s`` geht als ``Retry-After`` an den Client. Das ist kein
    Zugeständnis an einen Angreifer: Er kennt die Fenstergröße ohnehin, sobald
    er zweimal misst — der rechtmäßige Nutzer dagegen weiß sonst nicht, ob er
    in zwei Sekunden oder zwei Stunden wieder darf.
    """

    allowed: bool
    scope: str
    rule: RateLimitRule
    remaining: int
    retry_after_s: int

    @property
    def blocked_globally(self) -> bool:
        return not self.allowed and self.scope.endswith(f":{GLOBAL_CLIENT}")


class RateLimitPolicy(BaseModel):
    """Regelwerk einer Route."""

    model_config = ConfigDict(frozen=True)

    name: str
    per_client: RateLimitRule
    per_route: RateLimitRule
    """Die globale Stufe. Muss deutlich über der Client-Stufe liegen, sonst
    ist sie im Alltag die wirksame Grenze und sperrt reguläre Nutzung aus."""

    def key(self, client: str) -> str:
        """Schlüssel des Zählers.

        Der Client-Anteil wird **nicht** normalisiert oder gekürzt: Was der
        Aufrufer als Kennung übergibt, ist bereits das Ergebnis seiner eigenen
        Vertrauensentscheidung (siehe ``client_identifier``). Eine zweite
        Deutung hier wäre eine zweite Wahrheit darüber, wer jemand ist.
        """
        return f"ratelimit:{self.name}:{client}"

    def rule_for(self, client: str) -> RateLimitRule:
        return self.per_route if client == GLOBAL_CLIENT else self.per_client


AUTH_CHALLENGE = RateLimitPolicy(
    name="auth.challenge",
    per_client=RateLimitRule(limit=10, window_s=60),
    per_route=RateLimitRule(limit=300, window_s=60),
)
"""Ausstellung von Challenges — der Endpunkt, der ohne Anmeldung
Datenbankzustand erzeugt. Zehn pro Minute decken jede reale Bedienung ab;
selbst ein hartnäckiger Nutzer schafft keine zehn Anmeldeversuche in einer
Minute."""

AUTH_FINISH = RateLimitPolicy(
    name="auth.finish",
    per_client=RateLimitRule(limit=20, window_s=60),
    per_route=RateLimitRule(limit=600, window_s=60),
)
"""Abschluss einer Zeremonie. Etwas großzügiger als die Ausstellung, weil ein
misslungener Anlauf am Authenticator (abgebrochene Biometrie, falscher
Schlüssel gewählt) legitim wiederholt wird."""

BOOTSTRAP = RateLimitPolicy(
    name="auth.bootstrap",
    per_client=RateLimitRule(limit=5, window_s=300),
    per_route=RateLimitRule(limit=20, window_s=300),
)
"""Erstinbetriebnahme. Gelingt genau einmal; wer sie oft versucht, sucht das
Zeitfenster, in dem das System noch niemandem gehört."""

REGISTRIERTE_POLICIES = (AUTH_CHALLENGE, AUTH_FINISH, BOOTSTRAP)
"""Getrennte Regeln je Zeremonie — Registrierung und Anmeldung teilen sich
keinen Zähler. Ein gemeinsamer Topf hieße, dass ein Angreifer über den einen
Weg den anderen sperrt."""
