"""Das Tagesbudget — sehen, bevor es greift.

Die Grenze wirkt in der Modellwahl: Ist sie erreicht, kommen nur noch Modelle
in Frage, die auf diesem Gerät laufen. Damit ist sie zwar eingehalten, aber
unsichtbar — und eine Kostengrenze, die man erst am veränderten Verhalten
bemerkt, erklärt sich nicht, sie fällt auf.

Deshalb dieser Endpunkt. Er beantwortet drei Fragen, die zusammengehören: Was
ist heute ausgegeben worden, wo liegt die Grenze, und ab wann zählt „heute"?
Die dritte steht mit in der Antwort, weil ein Tagesbudget ohne Zeitzone keine
Auskunft ist, sondern eine Vermutung.

**Ein Schreibweg fehlt mit Absicht.** Die Grenze ist Konfiguration des
Deployments, nicht eine Einstellung im Gespräch. Ein Endpunkt, über den sich
das eigene Kostenlimit anheben ließe, wäre kein Limit — er wäre eine Bitte.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from jarvis_api.deps import CurrentSession, Spend
from jarvis_api.settings import Settings, get_settings
from jarvis_contracts import DailySpend
from jarvis_core.clock import tagesbeginn

__all__ = ["router"]

router = APIRouter(prefix="/budget", tags=["budget"])


class BudgetView(BaseModel):
    """Der Tagesstand, wie ihn die Oberfläche zeigt."""

    spent_eur: Decimal
    limit_eur: Decimal
    since: datetime
    share: float
    """Anteil zwischen 0 und 1 — und darüber hinaus, wenn ein einzelner Lauf
    die Grenze gerissen hat. Gekappt wird nicht: „1.0" sähe aus wie eine
    Punktlandung."""

    warning: bool
    """Ab 80 %. Die Schwelle steht in docs/04-orchestrator.md §7."""

    exhausted: bool
    """Ab hier wählt der Router nur noch lokale Modelle."""


@router.get("", response_model=BudgetView)
async def read_budget(
    session: CurrentSession,
    spend: Spend,
    settings: Annotated[Settings, Depends(get_settings)],
) -> BudgetView:
    """Was heute ausgegeben wurde — der eigene Stand, nie ein fremder."""
    seit = tagesbeginn(settings.timezone)
    stand = DailySpend(
        spent_eur=await spend.spent_since(seit),
        limit_eur=settings.daily_budget_eur,
        since=seit,
    )
    return BudgetView(
        spent_eur=stand.spent_eur,
        limit_eur=stand.limit_eur,
        since=seit,
        share=stand.share,
        warning=stand.warning,
        exhausted=stand.exhausted,
    )
