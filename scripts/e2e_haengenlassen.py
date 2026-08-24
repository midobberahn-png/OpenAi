"""Lässt einen Lauf hängen — ausschließlich für Browsertests.

**Warum das nicht über die API geht, und warum das gut ist.** Der Zustand
„Schritt beansprucht, Wirkung unklar, Frist abgelaufen" entsteht durch einen
**Absturz** zwischen Anspruch und Abschluss. Es gibt keinen Endpunkt, der ihn
herstellt, und es soll keinen geben: Ein Weg, einen fremden Lauf von außen in
eine Sperre zu versetzen, wäre ein Denial-of-Service mit Ansage.

Ein Browsertest braucht ihn trotzdem, denn die Frage, die nur er beantwortet,
ist nicht „hält die Grenze" (das prüft die Integrationssuite), sondern **findet
ein Mensch den Weg heraus**. Ein Bildschirm, den niemand entdeckt, ist keine
Auflösung.

Dieses Skript stellt den Zustand deshalb genauso her, wie ein Absturz ihn
hinterlässt, und zwar in genau der Reihenfolge:

1. Der Schritt wird **beansprucht** (``claim_step``) — wie vor jeder Wirkung.
2. Das **Werkzeugprotokoll** bekommt einen Eintrag, der den Handler betreten
   hat und dessen Ausgang niemand kennt (``effect_unknown``). Er wird vor der
   Wirkung geschrieben; genau deshalb ist er im Absturzfall da.
3. Die **Frist altert** in der Datenbank (``now() - interval``) und nicht in
   Python — dieselbe Uhr, die auch über die Übernahme entscheidet.

Den Vermerk setzt danach niemand von Hand: Ihn schreibt die Wiederaufnahme,
sobald der nächste ``advance`` daran scheitert. Der Test löst ihn also selbst
aus, und damit prüft er den Weg und nicht die Abkürzung.

**Dieselben zwei Wächter wie beim Zurücksetzen** (``JARVIS_E2E_RESET=1`` und
``JARVIS_ENV=development``), und aus demselben Grund: Was außerhalb der
Anwendung liegt, kann in ihr nicht falsch konfiguriert werden.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

TERMIN = {
    "title": "Fokuszeit",
    "start": "2026-09-30T09:00:00+00:00",
    "end": "2026-09-30T10:00:00+00:00",
}


async def main(run_id: str, seq: int) -> int:
    if os.environ.get("JARVIS_E2E_RESET") != "1":
        print("Abgebrochen: JARVIS_E2E_RESET=1 fehlt.", file=sys.stderr)
        return 2
    umgebung = os.environ.get("JARVIS_ENV", "development")
    if umgebung != "development":
        print(f"Abgebrochen: JARVIS_ENV ist {umgebung!r}, nicht 'development'.", file=sys.stderr)
        return 2

    url = os.environ.get(
        "DATABASE_URL", "postgresql+asyncpg://jarvis:jarvis_dev@localhost:5432/jarvis"
    )
    engine = create_async_engine(url)
    try:
        from jarvis_api.db.run_store import PostgresRunStore

        speicher = PostgresRunStore(engine)
        lauf = await speicher.load(uuid.UUID(run_id))
        if lauf is None:
            print(f"Kein Lauf mit der ID {run_id}.", file=sys.stderr)
            return 1

        anspruch = await speicher.claim_step(lauf.id, seq, erwarteter_status=lauf.status)
        if anspruch is None:
            print("Der Schritt war bereits beansprucht.", file=sys.stderr)
            return 1

        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO tool_invocations (id, run_id, step_seq, tool_name, arguments, "
                    "risk_level, policy_decision, decision_reason, status, created_at) VALUES "
                    "(:i, :r, :s, 'calendar.create', CAST(:a AS jsonb), 'medium', 'allow', "
                    "'Browsertest', 'effect_unknown', now())"
                ),
                {"i": uuid.uuid4(), "r": lauf.id, "s": seq, "a": json.dumps(TERMIN)},
            )
            await conn.execute(
                text(
                    "UPDATE runs SET state = state || jsonb_build_object("
                    "  'claimed_at', to_jsonb(now() - interval '1 hour')"
                    ") WHERE id = :id"
                ),
                {"id": lauf.id},
            )
    finally:
        await engine.dispose()

    print(f"Lauf {run_id} hängt an Schritt {seq} — die Frist ist abgelaufen.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Aufruf: e2e_haengenlassen.py <run_id> [seq]", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(asyncio.run(main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 1)))
