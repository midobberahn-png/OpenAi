"""Scope-Katalog einspielen.

Die Standardbelegung entspricht docs/07-security-permissions.md §2. Sie ist
bewusst restriktiv: Was Außenwirkung hat, ist bestätigungspflichtig; was
irreversibel ist, muss aktiv eingeschaltet werden.

Idempotent — mehrfaches Ausführen aktualisiert Beschreibungen, überschreibt
aber keine vom Nutzer geänderten Berechtigungen.
"""

from __future__ import annotations

import asyncio
import os
import sys

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

# (name, beschreibung, standardmodus, risiko)
SCOPES: list[tuple[str, str, str, str]] = [
    # -- E-Mail ---------------------------------------------------------
    ("mail.read", "Postfach lesen und durchsuchen", "allow", "low"),
    ("mail.search", "Gezielt nach Nachrichten suchen", "allow", "low"),
    ("mail.draft", "Entwürfe verfassen (ohne Versand)", "allow", "low"),
    ("mail.send", "E-Mails versenden", "confirm", "high"),
    ("mail.delete", "Nachrichten löschen", "deny", "high"),
    # -- Kalender -------------------------------------------------------
    ("calendar.read", "Termine lesen", "allow", "low"),
    ("calendar.freebusy", "Freie Zeitfenster ermitteln", "allow", "low"),
    ("calendar.create", "Termine anlegen", "allow", "medium"),
    ("calendar.update", "Termine ändern", "allow", "medium"),
    ("calendar.delete", "Termine löschen", "confirm", "high"),
    # -- Aufgaben -------------------------------------------------------
    ("tasks.read", "Aufgaben lesen", "allow", "low"),
    ("tasks.write", "Aufgaben anlegen und ändern", "allow", "medium"),
    ("tasks.delete", "Aufgaben löschen", "confirm", "medium"),
    # -- Dateien --------------------------------------------------------
    ("files.read", "Dateien in freigegebenen Ordnern lesen", "allow", "low"),
    ("files.write", "Dateien in freigegebenen Ordnern schreiben", "confirm", "high"),
    ("files.delete", "Dateien löschen", "deny", "critical"),
    # -- Web ------------------------------------------------------------
    ("search.web", "Websuche durchführen", "allow", "low"),
    ("web.fetch", "Webseiten abrufen und auswerten", "allow", "low"),
    # -- Gedächtnis -----------------------------------------------------
    ("memory.read", "Gespeichertes Wissen abrufen", "allow", "low"),
    ("memory.write", "Neues Wissen speichern", "allow", "medium"),
    ("memory.delete", "Gespeichertes Wissen löschen", "confirm", "medium"),
    # -- Geräte ---------------------------------------------------------
    ("mic.access", "Mikrofon verwenden", "allow", "medium"),
    ("camera.access", "Kamera verwenden", "deny", "high"),
    ("camera.capture", "Einzelbild aufnehmen und auswerten", "deny", "high"),
    ("screen.capture", "Bildschirmfoto aufnehmen und auswerten", "deny", "high"),
    # -- System ---------------------------------------------------------
    ("shell.exec", "Shell-Befehle ausführen", "deny", "critical"),
    ("computer.control", "Maus und Tastatur steuern", "deny", "critical"),
    # -- Smart Home (Phase 8) -------------------------------------------
    ("smarthome.read", "Gerätezustände lesen", "confirm", "low"),
    ("smarthome.control", "Licht, Musik und Steckdosen schalten", "confirm", "medium"),
    ("smarthome.climate", "Heizung und Klima steuern", "confirm", "medium"),
    ("smarthome.security", "Schlösser, Tore und Alarmanlagen", "confirm", "high"),
    # -- Standort und Fahrzeug ------------------------------------------
    ("location.read", "Standort abrufen", "deny", "medium"),
    ("vehicle.read", "Fahrzeugdaten abrufen", "deny", "low"),
    # -- Finanzen (ausschließlich lesend) -------------------------------
    ("finance.read", "Kontostände und Umsätze lesen", "deny", "medium"),
    # Hinweis: Es gibt bewusst KEINEN Scope 'finance.transfer' o. ä.
    # Geldbewegungen sind nicht implementiert (docs/07-security §11).
]


UPSERT = text(
    """
    INSERT INTO scopes (name, description, default_mode, risk_level)
    VALUES (:name, :description, :default_mode, :risk_level)
    ON CONFLICT (name) DO UPDATE
      SET description  = EXCLUDED.description,
          default_mode = EXCLUDED.default_mode,
          risk_level   = EXCLUDED.risk_level
    """
)


async def main() -> int:
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("DATABASE_URL ist nicht gesetzt.", file=sys.stderr)
        return 1

    engine = create_async_engine(url)
    async with engine.begin() as conn:
        for name, description, mode, risk in SCOPES:
            await conn.execute(
                UPSERT,
                {
                    "name": name,
                    "description": description,
                    "default_mode": mode,
                    "risk_level": risk,
                },
            )
        count = (await conn.execute(text("SELECT count(*) FROM scopes"))).scalar_one()
    await engine.dispose()

    print(f"✓ {len(SCOPES)} Scopes eingespielt, {count} im Katalog.")

    deny = sum(1 for s in SCOPES if s[2] == "deny")
    confirm = sum(1 for s in SCOPES if s[2] == "confirm")
    allow = sum(1 for s in SCOPES if s[2] == "allow")
    print(f"  Standard: {allow}× erlauben, {confirm}× bestätigen, {deny}× verweigern")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
