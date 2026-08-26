# Scope-Katalog

> GENERIERT aus `scripts/seed.py` — nicht von Hand bearbeiten.

Standardbelegung nach Erstinstallation. Der Nutzer kann jeden Scope im
Permission Center ändern; diese Tabelle zeigt den Auslieferungszustand.

**35 Scopes** in 16 Domänen.

## `calendar`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `calendar.create` | Termine anlegen | erlauben | medium |
| `calendar.delete` | Termine löschen | **bestätigen** | high |
| `calendar.freebusy` | Freie Zeitfenster ermitteln | erlauben | low |
| `calendar.read` | Termine lesen | erlauben | low |
| `calendar.update` | Termine ändern | erlauben | medium |

## `camera`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `camera.access` | Kamera verwenden | **verweigern** | high |
| `camera.capture` | Einzelbild aufnehmen und auswerten | **verweigern** | high |

## `computer`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `computer.control` | Maus und Tastatur steuern | **verweigern** | critical |

## `files`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `files.delete` | Dateien löschen | **verweigern** | critical |
| `files.list` | Freigegebene Ordner auflisten | erlauben | low |
| `files.read` | Dateien in freigegebenen Ordnern lesen | erlauben | low |
| `files.write` | Dateien in freigegebenen Ordnern schreiben | **bestätigen** | high |

## `finance`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `finance.read` | Kontostände und Umsätze lesen | **verweigern** | medium |

## `location`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `location.read` | Standort abrufen | **verweigern** | medium |

## `mail`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `mail.delete` | Nachrichten löschen | **verweigern** | high |
| `mail.draft` | Entwürfe verfassen (ohne Versand) | erlauben | low |
| `mail.read` | Postfach lesen und durchsuchen | erlauben | low |
| `mail.search` | Gezielt nach Nachrichten suchen | erlauben | low |
| `mail.send` | E-Mails versenden | **bestätigen** | high |

## `memory`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `memory.delete` | Gespeichertes Wissen löschen | **bestätigen** | medium |
| `memory.read` | Gespeichertes Wissen abrufen | erlauben | low |
| `memory.write` | Neues Wissen speichern | erlauben | medium |

## `mic`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `mic.access` | Mikrofon verwenden | erlauben | medium |

## `screen`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `screen.capture` | Bildschirmfoto aufnehmen und auswerten | **verweigern** | high |

## `search`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `search.web` | Websuche durchführen | erlauben | low |

## `shell`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `shell.exec` | Shell-Befehle ausführen | **verweigern** | critical |

## `smarthome`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `smarthome.climate` | Heizung und Klima steuern | **bestätigen** | medium |
| `smarthome.control` | Licht, Musik und Steckdosen schalten | **bestätigen** | medium |
| `smarthome.read` | Gerätezustände lesen | **bestätigen** | low |
| `smarthome.security` | Schlösser, Tore und Alarmanlagen | **bestätigen** | high |

## `tasks`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `tasks.delete` | Aufgaben löschen | **bestätigen** | medium |
| `tasks.read` | Aufgaben lesen | erlauben | low |
| `tasks.write` | Aufgaben anlegen und ändern | erlauben | medium |

## `vehicle`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `vehicle.read` | Fahrzeugdaten abrufen | **verweigern** | low |

## `web`

| Scope | Beschreibung | Standard | Risiko |
|---|---|---|---|
| `web.fetch` | Webseiten abrufen und auswerten | erlauben | low |

## Bewusst nicht vorhanden

Diese Grenzen sind keine Konfiguration, sondern Abwesenheit von
Implementierung — die belastbarste Form der Zusicherung:

- **Geldbewegungen** — kein `finance.transfer` o. ä. existiert.
- **Vertragsabschlüsse** — keine Signatur- oder Bestell-Werkzeuge.
- **Rechteerweiterung durch JARVIS selbst** — `permissions.*` ist für
  Werkzeuge nicht erreichbar.
