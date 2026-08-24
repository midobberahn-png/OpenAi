# ADR-015: Die Oberfläche ist eine SPA mit Vite, nicht Next.js

**Status:** angenommen · **Datum:** 24.08.2026 · **Ersetzt:** die Werkzeugwahl in
docs/10-ui.md §4

---

## Zusammenhang

`docs/10-ui.md` nennt Next.js App Router, TanStack Query und
react-three-fiber. Das Dokument ist ein Gestaltungs- und Architekturentwurf und
hat diese Wahl nie begründet — sie stand da, weil sie für Webanwendungen
naheliegt.

Beim Anfangen stellte sich die Frage konkret: Dieses Repository hatte bis dahin
**kein** npm-Toolchain. Wer hier beginnt, entscheidet die Werkzeugkette für
Monate, und die Entscheidung gehört aufgeschrieben statt nebenbei getroffen.

## Entscheidung

**Vite + React + TypeScript als reine SPA**, gebaut nach `apps/web/dist` und von
der API selbst ausgeliefert (`jarvis_api.main._oberflaeche_ausliefern`).

Kein Next.js. Kein Server-Side Rendering. Vorerst kein TanStack Query.

## Begründung

**Ein Prozess weniger, und einer weniger ist hier viel.** Im Betrieb laufen
bereits zwei: die API und der Arbeiter, der hängengebliebene Läufe fortsetzt.
Next.js brächte einen dritten mit — einen Node-Server, der nichts täte, was die
API nicht kann. Server-Side Rendering hat hier keinen Adressaten: Das System
ist einzelnutzerfähig, läuft lokal, und hinter der Anmeldung gibt es nichts zu
indexieren und keine erste Bildschirmseite, auf die jemand wartet.

**Ein Origin.** Zwei Zusagen dieses Systems hängen an der Herkunft: das
Sitzungs-Cookie (`SameSite`) und die Passkey-Bindung (`rp_id`). Wenn die
Oberfläche aus derselben Quelle kommt wie die API, sind beide trivial richtig.
Bei getrennten Prozessen sind sie eine Konfigurationsfrage — und
Konfigurationsfragen werden falsch beantwortet.

**Kein TanStack Query, bis es einen Grund gibt.** Die Regel des Projekts lautet
„keine neuen Abstraktionen ohne zwingenden Grund". Für eine Liste, eine
Detailansicht und einen Dialog reichen `fetch` und `useState`. Sobald ein
Ereignisstrom kommt und Cache-Invalidierung eine echte Frage wird, ist die
Bibliothek die richtige Antwort — dann mit Begründung.

**Was das kostet.** Kein SSR-Weg, falls später doch jemand die Oberfläche
öffentlich stellen will; kein eingebautes Routing (der App Router hätte es
mitgebracht). Beides ist ersetzbar, solange die Oberfläche klein ist — und sie
soll klein bleiben.

## Folgen

* `apps/web` bekommt `package.json`, `tsconfig.json`, `vite.config.ts`.
* Der Entwicklungsserver spiegelt die API-Pfade auf `127.0.0.1:8000`, damit
  Cookie und Passkey auch in der Entwicklung einen Origin sehen.
* `make web` baut, `make e2e` prüft im Browser, `make gate` tut beides.
* docs/10-ui.md bleibt für Gestaltung, Zustände und den Bestätigungsdialog
  maßgeblich. Nur die Werkzeugwahl in §4 ist durch dieses ADR ersetzt.

## Verworfene Möglichkeiten

**Next.js wie dokumentiert.** Hätte die Vorlage eingehalten. Der Preis wäre ein
dritter Betriebsprozess und eine zweite Herkunft für Cookie und Passkey gewesen
— beides ohne Gegenwert, solange niemand SSR braucht.

**Eine Seite ohne Bau (Vanilla + ES-Module).** Wäre in Stunden bedienbar
gewesen und ohne npm ausgekommen. Scheitert an dem, was als Nächstes kommt:
Markdown ohne rohes HTML, Streaming, ein Bestätigungsdialog mit Zuständen. Das
in Vanilla zu halten wäre Wegwerfarbeit gewesen.
