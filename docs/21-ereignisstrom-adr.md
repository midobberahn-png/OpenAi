# ADR-016: Der Ereignisstrom ist SSE, nicht WebSocket

**Status:** angenommen · **Datum:** 24.08.2026 · **Ersetzt:** die Wahl des
Transports in docs/10-ui.md §4

---

## Zusammenhang

Die Oberfläche pollt alle drei Sekunden. Das ist die ehrliche Fassung, solange
es nichts anderes gibt, und sie hat eine Eigenschaft, die man nicht wegreden
kann: Sie zeigt nicht den Moment, in dem etwas passiert. Bei einem System, das
auf eine Bestätigung wartet, ist das der Moment, auf den es ankommt.

`docs/10-ui.md` §4 nennt WebSocket, dazu „Nachrichten-Sequenznummern zur
Lückenerkennung" und „Nachladen verpasster Ereignisse". Die Anforderungen sind
richtig; die Wahl des Transports war nie begründet.

## Entscheidung

**Server-Sent Events** über `GET /events`, mit Redis Pub/Sub als Verteiler
zwischen den Prozessen. Kein WebSocket. **Keine Sequenznummern.**

## Begründung

**Der Rückkanal fehlt nicht — es gibt nichts zu senden.** Alles, was der Client
auslöst, ist eine Zustandsänderung mit Wirkung: einen Lauf starten, einen
Schritt anstoßen, bestätigen, zurücknehmen. Jede davon geht durch Policy
Engine, Bestätigung und Gate und braucht Statuscodes, Fehlermeldungen und
Wiederholbarkeit — also HTTP. Ein zweiter Weg für dieselben Absichten wäre
genau das, was `policy-single-entry-point` ausschließt: ein Kanal, an dessen
Ende jemand einen Aufruf ausführt, der nicht durch die Kette gegangen ist.

**Und der entscheidende Punkt ist die Anmeldung.** Die Sitzung liegt in einem
`HttpOnly`-Cookie; JavaScript kann sie nicht lesen, und das ist der Zweck.
`EventSource` schickt Cookies bei gleicher Herkunft mit — die Verbindung ist
angemeldet wie jeder andere Aufruf. Ein WebSocket-Handshake aus dem Browser
kann **keine** eigenen Header setzen: Wer ihn authentifizieren will, legt ein
Token in die URL (und damit in jedes Zugriffsprotokoll und jeden Proxy-Cache)
oder missbraucht das Subprotokoll-Feld dafür. Beides ist schlechter als das,
was hier bereits steht.

**Sequenznummern lösen ein Problem, das anders kleiner wird.** Sie dienen der
Lückenerkennung: Merken, dass etwas fehlt, und nachladen. Dieselbe Zusage gibt
es einfacher — **der Strom ist ein Hinweis und kein Zustand.** Jedes Ereignis
sagt nur „an diesem Lauf hat sich etwas geändert"; was sich geändert hat, holt
die Oberfläche über die API. Eine verpasste Nachricht kostet dann nichts außer
Latenz, und ein Wiederverbinden braucht keine Wiederherstellung.

Das ist auch die einzige Fassung, die zur Regel aus docs/10-ui.md §4 passt:
*Der Server ist die Quelle der Wahrheit; der Client hält keinen abgeleiteten
Zustand, den er selbst fortschreibt.* Ein Strom mit Sequenznummern und
Nachlademechanik ist ein Client, der Zustand fortschreibt — nur mit einem Netz
darunter.

**Redis Pub/Sub, weil die Prozesse getrennt sind.** Ein Lauf kann von der API
oder vom Arbeiter vorangebracht werden. Ein Ereignis im Arbeitsspeicher der API
erreicht den Arbeiter nicht und umgekehrt. Redis liegt ohnehin im Betrieb
(Zugriffsgrenzen) und trägt hier wieder nur flüchtigen Zustand: Geht er
verloren, verliert niemand Daten — die Oberfläche fällt auf Nachladen zurück.

## Folgen

* `RunEvent` im Vertrag, `EventBus` als Port, Redis-Adapter in `apps/api`.
* `GET /events` liefert den Strom des **angemeldeten** Nutzers. Der Kanal
  trägt seine Kennung; ein fremdes Ereignis erreicht ihn nicht.
* Die Oberfläche zeigt den Verbindungszustand und lädt bei jedem Ereignis
  nach. Fällt der Strom aus, bleibt das Nachladen im Takt — die Oberfläche
  wird langsamer, nicht falsch.
* Ohne Redis ist der Endpunkt nicht verfügbar (503), und die Oberfläche
  arbeitet weiter wie bisher.

## Verworfene Möglichkeiten

**WebSocket wie dokumentiert.** Bidirektional, gut unterstützt — und für die
Anmeldung schlechter, siehe oben. Für den Sprachkanal (Audio in beide
Richtungen, docs/08-voice.md) wird er trotzdem gebraucht; das ist ein anderer
Kanal mit anderen Anforderungen, und diese Entscheidung greift ihm nicht vor.

**Polling behalten.** Kostet nichts an Bauarbeit und bleibt als Rückfallebene
ohnehin bestehen. Was fehlt, ist der Moment: Eine Bestätigung, die drei
Sekunden später erscheint, ist bei einer Aktion mit Außenwirkung drei Sekunden
zu spät.

**Postgres `LISTEN/NOTIFY` statt Redis.** Wäre transaktional und käme ohne
zweite Infrastruktur aus — reizvoll, weil ein Ereignis dann genau dann
entsteht, wenn die Änderung committet. Verworfen, weil jede lauschende
Verbindung eine Datenbankverbindung dauerhaft belegt: Bei einem System, dessen
Ansprüche und Fristen an kurzen, eigenen Transaktionen hängen, ist der
Verbindungspool das Letzte, was man an offene Browserfenster binden will.
