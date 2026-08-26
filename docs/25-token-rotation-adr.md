# ADR-020: Token-Rotation — und was bei zwei gleichzeitigen Anfragen gilt

**Status:** angenommen · **Datum:** 26.08.2026 · **Ergänzt:** ADR-007
(Authentifizierung, Nachtrag „Offen"), docs/07-security-permissions.md §2

---

## Zusammenhang

`session-token-rotation` ist die einzige Invariante des Sicherheitskerns, die
seit dem ersten Entwurf auf `PLANNED` steht — und sie steht dort mit Begründung:

> Ein gestohlener Token bleibt bis zum Ablauf gültig, auch wenn der rechtmäßige
> Nutzer weiterarbeitet. Sie wird trotzdem nicht schnell implementiert: Zwei
> gleichzeitige Anfragen mit demselben Token dürfen nicht dazu führen, dass eine
> davon abgemeldet wird.

Das ist keine Zurückhaltung aus Bequemlichkeit. Rotation ohne Sorgfalt ist
schlechter als keine: Sie meldet Menschen zufällig ab, und wer das erlebt, baut
sich einen Weg daran vorbei — dann ist die Sitzung *und* das Vertrauen weg.

Was heute trägt: die Doppelfrist (14 Tage absolut, 12 Stunden Leerlauf) und der
sofort wirksame Widerruf. Was fehlt: **Entwertung durch Benutzung.** Ein
Angreifer mit einer Kopie des Cookies arbeitet zwei Wochen lang mit, ohne dass
das rechtmäßige Weiterarbeiten daran etwas ändert.

## Entscheidung

### 1. Rotiert wird bei Benutzung, aber nicht bei jeder

Ein Token wird ersetzt, wenn er älter ist als `ROTATION_INTERVAL` (Vorgabe: 15
Minuten). Nicht bei jedem Aufruf.

Der Schutz bleibt derselbe: Wer eine Kopie hat, verliert sie, sobald der
rechtmäßige Nutzer wieder arbeitet — spätestens nach einer Viertelstunde. Was
sich ändert, ist die Anzahl der Wettläufe. Diese Oberfläche stellt pro Minute
mehrere Anfragen gleichzeitig (Laufdetail alle 3 Sekunden, Laufliste alle 10,
dazu ein dauerhaft offener Ereignisstrom). Bei Rotation *je Aufruf* wäre jeder
dieser Takte ein Wettlauf; bei 15 Minuten sind es wenige am Tag.

**Die Zahl ist eine Abwägung und keine Ableitung.** Wer sie kleiner dreht,
verkürzt das Zeitfenster eines Diebs und erhöht die Zahl der Wettläufe; beides
ist gedeckt, weil der Wettlauf selbst gelöst ist (Punkt 3). Wer sie auf null
dreht, bekommt Rotation je Aufruf — und die kostet bei einem offenen
Ereignisstrom mehr, als sie einbringt.

### 2. Das Überlappungsfenster: der alte Token gilt kurz weiter

Nach einer Rotation bleibt der vorige Token für `OVERLAP` (Vorgabe: 60
Sekunden) gültig. Genau das ist die Antwort auf „zufällige Abmeldungen": Eine
Anfrage, die zum Zeitpunkt der Rotation bereits unterwegs war, trägt den alten
Token und darf nicht scheitern.

Gespeichert wird dafür **ein** Vorgänger, keine Kette. Zwei Rotationen
innerhalb von 60 Sekunden kommen bei einem Takt von 15 Minuten nicht vor; eine
Kette wäre Vorrat für einen Fall, den die erste Entscheidung ausschließt.

### 3. Genau einer rotiert — und die Datenbank entscheidet, wer

```sql
UPDATE sessions
   SET token_hash = :neu, prev_token_hash = :alt, rotated_at = now()
 WHERE id = :id AND token_hash = :alt
RETURNING id
```

Die Bedingung auf den **aktuellen** Hash macht daraus ein Vergleiche-und-setze.
Zwei gleichzeitige Anfragen mit demselben Token: Eine trifft die Zeile und
bekommt den neuen Token in ihre Antwort, die andere trifft null Zeilen — und
arbeitet mit dem alten weiter, der im Überlappungsfenster gilt. **Niemand wird
abgemeldet.**

Das ist dieselbe Bauart wie beim Schrittanspruch: Die Einmaligkeit entsteht in
der Anweisung, die auch schreibt, nicht in einer Prüfung davor. Wer zuerst
liest und dann schreibt, hat zwischen beidem ein Fenster — und in diesem
Projekt sind an genau dieser Grenze bereits zwei Lücken entstanden.

### 4. Rotiert wird nur, wohin der Ersatz zurückkann

Ein Token wird ersetzt, wenn die Antwort ein Cookie setzen kann. Wer den Token
als `Authorization: Bearer` vorlegt, bekommt keinen Ersatz — es gibt keinen
Kanal, über den er ihn erhielte, und ein Ersatz, der den Aufrufer nicht
erreicht, ist eine Abmeldung mit Ansage.

**Damit ist eine Lücke benannt, die nicht übersehen werden darf:** Wer ein
gestohlenes Cookie als Bearer-Kopfzeile vorlegt, entgeht der Rotation. Sie
schützt deshalb den *rechtmäßigen* Nutzer — seine Arbeit entwertet die Kopie —
und nicht gegen einen Dieb, der sich still verhält. Das ist die ehrliche
Reichweite dieser Maßnahme, und sie ändert nichts daran, dass sie sich lohnt:
Der stille Dieb verliert seinen Zugang, sobald der Nutzer arbeitet.

### 5. Der alte Token nach dem Fenster ist ein Fund

Wer einen ersetzten Token vorlegt, **nachdem** die Überlappung abgelaufen ist,
bekommt kein bloßes „nicht angemeldet": Die Sitzung wird widerrufen, und der
Vorgang steht in der Audit-Kette (`action="session.token-reuse"`).

Die Begründung ist die Wiederverwendungserkennung, wie sie für rotierende
Tokens Stand der Technik ist: Nach der Überlappung hat der rechtmäßige Client
längst gewechselt — sein Cookie *ist* der neue. Ein alter Token, der danach
auftaucht, ist eine **Kopie**, und wer eine Kopie benutzt, soll damit nicht
weiterkommen, sondern auffallen.

Der Preis ist eine Abmeldung im Fehlalarm. Er ist tragbar, weil die Antwort
darauf eine Anmeldung mit Passkey ist — und weil ein System, das eine
nachweisliche Kopie durchwinkt, seine eigene Zusage aufgibt.

### 6. Nicht rotiert wird im Ereignisstrom

`GET /events` hält eine Antwort über Stunden offen. Eine Rotation dort ersetzte
den Token in einem Kanal, der ihn nicht mehr aktualisiert bekommt, und ließe
die übrigen Anfragen des Browsers mit dem alten stehen. Der Strom prüft die
Sitzung wie bisher und rührt sie nicht an.

## Was diese Entscheidung ausdrücklich **nicht** trifft

**Keine Rotation der Sitzungs-ID.** Ersetzt wird das Geheimnis, nicht die
Identität der Sitzung. `session_id` ist die Bindung, an der Bestätigungen
hängen (`approval-channel-bound`) — sie zu wechseln hieße, offene Anfragen
unbedienbar zu machen.

**Keine Verlängerung der absoluten Frist.** Eine Rotation setzt `expires_at`
nicht neu. Andernfalls hielte sich eine benutzte Sitzung selbst unbegrenzt am
Leben — dieselbe Überlegung, aus der `touch()` schon heute nur den Leerlauf
verschiebt.

## Folgen

* Zwei Spalten in `sessions`: `prev_token_hash` und `rotated_at`.
* `session-token-rotation` wird von `PLANNED` auf `ENFORCED` gehoben — mit
  Tests, die den Wettlauf nachstellen und nicht nur den Normalfall.
* Der Fund aus Punkt 5 braucht einen Eintrag in der Audit-Kette und ist damit
  der erste Fall, in dem die Anmeldeschicht dorthin schreibt.
