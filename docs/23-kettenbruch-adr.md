# ADR-018: Ein Kettenbruch wird gefunden — und er hält den Arbeiter an

**Status:** angenommen · **Datum:** 25.08.2026 · **Ergänzt:**
docs/07-security-permissions.md §8 (Audit-Kette), ADR-016 (Ereignisstrom)

---

## Zusammenhang

Die Audit-Kette steht vollständig: Trigger, Hash-Verkettung, Port, Senke, und
seit `a67dd30` schreiben alle Wirkungspfade hinein. Die Invariante daneben
heißt `audit-tamper-evident` und lautet „Manipulation ist **erkennbar**".

Erkennbar ist sie. Erkannt wird sie von niemandem.

`verify()` hat genau einen Aufrufer: `GET /audit/verify`. Wer den Endpunkt nie
aufruft — und niemand ruft ihn auf, es gibt keine Oberfläche dafür und keinen
Anlass —, merkt einen Bruch nie. Das Dossier führt das seit dem Audit-Block als
offenen Punkt und stellt gleich die Frage mit, an der er hing:

> Was löst ein Fund aus, solange es keine Benachrichtigung gibt?

Diese Frage ist der eigentliche Inhalt dieses Dokuments. Eine Prüfung ohne
Folge ist die schwächere Fassung derselben Lücke: Sie verlagert das Nichtstun
von „niemand sieht nach" nach „niemand liest die Meldung". Das Projekt hat
diesen Fehler schon zweimal gemacht — 45 rote CI-Läufe, die nichts blockierten,
und ein Vertragsfeld (`zero_retention`), das kein Leser hatte.

## Entscheidung

### 1. Der Arbeiter prüft die Kette — ganz, in eigenem Takt

Der Prüfer sitzt im Arbeiter, weil dort schon eine Schleife läuft, die von
keiner Sitzung abhängt und einen Absturz überlebt. Er ist **kein** zweiter
Zweck des Laufdurchgangs, sondern hat einen eigenen Takt (Vorgabe: eine
Stunde, `JARVIS_AUDIT_INTERVAL`).

Zwei Takte statt einem, weil sie verschiedene Fragen beantworten: Der
Laufdurchgang fragt jede Minute „hängt etwas?" und liest dabei wenige Zeilen;
die Kettenprüfung liest die **ganze** Tabelle. Im Minutentakt wäre sie eine
wachsende Last für eine Frage, deren Antwort sich selten ändert.

Geprüft wird **ohne `limit`**. Ein Ausschnitt beantwortet „ist seit Eintrag N
etwas verändert worden?" — die Frage hier lautet „ist irgendetwas verändert
worden?", und nur die ganze Kette beantwortet sie. Der Docstring von
`PostgresAuditSink.verify()` sagt das seit dem Audit-Block; hier wird es
befolgt.

**Einmal sofort beim Start**, dann im Takt. Ein Bruch, der eine Stunde auf
seine erste Prüfung wartet, obwohl der Prozess gerade hochkam, wäre eine
selbst gewählte Verzögerung ohne Gegenwert.

### 2. Ein Fund hält den Arbeiter an

**Der Arbeiter wirkt nicht mehr.** Keine weiteren Laufdurchgänge, kein
`calendar.create`, kein `web.fetch`, nichts mit Außenwirkung.

Der Grund ist nicht die Kette, sondern das, was ein Bruch über den Zustand des
Systems aussagt. Der Trigger auf Datenbankebene lässt `UPDATE` und `DELETE`
nicht zu; ein Bruch heißt also, dass jemand **an der Anwendung vorbei** an der
Datenbank war. Wer das kann, kann auch Berechtigungen setzen, Läufe anlegen und
Bestätigungen fälschen. Ein Automat, der unter dieser Annahme weiter Werkzeuge
mit Außenwirkung ausführt, führt möglicherweise fremde Absichten aus — ohne
Zeugen, denn genau die Spur ist ja beschädigt.

Das ist dieselbe Haltung wie überall sonst im Sockel: **Der Schutz muss
folgenlos machen, nicht erkennen.** Eine Erkennung ohne Folge wäre hier nur die
Wiederholung des Fehlers, den dieses Dokument behebt.

**Er beendet sich nicht, er bleibt und prüft weiter.** Ein beendeter Prozess
sieht aus wie ein Absturz, wird von jedem Betriebssystem-Dienst neu gestartet
und wirkt danach wieder — der Halt wäre selbst nicht dauerhaft. Ein Arbeiter,
der läuft und nichts tut, ist außerdem der sichtbarere Zustand.

**Kein Schalter, der das abstellt.** Eine Umgebungsvariable, die den Halt
aufhebt, wäre die erste Zeile, die jemand setzt, wenn der Betrieb klemmt — und
zwar genau in dem Moment, in dem die Meldung ernst ist. Wer nach einem
untersuchten Fund weiterarbeiten will, startet den Prozess neu, nachdem die
Kette wieder stimmt.

### 3. Der Fund landet in der Kette, die er betrifft

Ein Bruch wird mit `ERROR` protokolliert **und** als Audit-Eintrag angefügt
(`actor="scheduler"`, `action="audit.chain-break"`, die betroffenen Zeilen-IDs
in `details`).

Das klingt zunächst verkehrt — in eine beschädigte Kette schreiben. Es ist
trotzdem richtig: Das Anfügen ist vom Prüfen unabhängig, der neue Eintrag
verkettet sich auf den *gespeicherten* letzten Hash, und wer den Fund später
entfernen will, bricht die Kette ein zweites Mal. Ein Logeintrag hat diese
Eigenschaft nicht; Logs rotieren, und wer die Datenbank manipulieren kann,
erreicht meist auch sie.

**Nur bei neuen Brüchen.** Solange dieselben Zeilen-IDs gefunden werden, wird
kein weiterer Eintrag geschrieben. Eine einzige Manipulation, die stündlich
einen Eintrag erzeugt, verwandelt das Audit-Log in ihr eigenes Rauschen — und
der Arbeiter ist ohnehin angehalten, es gibt nichts Neues zu melden.

## Was diese Entscheidung ausdrücklich **nicht** trifft

**Die HTTP-Schicht läuft weiter.** Ein Kettenbruch hält den Arbeiter an, nicht
die API. Das ist keine Inkonsequenz, sondern die Grenze dessen, was ohne
Benachrichtigungskanal verantwortbar ist: Der Arbeiter wirkt ohne Zeugen, und
sein Halt fällt niemandem zur Unzeit auf. Die API abzuschalten hieße, einem
Menschen mitten in der Arbeit den Dienst zu verweigern, **ohne ihm sagen zu
können, warum** — der Kanal dafür existiert nicht. Ein System, das sich
kommentarlos verweigert, wird umgangen, nicht untersucht.

Sobald es einen Weg gibt, einem angemeldeten Menschen einen Systemzustand zu
zeigen (Statusleiste, Ereignisstrom mit systemweitem Kanal), gehört diese
Entscheidung neu getroffen. Bis dahin steht sie hier als bewusste Hälfte und
nicht als Versehen.

**Keine Wiederherstellung.** Was mit einer gebrochenen Kette geschieht — Fund
untersuchen, Schnitt setzen, neu ansetzen —, ist eine Betriebsfrage und keine
Codeentscheidung. Sie wird gestellt, wenn sie zum ersten Mal ansteht.

## Folgen

* Neue Invariante `audit-chain-break-is-detected`: Ein Bruch wird ohne Zutun
  eines Menschen gefunden und hat eine Folge.
* `ChainWatch` in `jarvis_core.audit.watch` — die Entscheidung; die Schleife im
  Arbeiter enthält weiterhin keine.
* Der Prüfer braucht einen Port, der **liest und schreibt**: `verify`, `count`
  und `append`. Er bekommt ihn nicht als Erweiterung von `AuditSink` (den hält
  der Executor, und der soll nicht lesen können), sondern als eigenen,
  vollständigen Port `ChainInspector` — dieselbe Trennung wie beim Kalender,
  dessen Werkzeugseite kein `list_events` hat.
