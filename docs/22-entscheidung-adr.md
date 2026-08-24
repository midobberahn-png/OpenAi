# ADR-017: Einen unklaren Schritt löst sein Eigentümer auf

**Status:** angenommen · **Datum:** 24.08.2026 · **Ergänzt:** docs/04-orchestrator.md
(Wiederaufnahme), ADR-015 (Oberfläche)

---

## Zusammenhang

Die Wiederaufnahme kennt vier Urteile über einen beanspruchten Schritt. Drei
davon führen weiter; das vierte führt bewusst nirgendwohin:

```
Frist abgelaufen
        │
        ├─ Protokoll schließt Wirkung aus ──→ NEU_VERGEBBAR   → läuft weiter
        └─ Wirkung möglich ────────────────→ ENTSCHEIDUNG_NÖTIG
                                                   │
                                             Anspruch wird gehalten
                                                   │
                                              ← kein Ausgang →
```

Das Halten ist richtig: Ein Termin, der vielleicht im Kalender steht, darf
nicht von einem Automaten ein zweites Mal angelegt werden, und ihn freizugeben
öffnete den Schritt für den nächsten Anwärter. Nur gab es **keinen Übergang
heraus** — kein Endpunkt, keine Oberfläche, keine Entscheidung. Der Lauf stand
für immer.

Zwei Befunde kamen beim Bauen dazu, beide an derselben Stelle:

**Ein laufender Schritt sah aus wie ein hängender.** `take_over` fragte zuerst
das Protokoll und ging bei einer möglichen Wirkung sofort zurück — die
Datenbank kam gar nicht vor. Der Protokolleintrag entsteht aber *vor* dem
Handler, und `pending` ist nicht wiederholbar: Am Protokoll allein sind „läuft
gerade" und „ist mitten in der Wirkung abgestürzt" **nicht** zu unterscheiden.
Solange niemand auf das Urteil hin handelte, war das eine irreführende
Fehlermeldung. Mit einem Ausgang wäre es gefährlich geworden — die Oberfläche
böte „noch einmal versuchen" für einen Schritt an, der gerade in Ordnung läuft.

**Und die Frist wurde nie erneuert.** Wer nicht übernimmt, lässt `claimed_at`
alt stehen. Der Arbeiter fand denselben Lauf in jedem Durchgang wieder, urteilte
erneut und schrieb erneut `step-unresolved`. Im Minutentakt, dauerhaft.

## Entscheidung

**Die Frist entscheidet zuerst, dann das Protokoll.** `take_over` übernimmt den
Anspruch, *bevor* es urteilt: Ob überhaupt etwas hängt, beantwortet die
Datenbank in derselben Anweisung, die übernimmt — sie liest dieselbe Uhr, die
den Anspruch gesetzt hat. Übernehmen heißt dabei nicht wiederholen; der
Anspruch wird gehalten, gewirkt wird nichts.

**Der Befund wird persistiert** (`RunState.unresolved_step`) und nicht bei
Bedarf errechnet. Er entsteht ausschließlich nach einer erfolgreichen
Übernahme. Wer ihn sieht, weiß damit zweierlei: Die Frist *war* abgelaufen, und
der Anspruch daneben gehört uns.

**Genau drei Entscheidungen**, und ein Mensch trifft sie:

| Entscheidung | Übergang | Was sie **nicht** behauptet |
|---|---|---|
| Als erledigt verbuchen | Schritt abgeschlossen, Lauf läuft weiter | dass das System das Ergebnis kennt |
| Noch einmal versuchen | Anspruch frei, Schritt wieder fällig | dass der erste Versuch folgenlos war |
| Lauf abbrechen | `executing → cancelled` | dass etwas zurückgenommen wurde |

**Die Auflösung ist selbst eine Sicherheitsgrenze** (Invariante
`uncertain-effect-resolved-only-by-owner`): Eigentümer aus der Sitzung,
Vermerk vorhanden, Bindung an das **aktuelle** Fencing-Token, und die Prüfung
steht in derselben Anweisung, die schreibt.

## Begründung

**Warum ein Mensch und keine zweite Frist.** Der naheliegende Gegenentwurf ist,
nach hinreichend langer Zeit doch zu wiederholen. Er löst nichts: Die Unklarheit
wird durch Warten nicht kleiner, weil niemand nachsieht. Eine zweite Frist
verlegte die Entscheidung nur in eine Konfigurationsdatei — und träfe sie dann
für alle Fälle gleich, einschließlich derer, in denen der Termin längst steht.

**Warum drei benannte Entscheidungen und kein Zielstatus.** Ein
`POST /runs/{id}/resolve` mit frei gewähltem Status wäre der kürzere Entwurf und
die Abschaffung des Zustandsautomaten: Wer von außen einen Zielzustand nennen
darf, umgeht die Übergänge, die ihn tragen.

**Warum die Bindung an das aktuelle Token.** Läuft die Frist erneut ab,
übernimmt der nächste Durchgang den Schritt und vergibt ein **neues** Token. Die
Lage sieht danach gleich aus und ist eine andere. Ohne diese Bindung löste eine
Browserseite mit veraltetem Zustand einen Vorgang auf, den es so nicht mehr
gibt.

**Warum der Arbeiter vermerkte Läufe nicht mehr sucht.** Sonst greift er sie
nach jeder Frist erneut auf, urteilt dasselbe und vergibt dabei ein neues
Token — und entwertet genau die Seite, auf der die Entscheidung gerade gelesen
wird. Auflösen kann er sie ohnehin nicht.

## Was ein Mensch zu sehen bekommt — und was nicht

Die wichtigste Frage vor jeder dieser Entscheidungen ist nicht „was ist
passiert", sondern **„woran erkenne ich es"**. Die ehrliche Antwort heute:

* **Was gemeint war** — die Beschreibung aus dem Plan. Sie stammt aus der
  Absicht des Nutzers und ist damit das brauchbarste Stück: Wer „Zahnarzttermin
  Dienstag 14 Uhr" liest, weiß, wonach er im Kalender sucht.
* **Was versucht wurde** — Werkzeug, Zeitpunkt, Protokollzustand. **Nicht** die
  Argumente: Sie können Fremdinhalt tragen, und der Weg, Fremdinhalt einem
  Menschen zur Prüfung vorzulegen, ist die Vorschau (docs/10-ui.md §5) und
  nicht ein Nebenfeld in einer Statusansicht.
* **Was niemand weiß** — als Satz, über den Schaltflächen und nicht als
  Fußnote. Er kommt vom Server (`UnresolvedView.caveat`), damit ihn kein Client
  weglassen kann; eine Sprachausgabe muss denselben Vorbehalt nennen.

**Die Grenze ist ausdrücklich nicht behoben.** JARVIS kann nicht nachsehen: Es
gibt keinen lesenden Kalenderzugriff. Der Mensch prüft außerhalb, und die
Oberfläche sagt ihm das. Der benannte Ausweg ist ein **rücklesender Zugriff je
Werkzeug** — dieselbe Stelle, an der auch `ToolSpec.idempotent` und die
Rücknahme stehen. Solange es ihn nicht gibt, ist „als erledigt verbuchen" eine
Aussage des Menschen und wird auch so protokolliert: Die Zusammenfassung des
Schrittes sagt es, damit ein Modell im nächsten Schritt nicht mehr Gewissheit
unterstellt, als es gibt.

## Folgen

* `RunState.unresolved_step`; `RunStore.mark_unresolved` als bedingtes
  `UPDATE` gegen den gehaltenen Anspruch, in eigener Transaktion.
* `POST /runs/{run_id}/resolve` mit `decision` und `claim_id`;
  `GET /runs/{id}` führt `unresolved`, `GET /runs` das billige
  `needs_decision` (der Vermerk steht im ohnehin geladenen Zustand).
* Jede Entscheidung erzeugt einen Audit-Eintrag `run.step_resolved`. Sie ist
  der Punkt, an dem ein Mensch eine Sperre gegen doppelte Wirkung aufhebt; wer
  später fragt, warum ein Termin zweimal im Kalender steht, findet hier die
  Antwort.
* Der Protokolleintrag bleibt auf `effect_unknown`. Der Mensch hat entschieden,
  **wie es weitergeht**, und nicht, was geschehen ist — ein neuer Zustand
  trüge eine Gewissheit ein, die es nicht gibt.

## Verworfene Möglichkeiten

**Den Zustand ableiten statt speichern.** Spart ein Feld und ist nicht
möglich: Ein laufender und ein abgestürzter Schritt sehen im Protokoll gleich
aus, und die Frist rechnet die Datenbank. Ein Leser, der sie in Python
nachrechnet, liest eine zweite Uhr.

**Den Aufruf mit einem neuen Protokollzustand schließen** (`resolved`).
Verworfen, weil er behauptete, die Sache sei geklärt. Sie ist es nicht — die
Entscheidung ist geklärt.

**Die Entscheidung dem Arbeiter überlassen**, etwa anhand von
`ToolSpec.idempotent`. Das gibt es bereits, und zwar an der richtigen Stelle:
Ein idempotentes Werkzeug führt gar nicht erst hierher. Was übrig bleibt, ist
genau die Menge, für die kein Automat zuständig ist.

**Erst einen Kalender-Lesezugriff bauen und dann diesen Weg.** Reizvoll, weil
die Evidenz dann echt wäre. Verworfen, weil die Reihenfolge falsch ist: Die
Sackgasse existiert heute, der lesende Zugriff wäre ein eigener Block mit
eigener Policy-Frage — und `retry` und `abort` brauchen ihn nicht.

## Anschluss

Idempotency-Keys je Aufruf (Dossier §9) setzen genau hier an: Ein Schlüssel am
`ToolInvocation` macht aus „möglicherweise gewirkt" bei einem Provider, der ihn
unterstützt, ein „nachweislich einmal gewirkt". Der Weg dieses ADR bleibt
dabei bestehen — er ist die Antwort für alles, was **keinen** solchen Schlüssel
hat, und das ist heute jedes Werkzeug.
