# Die Angriffskette — was wo erzwungen wird

> Stand: Commit `316f9ce`, überarbeitet nach dem externen Review.

> **Nachtrag.** Ein externes Review hat Glied ⑦ praktisch falsifiziert, während
> es hier als gesichert geführt war. `ExecutionAuthorization` war ein
> `Protocol`; die Registry prüfte Hash, Lauf und Nutzer, aber nicht die
> Herkunft des Objekts. Ein `SimpleNamespace` mit passenden Attributen führte
> `mail.send` aus — ohne Policy Engine, ohne Approval Gateway, ohne Grant. Die
> Invariante `policy-single-entry-point` stand dabei auf ENFORCED.
>
> Behoben durch nominale Prüfung (`type(auth) is ExecutionGrant`). Die Lehre
> steht in Abschnitt 5: Eine Tabelle wie diese sagt, was geprüft *wird* — sie
> kann nicht sagen, ob die Prüfung das Richtige prüft.

Bis Punkt 9 bestand das System aus einzeln geprüften Komponenten. Die Frage,
die seitdem den Maßstab bildet, ist eine andere:

> **Lässt sich von außen ein Weg bauen, der eine falsche Identität in einen
> `ExecutionGrant` verwandelt?**

Dieses Dokument geht die Kette Glied für Glied durch. Für jeden Übergang steht,
**wodurch** er gesichert ist, **welcher Test** das belegt, und — die eigentliche
Aussage — **ob er über HTTP geprüft ist** oder nur im Kern.

Die letzte Spalte ist der Grund für dieses Dokument. Ein Übergang, der nur im
Testcode geprüft wird, ist nicht falsch abgesichert; er ist ungeprüft gegen
den Weg, den ein Angreifer tatsächlich nimmt.

---

## 1. Die Kette

```
untrusted HTTP → Auth → Session → Identity → Run → Policy → Approval → Execution
      ①          ②        ③         ④        ⑤       ⑥          ⑦
```

| # | Übergang | Erzwungen durch | Belegt in | Über HTTP? |
|---|---|---|---|---|
| ① | HTTP → Auth | Zweistufiges Rate-Limit; Origin- und RP-ID-Bindung; Challenge einmalig und zweckgebunden; keine Nutzerangabe in der Anmeldung | `test_http_auth.py`, `test_rate_limit.py`, `test_passkeys.py` | **ja** |
| ② | Auth → Session | Token nur einmal ausgegeben, in der DB nur als Hash; Doppelfrist (absolut + Leerlauf); Widerruf wirkt sofort | `test_sessions.py` (unit + integration) | **ja** |
| ③ | Session → Identity | `current_session` ist die einzige Quelle; kein Request-Modell führt `user_id`; jeder Endpunkt ist geschützt oder begründet öffentlich | `test_http_boundary.py` (AST), `test_http_auth.py` | **ja** |
| ④ | Identity → Run | `Run.user_id` stammt aus der Sitzung; ein fremder Lauf ist von einem nicht existierenden nicht unterscheidbar (404) | `test_http_runs.py` (Body mit fremder `user_id`, fremde `run_id`), `test_http_boundary.py` (AST), `test_e2e_identity_to_execution.py` | **ja** |
| ⑤ | Run → Policy | `PolicyRequest` entsteht an genau einer Stelle; `trigger` und `allowed_data_class` aus dem persistierten Run | `test_executor.py` (AST + Verhalten) | **nein** |
| ⑥ | Policy → Approval | Payload-Hash eingefroren; Nonce einmalig; Sitzungs-, Nutzer- und Kanalbindung; Sitzung wird verifiziert; der Kanal ist kein Feld des Requests | `test_approval_gateway.py`, `test_sessions.py`, `test_http_runs.py` (Antwort) | **halb** — die Antwort ja, die Anfrage nicht |
| ⑦ | Approval → Execution | **Herkunft nominal geprüft** (`type(auth) is ExecutionGrant`); an Lauf und Nutzer gebunden; Hash dreifach geprüft; erneute Policy-Prüfung im Gate; **Verbrauch als letzter Schritt vor dem Handler, in eigener Transaktion committed** | `test_tool_registry.py` (Herkunft), `test_grant_replay.py` (Verbrauch, Kopien, Nebenläufigkeit), `test_grant_consumption.py` (Verbindungsgrenzen, Absturz vor dem Commit), `test_layering.py` (AST), `test_e2e_identity_to_execution.py` | **nein** |

---

## 2. Wo die Kette über HTTP abbricht — und warum

**Geprüft über HTTP: ① bis ④, und ⑥ zur Hälfte.** Ein Angreifer, der von außen
kommt, scheitert belegbar an der Anmeldung, an der Sitzung, an der
Identitätsgrenze — und seit `POST /runs` auch daran, einen Lauf für ein fremdes
Konto anzulegen oder einen fremden zu lesen.

Mit ④ ist zugleich die Frage dazugekommen, die die Identitätsgrenze nicht
beantwortet. `current_session` sagt, **wer** fragt. Ob das angefragte Objekt
dem Fragenden gehört, ist eine zweite Prüfung, und sie ist der nächste kurze
Angriff nach `user_id` im Body: eine gültige eigene Sitzung und eine fremde
`run_id`. Sie liegt in genau einer Funktion je Ressource
(`resource-ownership-checked-once`), und ein Strukturtest hält fest, dass
daneben kein zweiter Ladeweg entsteht.

Die Antwort ist dabei **404 und nicht 403**. Ein 403 bestätigt die Existenz;
wer Kennungen durchprobiert, bekäme ein Orakel. Ein eigener Test vergleicht
deshalb die Antwort auf einen fremden Lauf mit der auf einen erfundenen — sie
müssen sich bis auf nichts decken.

**⑥ zur Hälfte:** Die *Antwort* auf eine Bestätigung läuft über HTTP
(`POST /actions/{id}/respond`) und ist dort geprüft — Nonce-Einmaligkeit,
fremde Bestätigung, falsche Nonce. Die *Anfrage* entsteht weiterhin nur im
Kern, weil sie aus einem Werkzeugschritt hervorgeht.

**Nur im Kern geprüft: ⑤ und ⑦.** Der Grund ist keine Nachlässigkeit, sondern
eine Abwesenheit, und sie ist inzwischen genauer benannt als „es fehlen
Endpunkte": **Es gibt keine einzige Werkzeug-Implementierung.** `build_registry()`
lebt in `tests/fakes.py`; der Katalog der Anwendung (`jarvis_api.tools`) ist
leer. Ein Ausführungsendpunkt hätte nichts auszuführen, und einer, der
Attrappen ausführt, prüft die Attrappe.

**Die ehrliche Einordnung:** Für ⑦ ist die Absicherung selbst vollständig und
adversarial geprüft — Payload-Mutation, TOCTOU, Replay, Cross-Run-Grant,
fremde Sitzung, Absturz vor dem Commit. Was fehlt, ist der Nachweis, dass eine
HTTP-Schicht diese Prüfungen auch tatsächlich *aufruft*, statt an ihnen vorbei
zu arbeiten. Genau dieser Fehler ist bei ③ schon einmal vorgekommen und wurde
dort durch einen Strukturtest geschlossen. Für ④ und ⑥ steht dieser Test jetzt;
für ⑦ steht er aus, solange es nichts auszuführen gibt.

---

## 3. Offene Angriffsflächen

| Fläche | Bewertung | Stand |
|---|---|---|
| **Sitzungstoken ohne Rotation** | Ein entwendeter Token bleibt bis Ablauf oder Widerruf gültig, auch wenn der rechtmäßige Nutzer weiterarbeitet. Das Replay-Fenster ist die volle Sitzungsdauer. | `session-token-rotation` als PLANNED geführt. Race-Semantik ist zu spezifizieren, bevor implementiert wird. |
| **HTTP-Grenze für ⑤/⑦** | Siehe oben. Kein bekannter Fehler, aber ein ungeprüfter Übergang. ④ und die Antwortseite von ⑥ sind seit `POST /runs` und `POST /actions/{id}/respond` geschlossen. | Offen, solange es keine Werkzeuge gibt — nicht mehr, weil Endpunkte fehlen. |
| **Globale Rate-Limit-Stufe** | Ist selbst ein Denial-of-Service-Werkzeug: Wer sie füllt, sperrt auch den rechtmäßigen Nutzer aus. | Bewusst in Kauf genommen; Grenze liegt weit über der Alltagsnutzung. Eine volle Challenge-Tabelle wäre schlimmer. |
| **Audit-Sink fehlt** | Die Hash-Kette ist implementiert und geprüft, die Postgres-Implementierung fehlt. Sicherheitsvorfälle (Klonverdacht, abgewiesene Grants) landen derzeit nur im Anwendungsprotokoll. | Offen. Der `pg_advisory_xact_lock` gegen gabelnde Ketten ist ebenfalls noch nicht implementiert. |
| **Keine Modellanbindung** | Die größte kommende Fläche: Prompt Injection, Tool-Call-Injection, unvertrauenswürdige Modellausgabe, P3-Abfluss. | Der Taint-Schutz ist dafür gebaut, aber noch nie gegen ein echtes Modell erprobt. |

---

## 4. Was dieses Dokument nicht behauptet

Es behauptet nicht, dass das System sicher ist. Es behauptet, dass für die
Übergänge ① bis ④ und für die Antwortseite von ⑥ ein Angriff von außen
belegbar scheitert, und benennt für ⑤ und ⑦, dass die Absicherung geprüft ist,
ihr Aufruf durch die HTTP-Schicht aber nicht.

Der Unterschied ist der Punkt. Eine Kennzahl von 44/45 sagt, wie viele
Eigenschaften erzwungen werden — nicht, ob sie auf dem Weg liegen, den ein
Angreifer nimmt.

---

## 5. Was ein solches Dokument nicht leisten kann

Der Bypass in Glied ⑦ stand in der Tabelle als gesichert, mit Verweis auf drei
Tests. Alle drei liefen grün. Sie prüften, dass ein Grant mit falschem Hash,
falschem Lauf oder falschem Nutzer abgewiesen wird — nur nicht, ob überhaupt
ein Grant vorliegt. Die Lücke war nicht, dass zu wenig geprüft wurde, sondern
dass die falsche Frage gestellt war.

Gefunden hat sie ein Prüfer mit dem Quelltext in der Hand, der eine eigene
Angriffsidee ausprobiert hat. Kein Test der Suite hätte darauf kommen können,
weil Tests nur Fragen beantworten, die jemand vorher gestellt hat.

Daraus folgt für dieses Dokument: Es ordnet, was geprüft wird. Es ersetzt
keinen Prüfer, der etwas versucht, woran niemand gedacht hat.

**Und die Spalte „über HTTP geprüft" ist nicht die einzige, die zu wenig
fragt.** Glied ⑦ stand nach der Behebung erneut als gesichert da, diesmal mit
Tests, die den Verbrauch über getrennte Datenbankverbindungen und unter
zehnfacher Nebenläufigkeit belegten. Sie waren richtig und trafen den
Angriff — nur committete jeder von ihnen am Blockende. Belegt war damit der
geordnete Ausgang.

Der ungeordnete fehlte: Handler wirkt nach außen, Prozess stirbt vor dem
Commit, PostgreSQL nimmt den Verbrauch zurück, der Seiteneffekt bleibt. Eine
Zeile in einer Tabelle kann „geprüft" sagen und dabei einen Ausgang meinen.
Zur Frage „liegt die Prüfung auf dem Weg des Angreifers?" gehört deshalb die
zweite: **„und gilt sie auch, wenn der Weg mittendrin abbricht?"**

---
