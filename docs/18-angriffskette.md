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
| ④ | Identity → Run | `Run.user_id` stammt aus der Sitzung | `test_e2e_identity_to_execution.py` | **nein** |
| ⑤ | Run → Policy | `PolicyRequest` entsteht an genau einer Stelle; `trigger` und `allowed_data_class` aus dem persistierten Run | `test_executor.py` (AST + Verhalten) | **nein** |
| ⑥ | Policy → Approval | Payload-Hash eingefroren; Nonce einmalig; Sitzungs-, Nutzer- und Kanalbindung; Sitzung wird verifiziert | `test_approval_gateway.py`, `test_sessions.py` | **nein** |
| ⑦ | Approval → Execution | Grant nur aus dem Gateway; an Lauf und Nutzer gebunden; Hash dreifach geprüft; erneute Policy-Prüfung im Gate | `test_layering.py` (AST), `test_tool_registry.py`, `test_e2e_identity_to_execution.py` | **nein** |

---

## 2. Wo die Kette über HTTP abbricht — und warum

**Geprüft über HTTP: ① bis ③.** Ein Angreifer, der von außen kommt, scheitert
belegbar an der Anmeldung, an der Sitzung und an der Identitätsgrenze. Für
diesen Teil ist die Eingangsfrage beantwortet.

**Nur im Kern geprüft: ④ bis ⑦.** Der Grund ist keine Nachlässigkeit, sondern
eine Abwesenheit: **Es gibt keine HTTP-Endpunkte für Läufe und keinen für
Bestätigungen.** Der Durchstichtest steuert den Orchestrator deshalb im
Testcode an — mit der Identität aus einer echten, über HTTP erlangten Sitzung,
aber ohne den HTTP-Weg dorthin.

Zwei Endpunkte fehlen konkret:

| Fehlender Endpunkt | Was er schließen würde | Warum er noch nicht existiert |
|---|---|---|
| `POST /runs` | ④ und ⑤: Ein Lauf entsteht über HTTP, seine `user_id` aus der Sitzung | Es gibt noch kein Sprachmodell — ein Lauf hätte nichts zu tun. Ein Endpunkt, der nur Attrappen ausführt, prüft die Attrappe. |
| `POST /actions/{id}/respond` | ⑥: Die Bestätigung, die heute nur im Kern aufgerufen wird | Ohne Läufe entstehen keine Bestätigungen im Betrieb. Der Endpunkt wäre baubar und testbar, aber ohne Erzeuger halb. |

**Die ehrliche Einordnung:** Für ⑥ und ⑦ ist die Absicherung selbst
vollständig und adversarial geprüft — Payload-Mutation, TOCTOU, Replay,
Cross-Run-Grant, fremde Sitzung. Was fehlt, ist der Nachweis, dass die
HTTP-Schicht diese Prüfungen auch tatsächlich *aufruft*, statt an ihnen vorbei
zu arbeiten. Genau dieser Fehler ist bei ③ schon einmal vorgekommen und wurde
dort durch einen Strukturtest geschlossen; für ⑥ und ⑦ steht der entsprechende
Test noch aus.

---

## 3. Offene Angriffsflächen

| Fläche | Bewertung | Stand |
|---|---|---|
| **Sitzungstoken ohne Rotation** | Ein entwendeter Token bleibt bis Ablauf oder Widerruf gültig, auch wenn der rechtmäßige Nutzer weiterarbeitet. Das Replay-Fenster ist die volle Sitzungsdauer. | `session-token-rotation` als PLANNED geführt. Race-Semantik ist zu spezifizieren, bevor implementiert wird. |
| **HTTP-Grenze für ⑥/⑦** | Siehe oben. Kein bekannter Fehler, aber ein ungeprüfter Übergang. | Offen bis zu den Endpunkten. |
| **Globale Rate-Limit-Stufe** | Ist selbst ein Denial-of-Service-Werkzeug: Wer sie füllt, sperrt auch den rechtmäßigen Nutzer aus. | Bewusst in Kauf genommen; Grenze liegt weit über der Alltagsnutzung. Eine volle Challenge-Tabelle wäre schlimmer. |
| **Audit-Sink fehlt** | Die Hash-Kette ist implementiert und geprüft, die Postgres-Implementierung fehlt. Sicherheitsvorfälle (Klonverdacht, abgewiesene Grants) landen derzeit nur im Anwendungsprotokoll. | Offen. Der `pg_advisory_xact_lock` gegen gabelnde Ketten ist ebenfalls noch nicht implementiert. |
| **Keine Modellanbindung** | Die größte kommende Fläche: Prompt Injection, Tool-Call-Injection, unvertrauenswürdige Modellausgabe, P3-Abfluss. | Der Taint-Schutz ist dafür gebaut, aber noch nie gegen ein echtes Modell erprobt. |

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

---

## 4. Was dieses Dokument nicht behauptet

Es behauptet nicht, dass das System sicher ist. Es behauptet, dass für die
Übergänge ① bis ③ ein Angriff von außen belegbar scheitert, und benennt für
④ bis ⑦, dass die Absicherung geprüft ist, ihr Aufruf durch die HTTP-Schicht
aber nicht.

Der Unterschied ist der Punkt. Eine Kennzahl von 38/39 sagt, wie viele
Eigenschaften erzwungen werden — nicht, ob sie auf dem Weg liegen, den ein
Angreifer nimmt.
