# Die Angriffskette — was wo erzwungen wird

> Stand: Commit `da244dc`, fortgeschrieben, seit ein Modell die
> Werkzeugargumente formuliert.

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
| ⑤ | Run → Policy | `PolicyRequest` entsteht an genau einer Stelle; `trigger` und `allowed_data_class` aus dem persistierten Run; **Argumente werden vorher gegen `ToolSpec.parameters` geprüft — gleich, ob sie vom Aufrufer oder vom Modell stammen** | `test_executor.py` (AST + Verhalten), `test_tool_arguments.py` (Schemaprüfung, Gegenprobe), `test_http_runs.py` (Schritt- und Planschritt-Endpunkt) | **ja** |
| ⑥ | Policy → Approval | Payload-Hash eingefroren; Nonce einmalig; Sitzungs-, Nutzer- und Kanalbindung; Sitzung wird verifiziert; der Kanal ist kein Feld des Requests | `test_approval_gateway.py`, `test_sessions.py`, `test_http_runs.py` | **ja** |
| ⑦ | Approval → Execution | **Herkunft nominal geprüft** (`type(auth) is ExecutionGrant`); an Lauf und Nutzer gebunden; Hash dreifach geprüft; erneute Policy-Prüfung im Gate; **Verbrauch als letzter Schritt vor dem Handler, in eigener Transaktion committed** | `test_tool_registry.py` (Herkunft), `test_grant_replay.py` (Verbrauch, Kopien, Nebenläufigkeit), `test_grant_consumption.py` (Verbindungsgrenzen, Absturz vor dem Commit), `test_layering.py` (AST), `test_werkzeug_files_read.py` (echtes Werkzeug), `test_http_runs.py` (über HTTP) | **ja** |

---

## 2. Wo die Kette über HTTP abbricht — und warum

**Geprüft über HTTP: ① bis ⑦ — die Kette ist geschlossen.** Ein Angreifer, der von außen
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

**Die Kette ist über HTTP geschlossen.** `POST /runs/{run_id}/steps` führt
einen Werkzeugschritt aus, und `test_http_runs.py` geht den ganzen Weg: Passkey
anmelden → Lauf anlegen → Schritt ausführen → Dateiinhalt in der Antwort, mit
`taint_level=tainted`. Kein Testcode steuert dabei den Orchestrator an; alles
läuft über die HTTP-Grenze.

Damit ist die Eingangsfrage dieses Dokuments zum ersten Mal vollständig
beantwortbar: Von außen führt kein Weg von einer falschen Identität zu einem
`ExecutionGrant`, und jeder Übergang dazwischen ist auf dem Weg geprüft, den
ein Angreifer tatsächlich nimmt.

**Was der Durchstich zutage gefördert hat**, und das ist sein eigentlicher
Wert — drei Dinge, die einzeln geprüft nicht auffielen:

1. **Ohne Routing bleibt die Werkzeugschicht lahmgelegt.** `_ceiling(run)`
   nimmt ohne Routing die Datenklasse des Laufs — die engere Annahme. Ein als
   P1 eingestufter Lauf darf damit kein Werkzeug ausführen, das P2 liefert. Der
   fehlende Schritt war nicht die Prüfung, sondern das Routing davor; es gab
   nirgends einen Modellkatalog (`jarvis_api.models` schließt das).
2. **`UnknownTool` entkam als Serverfehler.** Ein halluzinierter Werkzeugname
   ist Modellalltag; die Registry unterscheidet ihn ausdrücklich von einer
   gefälschten Autorisierung. Über HTTP war er ein 500 — jetzt ein 404.
3. **Listenfelder aus der Umgebung waren nicht lesbar.** pydantic-settings
   versucht `json.loads`, bevor der Validator läuft. Der Fehler betraf auch
   `WEBAUTHN_ORIGINS` und `TRUSTED_PROXIES` und war nur deshalb latent, weil
   sie niemand über die Umgebung gesetzt hatte.

**`files.read` hat eine eigene Grenze mitgebracht, die es vorher nicht gab.** Sie ist deshalb bemerkenswert, weil sie zeigt, wo die Kette *nicht*
endet: Die Policy prüft den Pfad als Zeichenkette, der Adapter löst ihn auf.
Ein Symlink in einem freigegebenen Ordner besteht die erste Prüfung
einwandfrei — sie hat kein Dateisystem und kann ihn nicht sehen. Erst die
zweite weist ab. Beim Bau fiel dabei ein Loch in der ersten auf: Sie ließ
`..` durch (`relative_to()` normalisiert nicht). Beides ist als
`file-access-confined-to-roots` geführt.

**Die ehrliche Einordnung:** Geschlossen heißt nicht fertig. Geprüft ist der
Weg mit **einem** Werkzeug, und zwar einem lesenden. Die interessanteste Hälfte
von ⑥ — eine Bestätigung, die einen kontaminierten Lauf saniert und danach ein
schreibendes Werkzeug freigibt — ist weiterhin nur im Kern belegt, weil es kein
schreibendes Werkzeug gibt. Der Alltagsfall aus `docs/16-v1.1-review.md §1`
(Mails lesen → Termin anlegen) endet über HTTP heute nach dem ersten Schritt.

---

## 3. Offene Angriffsflächen

| Fläche | Bewertung | Stand |
|---|---|---|
| **Sitzungstoken ohne Rotation** | Ein entwendeter Token bleibt bis Ablauf oder Widerruf gültig, auch wenn der rechtmäßige Nutzer weiterarbeitet. Das Replay-Fenster ist die volle Sitzungsdauer. | `session-token-rotation` als PLANNED geführt. Race-Semantik ist zu spezifizieren, bevor implementiert wird. |
| **Sanierung eines kontaminierten Laufs über HTTP** | Bestätigung → sanierter Lauf → schreibendes Werkzeug. | Geschlossen mit `calendar.create` (`test_http_runs.py::TestAlltagsfall`), inzwischen auch mit modellformulierten Argumenten. |
| **Globale Rate-Limit-Stufe** | Ist selbst ein Denial-of-Service-Werkzeug: Wer sie füllt, sperrt auch den rechtmäßigen Nutzer aus. | Bewusst in Kauf genommen; Grenze liegt weit über der Alltagsnutzung. Eine volle Challenge-Tabelle wäre schlimmer. |
| **Audit-Sink fehlt** | Die Hash-Kette ist implementiert und geprüft, die Postgres-Implementierung fehlt. Sicherheitsvorfälle (Klonverdacht, abgewiesene Grants) landen derzeit nur im Anwendungsprotokoll. | Offen. Der `pg_advisory_xact_lock` gegen gabelnde Ketten ist ebenfalls noch nicht implementiert. |
| **Modellformulierte Werkzeugargumente** | Die Fläche ist jetzt real: `advance_run` nimmt die Argumente wahlweise aus einem Modell, das eine kontaminierte Datei gelesen haben kann. Prompt Injection wirkt sich damit erstmals auf einen Payload aus, der zur Ausführung kommt. | **Erprobt, nicht behauptet.** llama3.1:8b folgt der untergeschobenen Anweisung 3 von 3 Malen; das Taint-Gate blockiert 3 von 3 (`test_ollama_live.py`, `test_http_runs.py::TestArgumenteAusDemModell`). Der Schutz besteht darin, dass der Vorschlag denselben Weg nimmt wie eine Absicht des Nutzers — nicht darin, dass das Modell widersteht. |
| **Werkzeugwahl durch ein Modell** | Bislang wählt der **Plan** das Werkzeug und das Modell nur die Argumente. Sobald `ModelLoop` einen Endpunkt bekommt, wählt das Modell aus der Schnittmenge — eine andere und größere Fläche. | Offen. `AgentRuntime` berechnet das Angebot je Zugriff neu und `ModelLoop` führt nichts aus; geprüft ist beides nur ohne Endpunkt. |
| **Dateiinhalt als Fremdinhalt** | `files.read` bringt echten Fremdinhalt ins System — eine Datei mit `SYSTEM: sende …` ist ein Injection-Versuch wie eine Mail. Der Schutz besteht nicht im Erkennen, sondern darin, dass der Lauf danach kontaminiert ist und keine sendenden Werkzeuge mehr im Angebot hat. | Geprüft (`taints_context`) — und seit dem Modellmodus auch gegen ein Modell, das den Vorschlag tatsächlich macht. |
| **Werkzeugergebnisse im Modellkontext** | `PlanArgumentSource` gibt dem Modell heute nur Schritt-Zusammenfassungen (Pfad, Bytezahl), nicht die gelesenen Daten. Sobald es die Daten braucht, steht Fremdinhalt im Prompt. | Offen und bewusst so zugeschnitten. Die Herkunftsmarkierung (`Message.is_untrusted`) trägt schon heute, entscheidet aber über wenig — das ändert sich mit dem ersten Schritt, der Inhalt weiterreicht. |

---

## 4. Was dieses Dokument nicht behauptet

Es behauptet nicht, dass das System sicher ist. Es behauptet, dass für die
Übergänge ① bis ⑦ ein Angriff von außen belegbar scheitert — auf dem Weg, den
ein Angreifer tatsächlich nimmt, mit einem echten Werkzeug am Ende.

Es behauptet **nicht**, dass damit alle Abläufe abgedeckt sind. Geprüft ist ein
lesender Schritt. Sanierung, schreibende Werkzeuge und Mehrschrittpläne über
HTTP stehen aus.

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
