# Fremdprojekte — was wir übernehmen und was nicht

> Stand: 20.08.2026. Geprüft wurden zwei öffentliche Projekte namens „JARVIS".
> Dieses Dokument hält fest, **was dort besser gelöst ist**, **was bei uns
> strenger ist** und **was beim Bau welcher Komponente nachzuschlagen lohnt**.

Der Zweck ist ausdrücklich nicht Vollständigkeit, sondern Entscheidbarkeit: Bei
jedem künftigen Baustein soll hier stehen, ob es Vorarbeit gibt, die einen Blick
wert ist — und ob deren Lizenz eine Übernahme zulässt.

---

## 1. Die beiden Projekte

| | microsoft/JARVIS | open-jarvis/OpenJarvis |
|---|---|---|
| Lizenz | **MIT** | **Apache 2.0** |
| Umfang | 20 Python-Dateien | 668 Dateien, ~166.000 Zeilen, 650 Testdateien |
| Letzter Commit | Juli 2025 | laufend gepflegt |
| Was es ist | HuggingGPT: ein LLM orchestriert HuggingFace-Modelle | Local-first-Framework für persönliche KI, Stanford, mit Paper |
| Relevanz für uns | **gering** | **hoch** |

**Beide Lizenzen sind permissiv.** Kein Copyleft, keine Ansteckungsgefahr für
unser Repository. Übernahme von Quelltext wäre mit Namensnennung zulässig —
bislang haben wir davon keinen Gebrauch gemacht und nur Ideen aufgegriffen.

**microsoft/JARVIS** teilt mit uns nur den Namen. Es ist ein
Forschungsprototyp zur Modellorchestrierung: kein Berechtigungssystem, kein
Gedächtnis, kein Assistent. Für unseren Fahrplan ohne Ertrag.

**OpenJarvis** verfolgt dieselbe Grundthese wie wir — persönliche KI, die
lokal läuft und die Cloud nur ruft, wenn es nötig ist. Es ist breiter als wir
(Sprache, Konnektoren, Desktop-App, Evaluationen) und an der entscheidenden
Stelle weniger streng.

---

## 2. Der direkte Vergleich: Dateizugriff

Beide Projekte haben ein lesendes Dateiwerkzeug. Der Vergleich ist deshalb
belastbar und war der Anlass für zwei Änderungen bei uns.

### Wo wir strenger sind

| Punkt | OpenJarvis | Wir |
|---|---|---|
| Leere Wurzelliste | `if not self._allowed_dirs: return True` — **alles lesbar** | nichts lesbar (`test_ohne_wurzeln_ist_nichts_lesbar`) |
| Zeitfenster zwischen Prüfung und Lesen | fünf getrennte Pfadoperationen (`exists`, `is_file`, `stat`, `read_text`) | ein Deskriptor: `resolve` → prüfen → `open(O_NOFOLLOW\|O_NONBLOCK)` → `fstat` → lesen |
| Binärdatei | `errors="replace"` — Ersatzzeichen ans Modell | Abweisung als „kein UTF-8-Text" |
| Kontamination | im Werkzeugergebnis nicht sichtbar | `taints_context=True`, der Lauf verliert seine sendenden Werkzeuge |

Der erste Punkt ist der schwerwiegendste: Eine vergessene Konfiguration öffnet
dort das ganze Dateisystem. Das ist dieselbe Klasse von Fehler, gegen die bei
uns `UnguardedExecution` und der fehlende Grant-Consumer stehen — ein fehlender
Sicherheitskontext muss schließen, nicht öffnen.

### Was wir von dort übernommen haben

**Musterliste sensibler Dateinamen** (`security/file_policy.py`). Sie sperrt
`.env`, `id_rsa`, `*.pem`, `.netrc` und Ähnliches — **auch innerhalb** eines
freigegebenen Ordners. Das schließt eine Lücke, die unsere Wurzelgrenze
prinzipiell offen lässt: Wer sein Heimatverzeichnis freigibt, gibt den
SSH-Schlüssel darin nicht bewusst mit frei.

Übernommen ist die Idee, nicht der Code. Und mit einer wichtigen Umkehrung:
**Dort ist die Liste die primäre Prüfung, bei uns ist sie die zweite.** Eine
Sperrliste übersieht immer etwas; als alleinige Grenze wäre sie untauglich,
hinter einer Wurzelgrenze kostet sie nichts.

Umgesetzt in `jarvis_contracts.SENSITIVE_FILE_PATTERNS` und geprüft auf zwei
Ebenen — auf dem genannten Pfad in `FilesConstraints.check()`, auf dem
**aufgelösten** in `LocalFileReader`. Nur die zweite sieht einen Symlink
`notizen.txt`, der auf `id_rsa` zeigt.

---

## 3. Taint-Tracking — dieselbe Idee, andere Statik

OpenJarvis hat Taint-Tracking mit Labels (`PII`, `SECRET`, `EXTERNAL`) und
einer `SINK_POLICY`, die je Werkzeug verbotene Labels führt.

**Wo wir strenger sind:**

* `check_taint()` liefert für jedes Werkzeug, das nicht in der Policy steht,
  `None` — **fail open**. Ihre Policy kennt drei Werkzeuge. Bei uns ist
  `forbidden_when_tainted=True` der Vorgabewert: Ein Werkzeug muss sich als
  unbedenklich *erklären*.
* `declassify()` entfernt ein Label mit einer Begründung, die ausdrücklich
  **nicht gespeichert** wird. Bei uns geht Entkontaminierung nur über
  menschliche Bestätigung, gebunden an einen Payload-Hash und beschränkt auf
  strukturierte Payloads.
* Ihre Erkennung ist die tragende Prüfung. Unsere Architekturentscheidung 1
  sagt das Gegenteil: nicht erkennen, sondern folgenlos machen.

**Was wir übernommen haben:** die Mustererkennung für Zugangsdaten — aber in
einer Rolle, die zu uns passt. `jarvis_core.policy.secrets` hebt bei einem
Treffer die Datenklasse eines Werkzeugergebnisses auf `P3`; P3 verlässt das
Gerät strukturell nie. Die Richtung ist einseitig:

```
Falsch negativ → die Klasse bleibt, was sie ohnehin gewesen wäre.
Falsch positiv → der Inhalt bleibt lokal. Unbequem, nie gefährlich.
```

Ein Mechanismus, dessen Versagen den Ausgangszustand herstellt, darf
heuristisch sein. Einer, auf dem eine Zusicherung ruht, nicht — deshalb gibt es
dort ein `escalate` und nirgends ein `declassify`.

Bewusst **kein** Muster für personenbezogene Daten: Eine Heuristik, die jede
Mailadresse auf P3 hebt, macht die Stufe wertlos. Personenbezug ist P2, und den
vergibt das Werkzeug ohnehin.

---

## 4. Audit — Bestätigung, keine Übernahme

`security/audit.py` dort ist SQLite mit `row_hash`/`prev_hash` und
`verify_chain()` — strukturell dasselbe wie unser `core/audit/chain.py`. Das
ist eine unabhängige Bestätigung unseres Entwurfs.

Gegen eine **gegabelte** Kette (zwei Zeilen mit demselben `prev_hash`) haben
sie nichts; bei SQLite mit einem Schreiber fällt das nicht auf. Für unseren
PostgreSQL-Sink mit mehreren Arbeitern ist genau das der interessante Fall —
der `pg_advisory_xact_lock` steht deshalb weiterhin auf unserer Liste.

---

## 5. Wo nachzuschlagen sich lohnt

Für Bausteine, die bei uns noch fehlen. Alles Apache 2.0.

| Unser Baustein | Dort nachsehen | Was man sich spart |
|---|---|---|
| `mail.*` | `connectors/gmail.py`, `gmail_imap.py` | OAuth-Ablauf, IMAP-Eigenheiten |
| `calendar.*` | `connectors/gcalendar.py`, `google_auth.py` | Wiederholungsregeln, Zeitzonen |
| Voice (Phase 2) | `speech/faster_whisper.py`, `kokoro_tts.py`, `deepgram.py` | Latenzverhalten, Modellwahl — `faster_whisper` steht in ADR-001 |
| Memory Service | `memory/extractor.py`, `store.py` | Extraktion als Kandidaten statt Direktschreiben |
| Plugins (MCP) | `mcp/`, `tools/mcp_adapter.py` | Manifest- und Isolationsfragen |
| Werkzeug-Sandbox | `sandbox/wasm_runner.py`, `subprocess_sandbox.py` | Isolation ausführender Werkzeuge |
| `web.fetch` | `security/ssrf.py` | SSRF-Abwehr, die wir noch nicht haben |

**Vorgehen bei einer Übernahme:** Ihr Code hängt an ihrer Registry, ihren Typen
und einer Rust-Brücke; ein Herauskopieren wäre teurer als ein Neuschreiben
gegen unsere Ports. Der Wert liegt in den gelösten Problemen, nicht in den
Zeilen. Wird doch Quelltext übernommen, gehört die Herkunft in den Modulkopf
und die Apache-Namensnennung ins Repository.

---

## 6. Was dieses Dokument nicht sagt

Es sagt nicht, dass unser Projekt besser ist. OpenJarvis ist deutlich breiter,
hat Sprache, Konnektoren, eine Desktop-Anwendung und eine Evaluationssuite —
alles Dinge, die bei uns fehlen.

Es sagt: An der Stelle, an der wir uns entschieden haben, streng zu sein — dem
Weg von einer Modellantwort zu einer Aktion mit Außenwirkung —, ist unsere
Absicherung enger. Das ist der Teil, der sich später am schwersten nachrüsten
lässt, und deshalb der richtige Ort für unseren Vorsprung.
