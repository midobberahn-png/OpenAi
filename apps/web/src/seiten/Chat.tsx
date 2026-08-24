import { useCallback, useEffect, useRef, useState } from "react";

import { api, ApiFehler } from "../api/client";
import { useStrom } from "../api/strom";
import type { LaufZeile } from "../api/typen";

/**
 * Der Chat — ein Lauf je Wortwechsel.
 *
 * **Kein eigener Zustand neben dem Server.** Was gesagt wurde, steht im Lauf
 * (``goal``), was geantwortet wurde ebenfalls (``output``). Der Strom bringt
 * die Textstücke, während sie entstehen; sie sind **Anzeige und kein
 * Zustand**. Beim nächsten Nachladen gilt, was der Server sagt — eine
 * Oberfläche, die sich ihre Wahrheit aus Stücken zusammensetzt, driftet beim
 * ersten verpassten.
 *
 * **Und der Text wird als Text dargestellt.** Kein ``dangerouslySetInnerHTML``,
 * kein rohes HTML aus Modellausgaben (docs/10-ui.md §5). Eine per Datei oder
 * Mail eingeschleuste HTML-Injektion wäre sonst ein direkter Weg in eine
 * Anwendung mit Postfachzugriff. Markdown kommt später und ohne ``rehype-raw``.
 *
 * **Der Plan bleibt sichtbar.** Ein Chatfenster, das nur Text zeigt, verbirgt,
 * was das System tut; das Laufdetail bleibt einen Klick entfernt.
 */
/** Wie viele Schritte die Oberfläche am Stück treibt. */
const MAX_SCHRITTE = 12;

/**
 * Treibt einen Lauf, solange Schritte **tatsächlich laufen**.
 *
 * **Die Abbruchbedingung ist der Punkt.** Weitergemacht wird nur nach
 * ``executed``: Ein blockierter Schritt bleibt der nächste fällige, und ein
 * Treiber, der „nicht ausgeführt" als „nochmal versuchen" liest, dreht sich im
 * Kreis — bei einem Werkzeugschritt mit jedem Umlauf auf Kosten des Budgets.
 *
 * Bei ``awaiting_confirmation`` endet er ohnehin: Dort steht ein Mensch, und
 * eine Oberfläche, die darüber hinwegtreibt, hätte die Bestätigung
 * abgeschafft.
 *
 * **Und er ist begrenzt.** Nicht, weil ein Plan so lang würde, sondern weil
 * eine Schleife ohne Grenze in einer Oberfläche, die Werkzeuge auslöst, kein
 * Fehler wäre, den man bemerkt — sie liefe einfach weiter.
 */
async function treiben(runId: string, laden: () => Promise<void>): Promise<void> {
  for (let runde = 0; runde < MAX_SCHRITTE; runde += 1) {
    const schritt = await api.post<{ status: string; run_status: string }>(
      `/runs/${runId}/advance`,
      {},
    );
    await laden();
    if (schritt.status !== "executed") return;
    if (schritt.run_status !== "executing" && schritt.run_status !== "queued") return;
  }
}

export function Chat({ oeffneLauf }: { oeffneLauf: (lauf: LaufZeile) => void }) {
  const [laeufe, setLaeufe] = useState<LaufZeile[]>([]);
  const [eingabe, setEingabe] = useState("");
  const [fehler, setFehler] = useState<string | null>(null);
  const [fliessend, setFliessend] = useState<Record<string, string>>({});
  const ende = useRef<HTMLDivElement>(null);

  const laden = useCallback(async () => {
    try {
      const geladen = await api.get<LaufZeile[]>("/runs");
      setLaeufe(geladen);
      // Fertige Läufe brauchen keinen Zwischenstand mehr: Was der Server
      // liefert, ist vollständig.
      setFliessend((bisher) => {
        const rest: Record<string, string> = {};
        for (const [id, text] of Object.entries(bisher)) {
          const lauf = geladen.find((l) => l.id === id);
          if (lauf !== undefined && lauf.finished_at === null) rest[id] = text;
        }
        return rest;
      });
      setFehler(null);
    } catch (problem) {
      setFehler(problem instanceof ApiFehler ? problem.detail : String(problem));
    }
  }, []);

  const verbindung = useStrom(() => void laden(), (nachricht) => {
    if (nachricht.t === "token.delta" && typeof nachricht.run_id === "string") {
      const stueck = String(nachricht.text ?? "");
      setFliessend((bisher) => ({
        ...bisher,
        [nachricht.run_id as string]: (bisher[nachricht.run_id as string] ?? "") + stueck,
      }));
    }
  });

  useEffect(() => {
    void laden();
    const takt = setInterval(() => void laden(), 10_000);
    return () => clearInterval(takt);
  }, [laden]);

  useEffect(() => {
    ende.current?.scrollIntoView({ behavior: "smooth" });
  }, [laeufe, fliessend]);

  async function senden() {
    const text = eingabe.trim();
    if (!text) return;
    setEingabe("");
    try {
      const lauf = await api.post<{ id: string }>("/runs", { input: text });
      await laden();
      await treiben(lauf.id, laden);
    } catch (problem) {
      setFehler(problem instanceof ApiFehler ? problem.detail : String(problem));
    }
  }

  return (
    <div className="inhalt">
      <div className="karte" data-test="verlauf">
        <h2>
          Gespräch
          <span className="gedaempft" data-test="strom" style={{ marginLeft: "0.75rem" }}>
            {verbindung === "verbunden" ? "· live" : "· lädt im Takt nach"}
          </span>
        </h2>

        {laeufe.length === 0 && <p className="gedaempft">Noch nichts gesagt.</p>}

        {[...laeufe].reverse().map((lauf) => (
          <div key={lauf.id} className="wortwechsel" data-test="wortwechsel">
            <div className="gesagt" data-test="gesagt">
              {lauf.goal ?? <span className="gedaempft">—</span>}
            </div>
            <div className="geantwortet" data-test="geantwortet">
              {fliessend[lauf.id] ?? lauf.output ?? ""}
              {lauf.finished_at === null && fliessend[lauf.id] === undefined && (
                <span className="gedaempft">
                  {lauf.status === "awaiting_confirmation"
                    ? "wartet auf deine Bestätigung"
                    : "arbeitet…"}
                </span>
              )}
            </div>
            <button className="klein" onClick={() => oeffneLauf(lauf)} data-test="zum-lauf">
              Plan ansehen
            </button>
          </div>
        ))}
        <div ref={ende} />
      </div>

      <div className="karte">
        <div className="zeile">
          <input
            placeholder="Sprich oder schreibe…"
            value={eingabe}
            onChange={(e) => setEingabe(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void senden()}
            data-test="eingabe"
          />
          <button className="haupt" onClick={() => void senden()} data-test="senden">
            Senden
          </button>
        </div>
      </div>

      {fehler !== null && (
        <div className="karte fehler" data-test="fehler">
          {fehler}
        </div>
      )}
    </div>
  );
}
