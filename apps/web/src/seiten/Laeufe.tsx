import { useCallback, useEffect, useState } from "react";

import { api, ApiFehler } from "../api/client";
import type { LaufZeile, OffeneAktion } from "../api/typen";
import { Bestaetigungsdialog } from "../teile/Bestaetigungsdialog";

/**
 * Was JARVIS gerade tut — und was auf eine Entscheidung wartet.
 *
 * **Der Server ist die Quelle der Wahrheit** (docs/10-ui.md §4). Diese Seite
 * hält keinen abgeleiteten Zustand, den sie selbst fortschreibt: Nach jeder
 * Aktion wird neu geladen statt lokal nachgezogen. Bei einem System mit
 * Bestätigungsdialogen ist eine driftende Anzeige nicht unschön, sondern
 * gefährlich — sie zeigt eine Entscheidung, die woanders schon gefallen ist.
 *
 * **Und deshalb wird hier gepollt.** Ein Ereignisstrom steht im Dokument und
 * existiert nicht; bis dahin ist regelmäßiges Nachladen die ehrliche Fassung.
 * Was es nicht kann: den Moment zeigen, in dem etwas passiert.
 */
export function Laeufe() {
  const [laeufe, setLaeufe] = useState<LaufZeile[]>([]);
  const [offen, setOffen] = useState<OffeneAktion[]>([]);
  const [fehler, setFehler] = useState<string | null>(null);
  const [eingabe, setEingabe] = useState("");

  const laden = useCallback(async () => {
    try {
      const [neueLaeufe, neueAktionen] = await Promise.all([
        api.get<LaufZeile[]>("/runs"),
        api.get<OffeneAktion[]>("/actions"),
      ]);
      setLaeufe(neueLaeufe);
      setOffen(neueAktionen);
      setFehler(null);
    } catch (problem) {
      setFehler(problem instanceof ApiFehler ? problem.detail : String(problem));
    }
  }, []);

  useEffect(() => {
    void laden();
    const takt = setInterval(() => void laden(), 3000);
    return () => clearInterval(takt);
  }, [laden]);

  async function starten() {
    if (!eingabe.trim()) return;
    try {
      await api.post("/runs", { input: eingabe });
      setEingabe("");
      await laden();
    } catch (problem) {
      setFehler(problem instanceof ApiFehler ? problem.detail : String(problem));
    }
  }

  const wartend = offen[0];

  return (
    <div className="inhalt">
      <div className="karte">
        <h2>Neuer Vorgang</h2>
        <div className="zeile">
          <input
            placeholder="Was soll geschehen?"
            value={eingabe}
            onChange={(e) => setEingabe(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void starten()}
            data-test="eingabe"
          />
          <button className="haupt" onClick={() => void starten()} data-test="starten">
            Starten
          </button>
        </div>
      </div>

      <div className="karte">
        <h2>Läufe</h2>
        {laeufe.length === 0 && <p className="gedaempft">Noch nichts geschehen.</p>}
        {laeufe.length > 0 && (
          <table data-test="laufliste">
            <thead>
              <tr>
                <th>Zustand</th>
                <th>Ziel</th>
                <th>Herkunft</th>
                <th>Begonnen</th>
              </tr>
            </thead>
            <tbody>
              {laeufe.map((lauf) => (
                <tr key={lauf.id} data-test="lauf">
                  <td>
                    <span className={`punkt ${lauf.status}`} /> {lauf.status}
                  </td>
                  <td>{lauf.goal ?? <span className="gedaempft">—</span>}</td>
                  <td>
                    {lauf.taint_level === "tainted" ? (
                      <span className="marke tainted" title="Dieser Lauf hat Fremdinhalt gelesen">
                        kontaminiert
                      </span>
                    ) : (
                      <span className="gedaempft">sauber</span>
                    )}
                  </td>
                  <td className="gedaempft">{new Date(lauf.started_at).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {fehler !== null && (
        <div className="karte fehler" data-test="fehler">
          {fehler}
        </div>
      )}

      {wartend !== undefined && (
        <Bestaetigungsdialog aktion={wartend} beantwortet={() => void laden()} />
      )}
    </div>
  );
}
