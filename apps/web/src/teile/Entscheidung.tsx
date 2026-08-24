import { useState } from "react";

import { api, ApiFehler } from "../api/client";
import type { OffenerVorgang } from "../api/typen";

/**
 * Der Ausgang aus einem Schritt, dessen Wirkung niemand kennt.
 *
 * **Der Bildschirm, der nicht beruhigen darf.** Ein Vorgang landet hier, weil
 * er begonnen und nicht geendet hat: Die Frist ist abgelaufen, und das
 * Werkzeugprotokoll schließt eine Wirkung *nicht* aus. Kein Automat wiederholt
 * das — die Entscheidung gehört einem Menschen, und der braucht dafür zwei
 * Dinge: was gemeint war, und die ehrliche Auskunft, dass JARVIS nicht
 * nachsehen kann.
 *
 * Deshalb steht der Vorbehalt **über** den Schaltflächen und nicht als
 * Fußnote, und deshalb kommt sein Text vom Server: Eine Zeichenkette in dieser
 * Datei gälte nur für diesen einen Client.
 *
 * **Die Beschriftungen sagen, was geschieht — nicht, was jemand weiß.**
 * „Erledigt" wäre eine Behauptung über die Welt; „Als erledigt verbuchen" ist
 * eine über die Buchführung. Der Unterschied ist genau der, um den es hier
 * geht.
 *
 * Kein `dangerouslySetInnerHTML`, wie überall: Die Beschreibung stammt aus
 * einem Plan, den ein Modell formuliert hat.
 */
export function Entscheidung({
  runId,
  vorgang,
  erledigt,
}: {
  runId: string;
  vorgang: OffenerVorgang;
  erledigt: () => Promise<void>;
}) {
  const [laeuft, setLaeuft] = useState<string | null>(null);
  const [fehler, setFehler] = useState<string | null>(null);

  async function entscheiden(wahl: "completed" | "retry" | "abort") {
    setLaeuft(wahl);
    setFehler(null);
    try {
      await api.post<{ detail: string }>(`/runs/${runId}/resolve`, {
        decision: wahl,
        // Unverändert zurück: Es ist der Bezug auf **diesen** Vorgang. Hat
        // inzwischen ein Wiederaufnahmedurchgang übernommen, gilt es nicht
        // mehr — und die Entscheidung wird abgewiesen statt auf eine Lage
        // angewandt, die es nicht mehr gibt.
        claim_id: vorgang.claim_id,
      });
      await erledigt();
    } catch (problem) {
      setFehler(problem instanceof ApiFehler ? problem.detail : String(problem));
    } finally {
      setLaeuft(null);
    }
  }

  return (
    <div className="karte entscheidung" data-test="entscheidung">
      <h2>Hier muss jemand nachsehen</h2>

      <p data-test="entscheidung-vorhaben">
        <strong>Vorgesehen war:</strong> {vorgang.description}
      </p>
      <p className="gedaempft" data-test="entscheidung-versuch">
        {vorgang.tool ?? "Der Schritt"} · Versuch{" "}
        {vorgang.attempted_at !== null
          ? new Date(vorgang.attempted_at).toLocaleString()
          : "zu unbekannter Zeit"}
        {vorgang.attempts.length > 0 && ` · Protokoll: ${vorgang.attempts.join(", ")}`}
      </p>

      <p className="warnung" data-test="entscheidung-vorbehalt">
        {vorgang.caveat}
      </p>

      <div className="zeile">
        <button
          onClick={() => void entscheiden("completed")}
          disabled={laeuft !== null}
          data-test="entscheidung-verbuchen"
        >
          Als erledigt verbuchen
        </button>
        <button
          onClick={() => void entscheiden("retry")}
          disabled={laeuft !== null}
          data-test="entscheidung-wiederholen"
        >
          Noch einmal versuchen
        </button>
        <button
          onClick={() => void entscheiden("abort")}
          disabled={laeuft !== null}
          data-test="entscheidung-abbrechen"
        >
          Lauf abbrechen
        </button>
      </div>

      <p className="gedaempft">
        „Noch einmal versuchen" kann ein zweites Mal wirken, falls der erste Versuch doch
        durchgekommen ist. „Abbrechen" nimmt nichts zurück.
      </p>

      {fehler !== null && (
        <p className="fehler" data-test="entscheidung-fehler">
          {fehler}
        </p>
      )}
    </div>
  );
}
