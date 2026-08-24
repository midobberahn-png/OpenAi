import { useEffect, useState } from "react";

import { api, ApiFehler } from "../api/client";
import type { OffeneAktion } from "../api/typen";

/**
 * Der wichtigste einzelne Screen des Systems (docs/10-ui.md §7).
 *
 * Vier Regeln aus dem Dokument, und jede hat einen Grund:
 *
 * 1. **Gezeigt wird das validierte Argumentobjekt**, Feld für Feld — nicht ein
 *    vom Modell formulierter Fließtext. Der Text käme aus derselben Quelle wie
 *    der Vorschlag; wer ihn anzeigt, lässt den Vorschlag seine eigene
 *    Beschreibung schreiben.
 * 2. **Der Bestätigen-Knopf ist 800 ms gesperrt.** Gegen den Reflexklick, nicht
 *    gegen einen Angreifer. Ein Dialog, der bei jedem zweiten Vorgang
 *    erscheint, wird weggeklickt, bevor er gelesen ist.
 * 3. **Hervorgehobene Felder bleiben hervorgehoben.** Die Einstufung kommt vom
 *    Server (``emphasis``); die Oberfläche entscheidet nicht neu, was
 *    auffällig ist.
 * 4. **Die Frist steht sichtbar.** Eine Bestätigung, die still abläuft, führt
 *    zu einem Klick ins Leere und zu der Vermutung, das System sei kaputt.
 */
export function Bestaetigungsdialog({
  aktion,
  beantwortet,
}: {
  aktion: OffeneAktion;
  beantwortet: () => void;
}) {
  const [gesperrt, setGesperrt] = useState(true);
  const [laeuft, setLaeuft] = useState(false);
  const [fehler, setFehler] = useState<string | null>(null);
  const [rest, setRest] = useState(() => sekunden(aktion.expires_at));

  useEffect(() => {
    const zeitgeber = setTimeout(() => setGesperrt(false), 800);
    return () => clearTimeout(zeitgeber);
  }, []);

  useEffect(() => {
    const takt = setInterval(() => setRest(sekunden(aktion.expires_at)), 1000);
    return () => clearInterval(takt);
  }, [aktion.expires_at]);

  async function antworten(zustimmen: boolean) {
    if (aktion.nonce === null) {
      // Ohne Nonce ist diese Bestätigung nicht die dieser Sitzung. Der Server
      // wiese sie ohnehin ab; hier steht der Satz, der erklärt, warum.
      setFehler("Diese Bestätigung gehört zu einer anderen Sitzung.");
      return;
    }
    setLaeuft(true);
    setFehler(null);
    try {
      await api.post(`/actions/${aktion.id}/respond`, {
        nonce: aktion.nonce,
        approve: zustimmen,
      });
      beantwortet();
    } catch (problem) {
      setFehler(problem instanceof ApiFehler ? problem.detail : String(problem));
    } finally {
      setLaeuft(false);
    }
  }

  return (
    <div className="dialog" role="dialog" aria-modal="true" data-test="dialog">
      <div className="karte">
        <div className="titel">
          <span>⚠</span>
          <strong>Bestätigung erforderlich</strong>
          <span className="abstand gedaempft" style={{ marginLeft: "auto" }}>
            Risiko: {aktion.risk.toUpperCase()}
          </span>
        </div>

        <h2 data-test="dialog-titel">{aktion.preview_title}</h2>

        <table>
          <tbody>
            {aktion.preview_fields.map((feld) => (
              <tr key={feld.label} className={feld.emphasis}>
                <td className="gedaempft">{feld.label}</td>
                <td className="wert" data-test={`feld-${feld.label}`}>
                  {feld.value}
                  {feld.truncated && <span className="gedaempft"> …gekürzt</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <p className="gedaempft" data-test="grund">
          {aktion.reason}
        </p>
        {aktion.warnings.map((warnung) => (
          <p key={warnung} className="fehler" data-test="warnung">
            {warnung}
          </p>
        ))}
        <p className="gedaempft">
          {aktion.reversible
            ? "Rückgängig machbar — 15 Minuten lang."
            : "Nicht rückgängig zu machen."}
          {" · "}
          <span data-test="frist">Gültig noch: {rest > 0 ? `${rest} s` : "abgelaufen"}</span>
        </p>

        {fehler !== null && (
          <p className="fehler" data-test="dialog-fehler">
            {fehler}
          </p>
        )}

        <div className="fuss">
          <button onClick={() => antworten(false)} disabled={laeuft} data-test="ablehnen">
            Abbrechen
          </button>
          <button
            className="haupt"
            onClick={() => antworten(true)}
            disabled={gesperrt || laeuft || rest <= 0}
            data-test="bestaetigen"
          >
            {gesperrt ? "Bitte lesen…" : "Bestätigen"}
          </button>
        </div>
      </div>
    </div>
  );
}

function sekunden(bis: string): number {
  return Math.max(0, Math.floor((new Date(bis).getTime() - Date.now()) / 1000));
}
