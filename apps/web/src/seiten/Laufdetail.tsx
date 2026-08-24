import { useCallback, useEffect, useState } from "react";

import { api, ApiFehler } from "../api/client";
import type { Aufruf, LaufZeile } from "../api/typen";
import { Entscheidung } from "../teile/Entscheidung";

/**
 * Ein einzelner Lauf: was vorgesehen war und was tatsächlich geschah.
 *
 * **Die beiden sind nicht dasselbe, und das ist der Grund für zwei Listen.**
 * Der Plan sagt, was angekündigt war — der Nutzer hat ihn gesehen, bevor etwas
 * lief. Das Werkzeugprotokoll sagt, was daraus wurde: Ein Schritt kann
 * abgewiesen worden sein, ein Aufruf kann außerhalb des Plans erfolgt sein, ein
 * Agentenschritt enthält mehrere Aufrufe. Eine Oberfläche, die nur den Plan
 * zeigt, zeigt eine Absicht und nennt sie Ergebnis.
 *
 * **Die Rücknahme steht am Aufruf und nicht am Plan.** Zurückgenommen wird
 * genau ein protokollierter Vorgang; die Schaltfläche gehört dorthin, wo er
 * steht.
 */
export function Laufdetail({ lauf, zurueck }: { lauf: LaufZeile; zurueck: () => void }) {
  const [stand, setStand] = useState<LaufZeile>(lauf);
  const [aufrufe, setAufrufe] = useState<Aufruf[]>([]);
  const [fehler, setFehler] = useState<string | null>(null);
  const [laeuft, setLaeuft] = useState<string | null>(null);

  const laden = useCallback(async () => {
    try {
      const [neuerStand, neueAufrufe] = await Promise.all([
        api.get<LaufZeile>(`/runs/${lauf.id}`),
        api.get<Aufruf[]>(`/runs/${lauf.id}/invocations`),
      ]);
      setStand(neuerStand);
      setAufrufe(neueAufrufe);
      setFehler(null);
    } catch (problem) {
      setFehler(problem instanceof ApiFehler ? problem.detail : String(problem));
    }
  }, [lauf.id]);

  useEffect(() => {
    void laden();
    const takt = setInterval(() => void laden(), 3000);
    return () => clearInterval(takt);
  }, [laden]);

  async function zuruecknehmen(aufruf: Aufruf) {
    setLaeuft(aufruf.id);
    setFehler(null);
    try {
      const ergebnis = await api.post<{ undone: boolean; display: string }>(
        `/invocations/${aufruf.id}/undo`,
      );
      if (!ergebnis.undone) {
        // Der Weg ist verbraucht, die Wirkung ist unklar — das steht so in der
        // Antwort und wird so gezeigt. Ein „erledigt" wäre hier eine
        // Falschaussage.
        setFehler(ergebnis.display);
      }
      await laden();
    } catch (problem) {
      setFehler(problem instanceof ApiFehler ? problem.detail : String(problem));
    } finally {
      setLaeuft(null);
    }
  }

  return (
    <div className="inhalt">
      <div className="zeile" style={{ marginBottom: "0.75rem" }}>
        <button onClick={zurueck} data-test="zurueck">
          ← Läufe
        </button>
        <span className={`punkt ${stand.status}`} />
        <span data-test="detail-status">{stand.status}</span>
        {stand.taint_level === "tainted" && (
          <span className="marke tainted" data-test="detail-taint">
            kontaminiert
          </span>
        )}
      </div>

      {/* **Ganz oben, vor dem Plan.** Ein Vorgang, der auf einen Menschen
          wartet, ist das Einzige auf dieser Seite, das ohne ihn nicht
          weitergeht — und der Lauf steht, bis er entschieden ist. */}
      {stand.unresolved != null && (
        <Entscheidung runId={stand.id} vorgang={stand.unresolved} erledigt={laden} />
      )}

      <div className="karte">
        <h2>Plan{stand.goal !== null && <span className="gedaempft"> · {stand.goal}</span>}</h2>
        {stand.plan.length === 0 && <p className="gedaempft">Kein Plan für diesen Lauf.</p>}
        {stand.plan.length > 0 && (
          <table data-test="planliste">
            <tbody>
              {stand.plan.map((schritt) => (
                <tr key={schritt.seq} data-test={`schritt-${schritt.seq}`}>
                  <td style={{ width: "2rem" }} className="gedaempft">
                    {schritt.seq}
                  </td>
                  <td>{schritt.description}</td>
                  <td style={{ width: "9rem" }} className="gedaempft">
                    {schritt.target}
                  </td>
                  <td style={{ width: "6rem" }} data-test={`schrittstand-${schritt.seq}`}>
                    {schritt.status}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="karte">
        <h2>Was geschehen ist</h2>
        {aufrufe.length === 0 && <p className="gedaempft">Noch kein Werkzeug aufgerufen.</p>}
        {aufrufe.length > 0 && (
          <table data-test="aufrufliste">
            <tbody>
              {aufrufe.map((aufruf) => (
                <tr key={aufruf.id} data-test={`aufruf-${aufruf.tool_name}`}>
                  <td>{aufruf.tool_name}</td>
                  <td data-test={`aufrufstand-${aufruf.id}`}>{aufruf.status}</td>
                  <td className="gedaempft">
                    {aufruf.executed_at !== null
                      ? new Date(aufruf.executed_at).toLocaleTimeString()
                      : "—"}
                  </td>
                  <td style={{ width: "10rem" }}>
                    {aufruf.undoable && (
                      <button
                        onClick={() => void zuruecknehmen(aufruf)}
                        disabled={laeuft === aufruf.id}
                        data-test={`undo-${aufruf.id}`}
                      >
                        Rückgängig
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {fehler !== null && (
        <div className="karte fehler" data-test="detail-fehler">
          {fehler}
        </div>
      )}
    </div>
  );
}
