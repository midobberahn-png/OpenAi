import { useEffect, useRef, useState } from "react";

/**
 * Der Ereignisstrom als Hook.
 *
 * **Der Strom ist ein Hinweis und kein Zustand** (ADR-016). Dieser Hook liefert
 * deshalb keine Ereignisdaten, sondern ruft ``beiAenderung`` — was gilt, holt
 * der Aufrufer über die API. Ein Hook, der Ereignisinhalte durchreichte, lüde
 * dazu ein, den Zustand im Browser fortzuschreiben, und dann driftet die
 * Anzeige, sobald eine Nachricht fehlt.
 *
 * **Die Lückenerkennung ist der Grund für ``seq``.** Fehlt eine Nummer, ist
 * etwas verpasst worden — und dann wird ohnehin neu geladen. Der Unterschied
 * zum Normalfall ist also keiner; die Prüfung steht trotzdem hier, weil sie
 * die einzige Stelle ist, an der eine Lücke überhaupt auffällt, und weil sie
 * ins Protokoll gehört, wenn jemand später wissen will, warum die Oberfläche
 * hakt.
 *
 * **Und das Nachladen im Takt bleibt.** Der Strom beschleunigt; er ersetzt
 * nicht. Fällt er aus — kein Redis, ein Proxy dazwischen, ein Netzwerkwackler
 * —, wird die Oberfläche langsamer und nicht falsch.
 */
export type Verbindung = "verbunden" | "getrennt" | "aus";

export function useStrom(
  beiAenderung: () => void,
  beiNachricht?: (nachricht: Record<string, unknown>) => void,
): Verbindung {
  const [zustand, setZustand] = useState<Verbindung>("getrennt");
  // Als Referenz und nicht als Abhängigkeit: Sonst würde jede neue Fassung
  // der Rückrufmethode die Leitung schließen und neu aufbauen.
  const rueckruf = useRef(beiAenderung);
  rueckruf.current = beiAenderung;
  // Der zweite Rückruf ist die **einzige** Stelle, an der Ereignisinhalte
  // überhaupt gelesen werden — und er dient genau einem Zweck: Textstücke
  // anzuzeigen, während sie entstehen. Alles andere bleibt beim Nachladen.
  const inhalt = useRef(beiNachricht);
  inhalt.current = beiNachricht;

  useEffect(() => {
    const quelle = new EventSource("/events", { withCredentials: true });
    let letzte = 0;

    quelle.onopen = () => setZustand("verbunden");

    quelle.onmessage = (ereignis) => {
      setZustand("verbunden");
      try {
        const nachricht = JSON.parse(ereignis.data) as Record<string, unknown> & {
          seq?: number;
        };
        inhalt.current?.(nachricht);
        // Die Nummer wird **immer** fortgeschrieben, auch für Textstücke:
        // Sonst zählte die Lückenerkennung an ihnen vorbei und meldete
        // Lücken, die keine sind.
        if (typeof nachricht.seq === "number") {
          if (letzte !== 0 && nachricht.seq > letzte + 1) {
            console.warn(`Ereignislücke: ${letzte} → ${nachricht.seq}`);
          }
          letzte = nachricht.seq;
        }
        if (nachricht.t === "token.delta") {
          // Ein Textstück ändert am Zustand nichts — es wird angezeigt und
          // nicht nachgeladen. Sonst löste jedes Wort einen Rundlauf aus.
          return;
        }
      } catch {
        // Eine unlesbare Nachricht ist kein Grund, nicht nachzuladen — im
        // Gegenteil: Wer nicht weiß, was geschehen ist, fragt nach.
      }
      rueckruf.current();
    };

    quelle.onerror = () => {
      // ``EventSource`` verbindet sich selbst neu; hier wird nur der Zustand
      // sichtbar gemacht. Ein eigener Wiederverbindungsversuch daneben ergäbe
      // zwei Leitungen.
      setZustand("getrennt");
    };

    return () => quelle.close();
  }, []);

  return zustand;
}
