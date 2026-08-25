import { useEffect, useState } from "react";

import { api } from "../api/client";

/**
 * Der Tagesstand in der Leiste — sichtbar, bevor er wirkt.
 *
 * **Warum das kein Beiwerk ist.** Die Grenze wirkt in der Modellwahl: Ist sie
 * erreicht, kommen nur noch Modelle in Frage, die auf dem Gerät laufen. Ohne
 * Anzeige merkt ein Mensch davon nur, dass die Antworten anders werden — und
 * sucht den Fehler dort, wo keiner ist. Das Dokument verlangt deshalb die
 * Warnung bei 80 % (docs/04-orchestrator.md §7), also **bevor** etwas
 * umschaltet.
 *
 * **Nur wenn es etwas zu sagen gibt.** Unterhalb der Warnschwelle steht hier
 * nichts. Eine Leiste, die dauerhaft einen Kontostand zeigt, macht aus einer
 * Warnung eine Tapete — und dann fällt sie nicht mehr auf, wenn sie eintritt.
 *
 * Nachgeladen im Takt und nicht über den Ereignisstrom: Der Stand ändert sich
 * mit jedem Modellaufruf, aber niemand muss ihn in der Sekunde sehen — und ein
 * Ereignis je Aufruf wäre ein Kanal, der Kosten in Echtzeit ausplaudert.
 */
type Stand = {
  spent_eur: string;
  limit_eur: string;
  share: number;
  warning: boolean;
  exhausted: boolean;
};

const TAKT_MS = 60_000;

export function Budgetmarke() {
  const [stand, setStand] = useState<Stand | null>(null);

  useEffect(() => {
    let lebt = true;
    const laden = async () => {
      try {
        const geladen = await api.get<Stand>("/budget");
        if (lebt) setStand(geladen);
      } catch {
        // Ein Kontostand, der sich nicht laden lässt, ist kein Grund, die
        // Oberfläche mit einem Fehler zu behängen: Die Grenze wirkt im
        // Server, ob sie hier steht oder nicht.
        if (lebt) setStand(null);
      }
    };
    void laden();
    const takt = setInterval(() => void laden(), TAKT_MS);
    return () => {
      lebt = false;
      clearInterval(takt);
    };
  }, []);

  if (stand === null || !stand.warning) return null;

  const prozent = Math.round(stand.share * 100);
  return (
    <span
      className={stand.exhausted ? "budget erschoepft" : "budget"}
      data-test="budgetmarke"
      title={`${stand.spent_eur} € von ${stand.limit_eur} € heute`}
    >
      {stand.exhausted
        ? `Tagesbudget erschöpft (${prozent} %) — nur noch lokale Modelle`
        : `Tagesbudget zu ${prozent} % verbraucht`}
    </span>
  );
}
