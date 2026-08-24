import { useCallback, useEffect, useState } from "react";

import { api } from "./api/client";
import { Anmeldung } from "./seiten/Anmeldung";
import { Laeufe } from "./seiten/Laeufe";

/**
 * Der Rahmen: Statusleiste und die Frage, ob jemand angemeldet ist.
 *
 * **Die Antwort darauf kommt vom Server**, nicht aus einem Zustand im Browser.
 * Ein Kennzeichen im ``localStorage`` wäre bequem und falsch: Es überlebt eine
 * abgelaufene Sitzung und zeigt dann eine Oberfläche, hinter der jeder Aufruf
 * mit 401 endet. ``GET /auth/me`` ist die einzige Stelle, die es weiß.
 */
export function App() {
  const [angemeldet, setAngemeldet] = useState<boolean | null>(null);

  const pruefen = useCallback(async () => {
    try {
      await api.get<{ user_id: string }>("/auth/me");
      setAngemeldet(true);
    } catch {
      setAngemeldet(false);
    }
  }, []);

  useEffect(() => {
    void pruefen();
  }, [pruefen]);

  async function abmelden() {
    await api.post("/auth/logout");
    setAngemeldet(false);
  }

  return (
    <>
      <header className="leiste">
        <h1>JARVIS</h1>
        <span className="gedaempft" data-test="verbindung">
          {angemeldet === null ? "…" : angemeldet ? "angemeldet" : "nicht angemeldet"}
        </span>
        {angemeldet === true && (
          <button className="abstand" onClick={() => void abmelden()} data-test="abmelden">
            Abmelden
          </button>
        )}
      </header>
      {angemeldet === null && <div className="inhalt gedaempft">Verbindung wird geprüft…</div>}
      {angemeldet === false && <Anmeldung fertig={() => void pruefen()} />}
      {angemeldet === true && <Laeufe />}
    </>
  );
}
