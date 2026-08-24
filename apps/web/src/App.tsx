import { useCallback, useEffect, useState } from "react";

import { api } from "./api/client";
import { Anmeldung } from "./seiten/Anmeldung";
import { Chat } from "./seiten/Chat";
import { Laeufe } from "./seiten/Laeufe";
import { Rechte } from "./seiten/Rechte";

/**
 * Der Rahmen: Statusleiste, Bereichswahl, und die Frage, ob jemand angemeldet ist.
 *
 * **Kein Router.** Zwei Bereiche brauchen keine Bibliothek und keine
 * Adresszeile; ein Zustand genügt. Sobald ein Laufdetail eine eigene Adresse
 * braucht — damit man sie weitergeben und neu laden kann —, ist das die
 * Gelegenheit, einen einzuführen, und dann mit Grund.
 *
 * **Die Antwort darauf kommt vom Server**, nicht aus einem Zustand im Browser.
 * Ein Kennzeichen im ``localStorage`` wäre bequem und falsch: Es überlebt eine
 * abgelaufene Sitzung und zeigt dann eine Oberfläche, hinter der jeder Aufruf
 * mit 401 endet. ``GET /auth/me`` ist die einzige Stelle, die es weiß.
 */
type Bereich = "chat" | "laeufe" | "rechte";

export function App() {
  const [angemeldet, setAngemeldet] = useState<boolean | null>(null);
  const [bereich, setBereich] = useState<Bereich>("chat");

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
          <>
            <nav className="zeile">
              <button
                onClick={() => setBereich("chat")}
                className={bereich === "chat" ? "haupt" : ""}
                data-test="zum-chat"
              >
                Chat
              </button>
              <button
                onClick={() => setBereich("laeufe")}
                className={bereich === "laeufe" ? "haupt" : ""}
                data-test="zu-laeufen"
              >
                Läufe
              </button>
              <button
                onClick={() => setBereich("rechte")}
                className={bereich === "rechte" ? "haupt" : ""}
                data-test="zu-rechten"
              >
                Rechte
              </button>
            </nav>
            <button className="abstand" onClick={() => void abmelden()} data-test="abmelden">
              Abmelden
            </button>
          </>
        )}
      </header>
      {angemeldet === null && <div className="inhalt gedaempft">Verbindung wird geprüft…</div>}
      {angemeldet === false && <Anmeldung fertig={() => void pruefen()} />}
      {angemeldet === true && bereich === "chat" && <Chat oeffneLauf={() => setBereich("laeufe")} />}
      {angemeldet === true && bereich === "laeufe" && <Laeufe />}
      {angemeldet === true && bereich === "rechte" && <Rechte />}
    </>
  );
}
