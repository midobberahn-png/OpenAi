import { useCallback, useEffect, useState } from "react";

import { api, ApiFehler } from "./api/client";
import { Anmeldung } from "./seiten/Anmeldung";
import { Chat } from "./seiten/Chat";
import { Laeufe } from "./seiten/Laeufe";
import { Rechte } from "./seiten/Rechte";
import { Budgetmarke } from "./teile/Budgetmarke";

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
 *
 * **Drei Zustände und nicht zwei — der Unterschied ist ein Befund.** Die erste
 * Fassung fing jeden Fehler und setzte „nicht angemeldet". Damit war „der
 * Server sagt nein" (401) dasselbe wie „die Frage kam nicht durch" — und weil
 * hier genau **einmal** gefragt wird, blieb ein einzelner misslungener Aufruf
 * für immer stehen: Anmeldemaske, obwohl die Sitzung gilt, ohne Hinweis und
 * ohne Ausweg.
 *
 * Aufgefallen ist das beim Nachgehen eines Testflackerns
 * (``e2e/system.ts``): Der Fehlschlag zeigte „nicht angemeldet" **ohne**
 * Fehlerkarte und ohne abgewiesenen Aufruf — die Oberfläche hielt den Versuch
 * für gelungen und zeigte trotzdem die Maske. Die Ursache des Flackerns ist
 * damit nicht gefunden; was gefunden ist, ist der Grund, warum ein
 * Augenblicksfehler zu einem dauerhaft falschen Bildschirm wurde.
 */
type Bereich = "chat" | "laeufe" | "rechte";

type Anmeldezustand = "ja" | "nein" | "unbekannt";
/**„unbekannt" ist kein Zwischenzustand, sondern eine eigene Aussage: Wir haben
 * gefragt und keine verwertbare Antwort bekommen. Wer daraus „nein" macht,
 * behauptet etwas über die Sitzung, das er nicht weiß. */

export function App() {
  const [angemeldet, setAngemeldet] = useState<Anmeldezustand | null>(null);
  const [bereich, setBereich] = useState<Bereich>("chat");

  const pruefen = useCallback(async () => {
    try {
      await api.get<{ user_id: string }>("/auth/me");
      setAngemeldet("ja");
    } catch (problem) {
      // **401 ist eine Antwort, alles andere ist keine.** Ein Netzfehler, ein
      // 500 oder ein abgebrochener Aufruf sagen nichts über die Sitzung.
      setAngemeldet(problem instanceof ApiFehler && problem.status === 401 ? "nein" : "unbekannt");
    }
  }, []);

  useEffect(() => {
    void pruefen();
  }, [pruefen]);

  async function abmelden() {
    await api.post("/auth/logout");
    setAngemeldet("nein");
  }

  return (
    <>
      <header className="leiste">
        <h1>JARVIS</h1>
        <span className="gedaempft" data-test="verbindung">
          {angemeldet === null
            ? "…"
            : angemeldet === "ja"
              ? "angemeldet"
              : angemeldet === "nein"
                ? "nicht angemeldet"
                : "Status unbekannt"}
        </span>
        {angemeldet === "ja" && (
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
            <Budgetmarke />
            <button className="abstand" onClick={() => void abmelden()} data-test="abmelden">
              Abmelden
            </button>
          </>
        )}
      </header>
      {angemeldet === null && <div className="inhalt gedaempft">Verbindung wird geprüft…</div>}
      {angemeldet === "unbekannt" && (
        // **Keine Anmeldemaske.** Wer eine gültige Sitzung hat und hier eine
        // Maske sieht, meldet sich ein zweites Mal an — oder glaubt, er sei
        // abgemeldet worden. Beides ist eine Aussage, die wir nicht treffen
        // können. Stattdessen: was wir wissen, und ein Weg weiter.
        <div className="inhalt">
          <div className="karte fehler" data-test="status-unbekannt">
            <p>
              Der Server hat auf die Frage, ob eine Sitzung besteht, nicht geantwortet. Ob Sie
              angemeldet sind, ist damit offen — abgemeldet wurden Sie nicht.
            </p>
            <button className="haupt" onClick={() => void pruefen()} data-test="erneut-pruefen">
              Erneut prüfen
            </button>
          </div>
        </div>
      )}
      {angemeldet === "nein" && <Anmeldung fertig={() => void pruefen()} />}
      {angemeldet === "ja" && bereich === "chat" && <Chat oeffneLauf={() => setBereich("laeufe")} />}
      {angemeldet === "ja" && bereich === "laeufe" && <Laeufe />}
      {angemeldet === "ja" && bereich === "rechte" && <Rechte />}
    </>
  );
}
