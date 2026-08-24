import { useState } from "react";

import { api, ApiFehler } from "../api/client";
import { anmelden, registrieren } from "../api/passkey";

/**
 * Anmeldung mit Passkey — und die Erstinbetriebnahme daneben.
 *
 * **Kein Passwortfeld, und das ist der Punkt.** Ein Passkey ist an die Herkunft
 * der Seite gebunden; eine nachgebaute Oberfläche bekommt keine gültige
 * Signatur. Ein Passwort bekäme sie.
 *
 * Die Erstinbetriebnahme steht hier gleichberechtigt daneben, weil sie genau
 * einmal gelingt: Solange kein Nutzer existiert, gehört das System niemandem.
 * Wer die Seite zum ersten Mal öffnet, soll nicht raten müssen, wo er anfängt.
 */
export function Anmeldung({ fertig }: { fertig: () => void }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [fehler, setFehler] = useState<string | null>(null);
  const [laeuft, setLaeuft] = useState(false);

  async function versuchen(was: () => Promise<void>) {
    setFehler(null);
    setLaeuft(true);
    try {
      await was();
      fertig();
    } catch (problem) {
      // Der Grund kommt vom Server oder vom Authenticator und wird
      // unverändert gezeigt: Eine eigene Formulierung wäre eine zweite
      // Wahrheit über etwas, das man nicht selbst geprüft hat.
      setFehler(problem instanceof ApiFehler ? problem.detail : String(problem));
    } finally {
      setLaeuft(false);
    }
  }

  const einrichten = () =>
    versuchen(async () => {
      const zeremonie = await api.post<{ options: Record<string, unknown>; challenge: string }>(
        "/auth/bootstrap",
        { email, display_name: name },
      );
      const nachweis = await registrieren(zeremonie);
      await api.post("/auth/register/finish", {
        credential: nachweis,
        challenge: zeremonie.challenge,
        device_label: geraet(),
      });
      await anmeldezeremonie();
    });

  const eintreten = () => versuchen(anmeldezeremonie);

  return (
    <div className="inhalt">
      <div className="karte">
        <h2>Anmelden</h2>
        <p className="gedaempft">
          Mit dem Passkey dieses Geräts. Ein Passkey gilt nur für diese Herkunft — eine
          nachgebaute Seite bekommt keine gültige Signatur.
        </p>
        <button className="haupt" onClick={eintreten} disabled={laeuft} data-test="anmelden">
          Mit Passkey anmelden
        </button>
      </div>

      <div className="karte">
        <h2>Erstinbetriebnahme</h2>
        <p className="gedaempft">
          Gelingt genau einmal — solange das System noch niemandem gehört.
        </p>
        <div className="zeile" style={{ marginBottom: "0.5rem" }}>
          <input
            placeholder="E-Mail"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            data-test="email"
          />
          <input
            placeholder="Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            data-test="name"
          />
        </div>
        <button onClick={einrichten} disabled={laeuft || !email || !name} data-test="einrichten">
          Einrichten und anmelden
        </button>
      </div>

      {fehler !== null && (
        <div className="karte fehler" data-test="fehler">
          {fehler}
        </div>
      )}
    </div>
  );
}

async function anmeldezeremonie(): Promise<void> {
  const zeremonie = await api.post<{ options: Record<string, unknown>; challenge: string }>(
    "/auth/login/start",
    {},
  );
  const nachweis = await anmelden(zeremonie);
  await api.post("/auth/login/finish", {
    credential: nachweis,
    challenge: zeremonie.challenge,
  });
}

function geraet(): string {
  // Eine Bezeichnung zum Wiedererkennen in der Sitzungsübersicht, keine
  // Kennung: Was hier steht, entscheidet über nichts.
  return navigator.userAgent.slice(0, 80);
}
