import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, type Page } from "@playwright/test";

const WURZEL = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

/**
 * Setzt die Nutzertabelle zurück — das Fenster für die Erstinbetriebnahme.
 *
 * Die Zeremonie gelingt genau einmal; ein Test, der sie durchspielt, braucht
 * eine Datenbank ohne Nutzer. Aufgeräumt wird über das Skript des Projekts und
 * **nicht** über einen Endpunkt: Ein Endpunkt, der Nutzer löscht, wäre
 * auszuliefern — was es nicht gibt, kann im Betrieb nicht falsch konfiguriert
 * sein. Die Wächter (``JARVIS_E2E_RESET``, ``JARVIS_ENV``) stehen im Skript.
 *
 * Je Test und nicht einmal global: Dieselbe Entscheidung wie in der
 * pytest-Suite, wo ``_angemeldet`` vor jeder Anmeldung aufräumt. Tests, die
 * sich einen Zustand teilen, scheitern in der Reihenfolge, in der sie zufällig
 * laufen.
 */
export function frischesSystem(): void {
  execFileSync("uv", ["run", "python", "scripts/e2e_reset.py"], {
    cwd: WURZEL,
    stdio: "pipe",
    env: { ...process.env, JARVIS_E2E_RESET: "1" },
  });
}

/**
 * Lässt einen Lauf hängen — Anspruch gesetzt, Wirkung unklar, Frist abgelaufen.
 *
 * Der Zustand entsteht im Betrieb durch einen **Absturz** zwischen Anspruch und
 * Abschluss; es gibt keinen Endpunkt dafür, und es soll keinen geben. Ein Weg,
 * einen fremden Lauf von außen in eine Sperre zu versetzen, wäre ein
 * Denial-of-Service mit Ansage.
 *
 * Den **Vermerk** setzt dieses Skript ausdrücklich nicht: Ihn schreibt die
 * Wiederaufnahme, sobald der nächste Schritt daran scheitert. Der Test löst ihn
 * also selbst aus und prüft damit den Weg statt der Abkürzung.
 */
export function haengenLassen(runId: string): void {
  execFileSync("uv", ["run", "python", "scripts/e2e_haengenlassen.py", runId], {
    cwd: WURZEL,
    stdio: "pipe",
    env: { ...process.env, JARVIS_E2E_RESET: "1" },
  });
}

/**
 * Ein virtueller Authenticator über das Chrome DevTools Protocol.
 *
 * **Warum das keine Attrappe der Sicherheitsprüfung ist.** Nachgestellt wird
 * ausschließlich der *Schlüsselspeicher*. Die Zeremonie läuft vollständig: Der
 * Browser bildet ``clientDataJSON`` mit der echten Herkunft, der Authenticator
 * signiert mit einem echten Schlüssel, und der Server prüft Signatur, Herkunft
 * und ``rp_id`` wie immer.
 *
 * Dass das keine Formalie ist, hat dieser Aufbau selbst gezeigt: Der erste
 * Lauf lief gegen ``:8000``, während ``WEBAUTHN_ORIGINS`` auf ``:5173`` stand —
 * und die Registrierung scheiterte mit 401. Genau so soll es sein.
 */
export async function mitVirtuellemAuthenticator(page: Page): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

/**
 * Erstinbetriebnahme über die Oberfläche — der Weg, den ein Mensch nimmt.
 *
 * **Warum hier so viel Aufwand um eine Fehlermeldung getrieben wird.** Diese
 * Funktion flackert: etwa einmal in dreißig Durchgängen bleibt die Leiste auf
 * „nicht angemeldet" stehen. Die erste Fassung wartete schlicht 20 Sekunden auf
 * „angemeldet" und meldete danach genau das — *dass* es nicht da war, nie
 * *warum*. Die Oberfläche zeigt den Grund die ganze Zeit an (die Fehlerkarte
 * steht direkt darunter), und der Test sah nicht hin. Jeder Fehlschlag kostete
 * damit einen Durchgang und brachte kein Material.
 *
 * Deshalb sammelt sie drei Dinge und legt sie in die Fehlermeldung:
 *
 * 1. **Die Fehlerkarte der Oberfläche** — der Grund, den Server oder
 *    Authenticator genannt haben.
 * 2. **Alle Anmelde-Aufrufe mit ihrem Ausgang**, ungefiltert und in der
 *    Reihenfolge — auch die, die gar nicht ankamen.
 * 3. **Den zuletzt gesehenen Zustand der Leiste**, damit „stand auf …" nicht
 *    aus der Erinnerung rekonstruiert werden muss.
 *
 * Ein Retry wäre die falsche Antwort und steht deshalb auch nicht in der
 * Konfiguration: Er verdeckt genau das, was hier gesucht wird.
 */
export async function angemeldet(page: Page): Promise<void> {
  frischesSystem();
  await mitVirtuellemAuthenticator(page);

  // **Jeder** Anmelde-Aufruf mit seinem Ausgang, in der Reihenfolge.
  //
  // Die erste Fassung filterte das reguläre ``401 /auth/me`` vor der Anmeldung
  // heraus — und versteckte damit ausgerechnet den Hauptverdächtigen: Die
  // Leiste fragt **einmal**, und ein 401 auf diese eine Frage lässt sie für
  // immer auf „nicht angemeldet" stehen. Beim ersten reproduzierten Fehlschlag
  // stand deshalb da: keine Fehlerkarte, kein abgewiesener Aufruf, keine
  // Erklärung. Wer filtert, entscheidet vorab, was die Ursache nicht ist.
  const verlauf: string[] = [];
  page.on("response", (antwort) => {
    const pfad = new URL(antwort.url()).pathname;
    if (pfad.startsWith("/auth/")) verlauf.push(`${antwort.status()} ${pfad}`);
  });
  page.on("requestfailed", (anfrage) => {
    const pfad = new URL(anfrage.url()).pathname;
    // Ein Aufruf, der gar nicht ankommt, erzeugt **keine** Antwort — ohne
    // diese Zeile wäre er in der Auswertung schlicht nicht vorhanden.
    if (pfad.startsWith("/auth/")) {
      verlauf.push(`GESCHEITERT ${pfad} (${anfrage.failure()?.errorText ?? "ohne Grund"})`);
    }
  });

  await page.goto("/");
  await page.getByTestId("email").fill(`e2e-${Date.now()}@example.test`);
  await page.getByTestId("name").fill("Playwright");
  await page.getByTestId("einrichten").click();

  // Der Vergleich bleibt schmal, die Auskunft steht im Fehlerfall. Die erste
  // Fassung hängte die abgewiesenen Aufrufe an den Vergleichswert — und
  // **jeder** Durchgang beginnt mit einem regulären ``401 /auth/me``, denn
  // genau so fragt die Oberfläche, ob jemand angemeldet ist. Der Wert konnte
  // damit nie „angemeldet" lauten: 19 von 21 Tests rot, und zwar zu Recht.
  try {
    await expect(page.getByTestId("verbindung")).toHaveText("angemeldet", { timeout: 20_000 });
  } catch (problem) {
    throw new Error(
      [
        "Die Erstinbetriebnahme kam nicht durch.",
        `Leiste: "${(await page.getByTestId("verbindung").innerText()).trim()}"`,
        (await page.getByTestId("fehler").count()) > 0
          ? `Grund laut Oberfläche: ${(await page.getByTestId("fehler").innerText()).trim()}`
          : "Keine Fehlerkarte — die Oberfläche hat den Versuch nicht als gescheitert gesehen.",
        `Anmelde-Aufrufe: ${verlauf.length > 0 ? verlauf.join(" → ") : "keine"}`,
        "Zu lesen ist die Kette so: Das erste 401 auf /auth/me ist die Frage der Leiste " +
          "vor der Anmeldung und gehört dazu. Endet die Kette mit einem zweiten 401 auf " +
          "/auth/me, war die Zeremonie erfolgreich und die Sitzung trotzdem nicht gültig.",
        `Ursprünglich: ${problem instanceof Error ? problem.message.split("\n")[0] : problem}`,
      ].join(" · "),
    );
  }
}


/**
 * Wartet, bis ein Element verschwunden ist — und sagt sonst, **warum** nicht.
 *
 * `toBeHidden()` meldet im Fehlfall „expected hidden, received visible". Das
 * ist wahr und nutzlos: Die Oberfläche zeigt daneben die ganze Zeit eine
 * Fehlerkarte mit dem Grund, den der Server genannt hat, und niemand sieht
 * hin. Genau diese Lücke hat beim Anmeldeflackern einen Durchgang gekostet,
 * ohne Material zu liefern — beim zweiten Mal wird sie nicht noch einmal
 * gebaut.
 *
 * Zusätzlich werden abgewiesene Aufrufe mitgeschrieben: Verschwindet ein
 * Element nicht, weil der Aufruf dahinter mit 409 endete, steht das hier und
 * muss nicht erschlossen werden.
 */
export async function verschwindet(page: Page, kennung: string, pfad = "/runs/"): Promise<void> {
  const abgewiesen: string[] = [];
  page.on("response", (antwort) => {
    const url = new URL(antwort.url()).pathname;
    if (url.includes(pfad) && !antwort.ok()) abgewiesen.push(`${antwort.status()} ${url}`);
  });

  try {
    await expect(page.getByTestId(kennung)).toBeHidden();
  } catch (problem) {
    const karte = page.getByTestId("fehler");
    throw new Error(
      [
        `„${kennung}" ist nicht verschwunden.`,
        (await karte.count()) > 0
          ? `Grund laut Oberfläche: ${(await karte.innerText()).trim()}`
          : "Keine Fehlerkarte — die Oberfläche hält den Vorgang für gelungen.",
        abgewiesen.length > 0
          ? `Abgewiesene Aufrufe: ${abgewiesen.join(", ")}`
          : "Kein abgewiesener Aufruf.",
        `Ursprünglich: ${problem instanceof Error ? problem.message.split("\n")[0] : problem}`,
      ].join(" · "),
    );
  }
}
