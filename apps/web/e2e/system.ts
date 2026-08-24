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

/** Erstinbetriebnahme über die Oberfläche — der Weg, den ein Mensch nimmt. */
export async function angemeldet(page: Page): Promise<void> {
  frischesSystem();
  await mitVirtuellemAuthenticator(page);
  await page.goto("/");
  await page.getByTestId("email").fill(`e2e-${Date.now()}@example.test`);
  await page.getByTestId("name").fill("Playwright");
  await page.getByTestId("einrichten").click();
  await expect(page.getByTestId("verbindung")).toHaveText("angemeldet", { timeout: 20_000 });
}
