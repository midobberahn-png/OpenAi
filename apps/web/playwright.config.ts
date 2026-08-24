import { defineConfig, devices } from "@playwright/test";

/**
 * Durchstiche im echten Browser gegen die echte API.
 *
 * **Warum nicht gegen eine Attrappe.** Dieses Projekt belegt keine Zusage mit
 * einem Doppelgänger: Eine Attrappe tut, was der Test ihr sagt. Die
 * Oberfläche ist die Schicht, an der ein Mensch entscheidet — der
 * Bestätigungsdialog ist laut docs/10-ui.md der wichtigste einzelne Screen —,
 * und was dort geprüft wird, muss gegen dieselbe Policy, dieselbe Datenbank
 * und dieselben Nonces laufen wie im Betrieb.
 *
 * **Virtueller Authenticator statt echtem Passkey.** Ein Sicherheitsschlüssel
 * lässt sich nicht automatisieren; Chrome DevTools Protocol bietet dafür einen
 * virtuellen an (`WebAuthn.addVirtualAuthenticator`). Damit läuft die echte
 * Zeremonie — dieselbe Signaturprüfung, dieselbe Origin-Bindung —, nur der
 * Schlüsselspeicher ist einer im Speicher.
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  // Ein Durchgang, keine Wiederholung: Ein Test, der beim zweiten Versuch
  // grün wird, hat ein Problem, das ein Retry verdeckt.
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? "list" : "line",
  use: {
    baseURL: process.env.JARVIS_WEB_URL ?? "http://localhost:5173",
    trace: "retain-on-failure",
    // ``data-test`` und nicht ``data-testid``: Das Attribut steht im Markup und
    // ist auf Deutsch gehalten wie der Rest; die Vorgabe von Playwright hier
    // umzustellen ist billiger, als die Oberfläche an ein Werkzeug anzupassen.
    testIdAttribute: "data-test",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
