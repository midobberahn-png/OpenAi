import { expect, test } from "@playwright/test";

import { angemeldet, frischesSystem, mitVirtuellemAuthenticator } from "./system";

/**
 * Der erste Durchstich im Browser: Erstinbetriebnahme, Passkey, Anmeldung.
 *
 * **Was hier echt ist:** die Zeremonie, die Signaturprüfung, die
 * Origin-Bindung, die Datenbank, das Sitzungs-Cookie. **Was nachgestellt ist:**
 * der Schlüsselspeicher.
 */
test("Erstinbetriebnahme, Passkey, Anmeldung", async ({ page }) => {
  frischesSystem();
  await mitVirtuellemAuthenticator(page);

  await page.goto("/");
  await expect(page.getByTestId("verbindung")).toHaveText("nicht angemeldet");

  await page.getByTestId("email").fill(`e2e-${Date.now()}@example.test`);
  await page.getByTestId("name").fill("Playwright");
  await page.getByTestId("einrichten").click();

  await expect(page.getByTestId("verbindung")).toHaveText("angemeldet", { timeout: 20_000 });
  await expect(page.getByTestId("eingabe")).toBeVisible();
});

test("Abmelden führt zurück zur Anmeldung", async ({ page }) => {
  await angemeldet(page);

  await page.getByTestId("abmelden").click();

  await expect(page.getByTestId("verbindung")).toHaveText("nicht angemeldet");
  await expect(page.getByTestId("anmelden")).toBeVisible();
});

test("Ohne Anmeldung ist nichts zu sehen", async ({ page }) => {
  frischesSystem();
  await page.goto("/");

  await expect(page.getByTestId("verbindung")).toHaveText("nicht angemeldet");
  await expect(page.getByTestId("eingabe")).toHaveCount(0);
  await expect(page.getByTestId("laufliste")).toHaveCount(0);
});
