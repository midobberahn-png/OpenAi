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

/**
 * Eine Frage ohne Antwort ist kein „Nein".
 *
 * Die Leiste fragt genau **einmal** `GET /auth/me`. Die erste Fassung fing
 * jeden Fehler und zeigte „nicht angemeldet" — ein einzelner misslungener
 * Aufruf hinterließ damit dauerhaft eine Anmeldemaske, obwohl die Sitzung
 * galt, ohne Hinweis und ohne Ausweg.
 *
 * Aufgefallen beim Nachgehen des Testflackerns: Der Fehlschlag zeigte „nicht
 * angemeldet" ohne Fehlerkarte und ohne abgewiesenen Aufruf. Die Ursache des
 * Flackerns ist damit nicht gefunden — der Grund, warum es dauerhaft wirkte,
 * schon.
 */
test("Bleibt die Antwort aus, behauptet die Leiste nichts", async ({ page }) => {
  frischesSystem();
  // Nachgestellt wird der Aufruf, der nicht ankommt — nicht einer, der „nein"
  // sagt. Genau diese beiden hat die Oberfläche verwechselt.
  await page.route("**/auth/me", (weg) => weg.abort());
  await page.goto("/");

  await expect(page.getByTestId("verbindung")).toHaveText("Status unbekannt");
  await expect(page.getByTestId("status-unbekannt")).toBeVisible();
  // Keine Anmeldemaske: Wer eine gültige Sitzung hat, soll sich nicht ein
  // zweites Mal anmelden, weil eine Frage unterwegs verloren ging.
  await expect(page.getByTestId("einrichten")).toHaveCount(0);

  await page.unroute("**/auth/me");
  await page.getByTestId("erneut-pruefen").click();

  await expect(page.getByTestId("verbindung")).toHaveText("nicht angemeldet");
  await expect(page.getByTestId("anmelden")).toBeVisible();
});
