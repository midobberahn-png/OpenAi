import { expect, test } from "@playwright/test";

import { angemeldet } from "./system";

/**
 * Der Ereignisstrom im Browser.
 *
 * **Gemessen wird die Latenz, nicht das Vorhandensein.** Dass eine Änderung
 * irgendwann erscheint, konnte die Oberfläche vorher auch — sie pollte. Der
 * Gegenstand dieses Blocks ist der *Moment*: Eine Bestätigung, die drei
 * Sekunden später auftaucht, ist bei einer Aktion mit Außenwirkung drei
 * Sekunden zu spät.
 *
 * Deshalb steht der Takt der Oberfläche auf zehn Sekunden und die Erwartung
 * hier auf drei: Was in unter drei Sekunden erscheint, kann nicht vom
 * Nachladen kommen.
 */
test("Eine Änderung erscheint, ohne auf den Takt zu warten", async ({ page }) => {
  await angemeldet(page);
  await page.getByTestId("zu-laeufen").click();
  await expect(page.getByTestId("strom")).toHaveText("· live", { timeout: 10_000 });

  // Der Lauf entsteht **außerhalb** dieses Fensters — so, wie ihn der Arbeiter
  // oder ein zweites Gerät anlegen würde. Ohne Strom sähe die Oberfläche ihn
  // erst beim nächsten Takt.
  const beginn = Date.now();
  await page.request.post("/runs", { data: { input: "Von woanders gestartet" } });

  await expect(page.getByTestId("lauf")).toHaveCount(1, { timeout: 5_000 });
  expect(Date.now() - beginn).toBeLessThan(3_000);
});

test("Ohne Strom bleibt die Oberfläche richtig, nur langsamer", async ({ page }) => {
  await angemeldet(page);

  // Die Leitung wird gekappt — nachgestellt wird ein Proxy, der sie schließt,
  // oder ein Redis, der wegbleibt.
  await page.route("**/events", (route) => route.abort());
  await page.reload();
  await page.getByTestId("zu-laeufen").click();

  await expect(page.getByTestId("strom")).toHaveText("· lädt im Takt nach");
  await page.request.post("/runs", { data: { input: "Ohne Strom" } });

  // Der Takt trägt weiter: Die Oberfläche wird langsamer und nicht falsch.
  await expect(page.getByTestId("lauf")).toHaveCount(1, { timeout: 15_000 });
});
