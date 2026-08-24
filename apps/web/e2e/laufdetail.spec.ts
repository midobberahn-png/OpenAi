import { expect, test } from "@playwright/test";

import { angemeldet } from "./system";

const TERMIN = {
  title: "Fokuszeit aus dem Browser",
  start: "2026-09-22T09:00:00+00:00",
  end: "2026-09-22T10:00:00+00:00",
};

/**
 * Laufdetail und Rücknahme im Browser.
 *
 * **Der Durchstich, auf den es ankommt:** Recht erteilen, Termin anlegen,
 * Rücknahme drücken — und danach ist der Termin weg. Gemessen wird am Ende an
 * der API und nicht an der Anzeige: Eine Oberfläche, die „zurückgenommen"
 * schreibt, während der Eintrag steht, ist schlimmer als eine, die schweigt.
 *
 * Die Vorbereitung läuft **durch die Oberfläche** — das Recht wird im
 * Permission Center gesetzt, nicht per API-Seitentür. Ein Test, der den
 * Zustand hinter der Oberfläche herstellt, prüft die Oberfläche nur halb.
 */
test("Ein Lauf zeigt seinen Plan", async ({ page }) => {
  await angemeldet(page);
  await page.getByTestId("zu-laeufen").click();
  await page.getByTestId("eingabe").fill("Blockier mir eine Stunde am Dienstag");
  await page.getByTestId("starten").click();

  await page.getByTestId("lauf").first().click();

  await expect(page.getByTestId("planliste")).toBeVisible();
  await expect(page.getByTestId("schritt-1")).toBeVisible();
  await expect(page.getByTestId("detail-status")).toHaveText("queued");
});

test("Ein ausgeführter Aufruf lässt sich zurücknehmen", async ({ page }) => {
  await angemeldet(page);

  // Recht erteilen — über die Oberfläche, wie ein Mensch es täte. Ein Test,
  // der den Zustand hinter der Oberfläche herstellt, prüft sie nur halb.
  await page.getByTestId("zu-rechten").click();
  await page.getByTestId("modus-calendar.create").selectOption("allow");
  await expect(page.getByTestId("modus-calendar.create")).toHaveValue("allow");
  await page.getByTestId("zu-laeufen").click();

  const lauf = await page.request.post("/runs", { data: { input: "Blockier mir eine Stunde" } });
  const laufId = (await lauf.json()).id as string;
  const schritt = await page.request.post(`/runs/${laufId}/steps`, {
    data: { tool: "calendar.create", arguments: TERMIN },
  });
  expect((await schritt.json()).status).toBe("executed");

  await page.reload();
  await page.getByTestId("zu-laeufen").click();
  await page.getByTestId("lauf").first().click();
  await expect(page.getByTestId("aufruf-calendar.create")).toBeVisible();

  await page.getByTestId("aufrufliste").getByRole("button", { name: "Rückgängig" }).click();

  await expect(page.getByTestId("aufrufliste")).toContainText("undone");
  // Und die Rücknahme steht in der verketteten Spur — sie ist eine Wirkung.
  const protokoll = await page.request.get("/audit?limit=50");
  const aktionen = ((await protokoll.json()) as Array<{ action: string }>).map((z) => z.action);
  expect(aktionen).toContain("tool.undone");
});

/**
 * **Was dieser Durchstich nicht misst, und warum das hier steht.**
 *
 * Ob der Termin danach tatsächlich aus dem Kalender verschwunden ist, kann der
 * Browser nicht sehen: Es gibt keinen Endpunkt, der Termine liest. Gemessen
 * wird die Wirkung deshalb in der pytest-Suite (``tests/integration/
 * test_undo.py`` zählt ``calendar_events``), und hier nur das, was die
 * Oberfläche tatsächlich weiß.
 *
 * Das ist eine Lücke der API und keine des Tests — und sie ist die nächste,
 * die auffällt, sobald jemand einen Kalender *anzeigen* will.
 */
test("Eine zweite Rücknahme wird nicht angeboten", async ({ page }) => {
  await angemeldet(page);
  await page.getByTestId("zu-rechten").click();
  await page.getByTestId("modus-calendar.create").selectOption("allow");
  await expect(page.getByTestId("modus-calendar.create")).toHaveValue("allow");
  await page.getByTestId("zu-laeufen").click();

  const lauf = await page.request.post("/runs", { data: { input: "Blockier mir eine Stunde" } });
  const laufId = (await lauf.json()).id as string;
  await page.request.post(`/runs/${laufId}/steps`, {
    data: { tool: "calendar.create", arguments: { ...TERMIN, title: "Einmal" } },
  });

  await page.reload();
  await page.getByTestId("zu-laeufen").click();
  await page.getByTestId("lauf").first().click();
  await page.getByTestId("aufrufliste").getByRole("button", { name: "Rückgängig" }).click();
  await expect(page.getByTestId("aufrufliste")).toContainText("undone");

  // Der Weg ist verbraucht — und die Oberfläche bietet ihn nicht mehr an.
  await expect(
    page.getByTestId("aufrufliste").getByRole("button", { name: "Rückgängig" }),
  ).toHaveCount(0);
});
