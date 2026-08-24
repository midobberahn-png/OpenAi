import { expect, test } from "@playwright/test";

import { angemeldet } from "./system";

/**
 * Der Chat im Browser.
 *
 * **Was hier geprüft wird und was nicht.** Ob Textstücke fließen, hängt an
 * einem Sprachmodell; ein Gate, das ein 4,9-GB-Modell voraussetzt, läuft in
 * keiner Pipeline. Der Fluss selbst ist deshalb in der pytest-Suite gemessen
 * (``test_ereignisstrom.py``: die Stücke kommen einzeln und ergeben den Text).
 *
 * Hier geht es um das, was die Oberfläche unabhängig davon leisten muss: Was
 * gesagt wurde, steht sofort da; was das System tut, bleibt sichtbar; und der
 * Plan ist einen Klick entfernt — ein Chatfenster, das nur Text zeigt,
 * verbirgt, was gerade geschieht.
 */
test("Gesagtes erscheint sofort, mit sichtbarem Zustand", async ({ page }) => {
  await angemeldet(page);

  await page.getByTestId("eingabe").fill("Wie spät ist es?");
  await page.getByTestId("senden").click();

  const wortwechsel = page.getByTestId("wortwechsel").first();
  await expect(wortwechsel.getByTestId("gesagt")).toContainText("Wie spät ist es?");
  // Ohne laufendes Modell bleibt der Lauf stehen — und die Oberfläche sagt
  // das, statt eine leere Antwort zu zeigen.
  await expect(wortwechsel.getByTestId("geantwortet")).toContainText(/arbeitet|wartet/);
});

test("Der Plan bleibt einen Klick entfernt", async ({ page }) => {
  await angemeldet(page);
  await page.getByTestId("eingabe").fill("Blockier mir eine Stunde");
  await page.getByTestId("senden").click();
  await expect(page.getByTestId("wortwechsel").first()).toBeVisible();

  await page.getByTestId("zum-lauf").first().click();

  await expect(page.getByTestId("laufliste")).toBeVisible();
});

test("Der Antworttext wird als Text dargestellt, nicht als HTML", async ({ page }) => {
  await angemeldet(page);

  // Nachgestellt wird eine Modellantwort mit HTML darin — der Weg, den eine
  // präparierte Datei oder Mail nähme. Gerendert werden darf sie nur als Text;
  // ein ``dangerouslySetInnerHTML`` an dieser Stelle wäre der direkte Pfad in
  // eine Anwendung mit Postfachzugriff.
  await page.route("**/runs", async (route) => {
    if (route.request().method() !== "GET") return route.fallback();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        {
          id: "11111111-1111-1111-1111-111111111111",
          status: "completed",
          trigger: "user",
          taint_level: "clean",
          data_class: "p2",
          intent: null,
          is_multi_step: false,
          trace_id: "t",
          started_at: new Date().toISOString(),
          finished_at: new Date().toISOString(),
          goal: "Lies die Notiz",
          output: '<img src=x onerror="window.__geknackt=1"> <b>fett</b>',
          plan: [],
        },
      ]),
    });
  });
  await page.reload();

  const antwort = page.getByTestId("geantwortet").first();
  await expect(antwort).toContainText("<b>fett</b>");
  expect(await page.evaluate(() => (window as never as Record<string, unknown>).__geknackt)).toBeUndefined();
  expect(await antwort.locator("img").count()).toBe(0);
});
