import { expect, test } from "@playwright/test";

import { angemeldet } from "./system";

/**
 * Das Permission Center im Browser.
 *
 * Der Maßstab aus docs/10-ui.md §6: „darf JARVIS Mails senden?" muss in unter
 * einer Minute zu beantworten sein. Geprüft wird deshalb nicht nur, dass die
 * Liste erscheint, sondern dass sie die **richtige** Auskunft gibt — und dass
 * eine Änderung dort tatsächlich wirkt.
 *
 * Die Wirkung wird am Werkzeug gemessen und nicht an der Anzeige: Eine
 * Berechtigung, die im Permission Center steht und beim Aufruf nicht gilt,
 * wäre schlimmer als keine.
 */
test("Der Katalog zeigt auch, was nicht erteilt ist", async ({ page }) => {
  await angemeldet(page);

  await page.getByTestId("zu-rechten").click();

  const kalender = page.getByTestId("scope-calendar.create");
  await expect(kalender).toBeVisible();
  await expect(page.getByTestId("modus-calendar.create")).toHaveValue("");
  await expect(page.getByTestId("vorgabe-calendar.create")).toContainText("Katalog empfiehlt");
});

test("Eine Erteilung wirkt am Werkzeug", async ({ page }) => {
  await angemeldet(page);
  await page.getByTestId("zu-rechten").click();

  await page.getByTestId("modus-calendar.create").selectOption("allow");
  await expect(page.getByTestId("modus-calendar.create")).toHaveValue("allow");

  // Gemessen an der API und nicht an der Anzeige: Der Browser bringt die
  // Sitzung mit, der Aufruf geht denselben Weg wie jeder andere.
  const lauf = await page.request.post("/runs", { data: { input: "Blockier mir eine Stunde" } });
  const schritt = await page.request.post(`/runs/${(await lauf.json()).id}/steps`, {
    data: {
      tool: "calendar.create",
      arguments: {
        title: "Aus dem Browser",
        start: "2026-09-20T09:00:00+00:00",
        end: "2026-09-20T10:00:00+00:00",
      },
    },
  });
  expect((await schritt.json()).status).toBe("executed");
});

test("Zurückziehen wirkt ebenso sofort", async ({ page }) => {
  await angemeldet(page);
  await page.getByTestId("zu-rechten").click();
  await page.getByTestId("modus-calendar.create").selectOption("allow");
  await expect(page.getByTestId("modus-calendar.create")).toHaveValue("allow");

  await page.getByTestId("modus-calendar.create").selectOption("");

  await expect(page.getByTestId("modus-calendar.create")).toHaveValue("");
  const lauf = await page.request.post("/runs", { data: { input: "Blockier mir eine Stunde" } });
  const schritt = await page.request.post(`/runs/${(await lauf.json()).id}/steps`, {
    data: {
      tool: "calendar.create",
      arguments: {
        title: "Darf nicht",
        start: "2026-09-20T11:00:00+00:00",
        end: "2026-09-20T12:00:00+00:00",
      },
    },
  });
  expect((await schritt.json()).status).toBe("blocked");
});

test("Eine Dateiberechtigung ohne Pfadgrenze wird abgewiesen", async ({ page }) => {
  await angemeldet(page);
  await page.getByTestId("zu-rechten").click();

  await page.getByTestId("modus-files.read").selectOption("allow");

  // ``FilesConstraints.allowed_roots`` trägt ``min_length=1`` — ein
  // Dateizugriff ohne Pfadgrenze ist keine Berechtigung. Die Oberfläche zeigt
  // den Satz des Servers, statt ihn neu zu erfinden.
  await expect(page.getByTestId("rechte-fehler")).toBeVisible();
  await expect(page.getByTestId("modus-files.read")).toHaveValue("");
});
