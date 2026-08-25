import { expect, test, type Page } from "@playwright/test";

import { angemeldet } from "./system";

/**
 * Das Tagesbudget in der Leiste.
 *
 * **Was hier geprüft wird und warum überhaupt.** Die Grenze wirkt in der
 * Modellwahl: Ist sie erreicht, kommen nur noch Modelle in Frage, die auf dem
 * Gerät laufen. Ohne Anzeige merkt ein Mensch davon nur, dass die Antworten
 * anders werden — und sucht den Fehler dort, wo keiner ist.
 *
 * Der Stand wird hier **nachgestellt**: Ihn echt zu erzeugen hieße, Geld
 * auszugeben. Was die Oberfläche daraus macht, ist davon unabhängig, und genau
 * das ist die Frage.
 */
async function mitStand(page: Page, stand: Record<string, unknown>): Promise<void> {
  await page.route("**/budget", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(stand),
    });
  });
  await page.reload();
}

test("Unterhalb der Schwelle steht nichts da", async ({ page }) => {
  await angemeldet(page);
  await mitStand(page, {
    spent_eur: "0.50",
    limit_eur: "5.00",
    since: new Date().toISOString(),
    share: 0.1,
    warning: false,
    exhausted: false,
  });

  // Eine Leiste, die dauerhaft einen Kontostand zeigt, macht aus einer Warnung
  // eine Tapete — und dann fällt sie nicht mehr auf, wenn sie eintritt.
  await expect(page.getByTestId("budgetmarke")).toHaveCount(0);
});

test("Ab achtzig Prozent warnt die Leiste", async ({ page }) => {
  await angemeldet(page);
  await mitStand(page, {
    spent_eur: "4.20",
    limit_eur: "5.00",
    since: new Date().toISOString(),
    share: 0.84,
    warning: true,
    exhausted: false,
  });

  const marke = page.getByTestId("budgetmarke");
  await expect(marke).toBeVisible();
  await expect(marke).toContainText("84");
  // Gewarnt, nicht abgeschaltet: Der teure Weg steht noch offen.
  await expect(marke).not.toContainText("erschöpft");
});

test("Ist es erschöpft, sagt die Leiste auch, was daraus folgt", async ({ page }) => {
  await angemeldet(page);
  await mitStand(page, {
    spent_eur: "5.40",
    limit_eur: "5.00",
    since: new Date().toISOString(),
    share: 1.08,
    warning: true,
    exhausted: true,
  });

  const marke = page.getByTestId("budgetmarke");
  await expect(marke).toContainText("erschöpft");
  // Die Folge gehört dazu. „Erschöpft" allein sagt einem Menschen nicht, was
  // sich für ihn ändert.
  await expect(marke).toContainText("lokale Modelle");
});
