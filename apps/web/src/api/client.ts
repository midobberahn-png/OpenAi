/**
 * Der einzige Weg der Oberfläche zur API.
 *
 * Dünn mit Absicht: Diese Datei entscheidet nichts. Sie kennt keine
 * Berechtigungen, keine Fristen und keine Zustände — sie überträgt.
 *
 * **Cookies gehen mit, Tokens nicht.** Die Sitzung liegt in einem
 * `HttpOnly`-Cookie; JavaScript kann sie nicht lesen, und das ist der Zweck.
 * Ein Token im `localStorage` wäre über jede XSS-Lücke abgreifbar — in einer
 * Anwendung mit Postfach- und Kalenderzugriff der teuerste Fehler, den man an
 * dieser Stelle machen kann.
 */

export class ApiFehler extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(`${status}: ${detail}`);
  }
}

async function anfrage<T>(pfad: string, init?: RequestInit): Promise<T> {
  const antwort = await fetch(pfad, {
    ...init,
    // Ohne dies schickt `fetch` das Sitzungs-Cookie bei manchen Aufrufen nicht
    // mit — und die Anmeldung sähe aus, als hätte sie nicht stattgefunden.
    credentials: "same-origin",
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });

  if (!antwort.ok) {
    throw new ApiFehler(antwort.status, await detailLesen(antwort));
  }
  if (antwort.status === 204) {
    return undefined as T;
  }
  return (await antwort.json()) as T;
}

async function detailLesen(antwort: Response): Promise<string> {
  try {
    const koerper = (await antwort.json()) as { detail?: unknown };
    if (typeof koerper.detail === "string") return koerper.detail;
    return JSON.stringify(koerper.detail ?? koerper);
  } catch {
    // Eine Fehlerantwort ohne JSON ist selten und soll den Fehler nicht
    // verdecken, den sie meldet.
    return antwort.statusText;
  }
}

export const api = {
  get: <T>(pfad: string) => anfrage<T>(pfad),
  post: <T>(pfad: string, koerper?: unknown) =>
    anfrage<T>(pfad, { method: "POST", body: JSON.stringify(koerper ?? {}) }),
  put: <T>(pfad: string, koerper: unknown) =>
    anfrage<T>(pfad, { method: "PUT", body: JSON.stringify(koerper) }),
  del: <T>(pfad: string) => anfrage<T>(pfad, { method: "DELETE" }),
};
