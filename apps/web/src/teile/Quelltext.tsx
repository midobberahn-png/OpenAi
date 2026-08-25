import { useEffect, useState } from "react";

/**
 * Ein Quelltextblock aus einer Modellantwort — eingefärbt und kopierbar.
 *
 * **Shiki liefert hier Token, kein HTML.** Das ist die tragende Entscheidung
 * dieser Datei. Der übliche Weg (`codeToHtml` und `dangerouslySetInnerHTML`)
 * ist genau der, den docs/10-ui.md §5 ausschließt: „Kein
 * `dangerouslySetInnerHTML`, kein rohes HTML aus Modell- oder Fremdinhalt."
 * Der Text in diesem Block stammt aus einer Modellausgabe und kann über eine
 * gelesene Datei oder Mail von jemand anderem geschrieben worden sein.
 *
 * Dass Shiki das Eingefügte selbst maskiert, ändert daran nichts: Die Zusage
 * wäre dann eine über eine fremde Bibliothek und ihre nächste Version. Über
 * `codeToTokens` kommt statt einer Zeichenkette eine Liste aus Inhalt und
 * Farbe zurück; React setzt den Inhalt als Text und die Farbe als `style`.
 * **Es gibt keinen Weg, auf dem Markup aus dem Quelltext entstehen könnte** —
 * nicht weil es maskiert wird, sondern weil es nie als Markup gelesen wird.
 *
 * **Das Einfärben ist Schmuck, und die Reihenfolge sagt das.** Zuerst steht
 * der Block als schlichter Text da — richtig, lesbar, vollständig. Die Farben
 * kommen nach, wenn Shiki geladen ist. Wer eine Sprache schickt, die nicht
 * geladen ist, bekommt denselben schlichten Block; ein Fehlschlag beim Laden
 * ebenso. Ein Quelltext, der auf eine Bibliothek wartet, bevor er erscheint,
 * hätte die Verhältnisse umgedreht.
 *
 * **Sprachen sind eine feste Liste, keine Erkennung.** Das UI-Dokument nennt
 * „Sprachenerkennung"; erkannt wird hier ausschließlich, was im Zaun der
 * Markdown-Auszeichnung steht (```` ```python ````). Zu *raten*, welche
 * Sprache ein Block hat, färbt im Zweifel falsch ein — und eine falsche
 * Einfärbung ist schlechter als keine, weil sie eine Aussage über den Text
 * macht. Was nicht in der Liste steht, bleibt schlicht.
 */

const SPRACHEN: Record<string, () => Promise<unknown>> = {
  typescript: () => import("@shikijs/langs/typescript"),
  javascript: () => import("@shikijs/langs/javascript"),
  python: () => import("@shikijs/langs/python"),
  json: () => import("@shikijs/langs/json"),
  bash: () => import("@shikijs/langs/bash"),
  sql: () => import("@shikijs/langs/sql"),
  html: () => import("@shikijs/langs/html"),
  css: () => import("@shikijs/langs/css"),
  markdown: () => import("@shikijs/langs/markdown"),
};

/** Was ein Mensch schreibt und was Shiki heißt. */
const ANDERE_NAMEN: Record<string, string> = {
  ts: "typescript",
  tsx: "typescript",
  js: "javascript",
  jsx: "javascript",
  py: "python",
  sh: "bash",
  shell: "bash",
  zsh: "bash",
  md: "markdown",
};

type Token = { inhalt: string; farbe?: string };

type Hervorheber = {
  codeToTokens: (
    code: string,
    optionen: { lang: string; theme: string },
  ) => { tokens: { content: string; color?: string }[][] };
  loadLanguage: (sprache: unknown) => Promise<void>;
  getLoadedLanguages: () => string[];
};

let kern: Promise<Hervorheber> | null = null;

/**
 * Der Hervorheber, einmal je Seite.
 *
 * Ein Modul-Zustand und kein React-Kontext: Es gibt nichts zu konfigurieren
 * und nichts, was sich je Teilbaum unterscheiden könnte. Der JavaScript-Motor
 * statt Oniguruma, weil der ein WebAssembly-Modul nachlädt — für Einfärbung
 * ist das ein hoher Preis.
 */
async function hervorheber(): Promise<Hervorheber> {
  if (kern === null) {
    kern = (async () => {
      const [{ createHighlighterCore }, { createJavaScriptRegexEngine }, thema] = await Promise.all([
        import("shiki/core"),
        import("shiki/engine/javascript"),
        import("@shikijs/themes/github-dark"),
      ]);
      const erzeugt = await createHighlighterCore({
        themes: [thema],
        langs: [],
        engine: createJavaScriptRegexEngine(),
      });
      return erzeugt as unknown as Hervorheber;
    })();
  }
  return kern;
}

async function faerben(text: string, sprache: string): Promise<Token[][]> {
  const laden = SPRACHEN[sprache];
  if (laden === undefined) throw new Error(`Sprache ${sprache} steht nicht in der Liste.`);
  const hh = await hervorheber();
  if (!hh.getLoadedLanguages().includes(sprache)) {
    await hh.loadLanguage(await laden());
  }
  const { tokens } = hh.codeToTokens(text, { lang: sprache, theme: "github-dark" });
  return tokens.map((zeile) => zeile.map((t) => ({ inhalt: t.content, farbe: t.color })));
}

export function Quelltext({ text, sprache }: { text: string; sprache?: string }) {
  const gewaehlt = sprache === undefined ? undefined : (ANDERE_NAMEN[sprache] ?? sprache);
  const bekannt = gewaehlt !== undefined && gewaehlt in SPRACHEN;
  const [zeilen, setZeilen] = useState<Token[][] | null>(null);
  const [kopiert, setKopiert] = useState<"nein" | "ja" | "ging-nicht">("nein");

  useEffect(() => {
    if (!bekannt || gewaehlt === undefined) return;
    let gilt = true;
    void faerben(text, gewaehlt)
      .then((ergebnis) => {
        if (gilt) setZeilen(ergebnis);
      })
      .catch(() => {
        // Ein Fehlschlag beim Einfärben kostet Farbe, nicht den Quelltext.
        // Der schlichte Block steht bereits da.
        if (gilt) setZeilen(null);
      });
    return () => {
      gilt = false;
    };
  }, [text, gewaehlt, bekannt]);

  async function kopieren() {
    try {
      await navigator.clipboard.writeText(text);
      setKopiert("ja");
    } catch {
      // Die Zwischenablage ist nicht überall zugänglich (fehlende Erlaubnis,
      // unsicherer Kontext). Ein Knopf, der dann „kopiert" behauptet, lässt
      // jemanden einfügen, was nicht da ist.
      setKopiert("ging-nicht");
    }
  }

  return (
    <div className="quelltext" data-test="quelltext" data-sprache={gewaehlt ?? "ohne"}>
      <div className="quelltextkopf">
        <span className="gedaempft">{gewaehlt ?? "Text"}</span>
        <button onClick={() => void kopieren()} data-test="kopieren">
          {kopiert === "ja" ? "kopiert" : kopiert === "ging-nicht" ? "ging nicht" : "kopieren"}
        </button>
      </div>
      <pre>
        <code>
          {zeilen === null
            ? text
            : zeilen.map((zeile, i) => (
                <span key={i}>
                  {zeile.map((token, j) => (
                    <span key={j} style={{ color: token.farbe }}>
                      {token.inhalt}
                    </span>
                  ))}
                  {"\n"}
                </span>
              ))}
        </code>
      </pre>
    </div>
  );
}
