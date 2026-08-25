import type { ReactElement, ReactNode } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { Quelltext } from "./Quelltext";

/**
 * Modellantwort als Markdown — ohne rohes HTML und ohne Abruf nach außen.
 *
 * **Kein ``rehype-raw``** (docs/10-ui.md §5). Ohne dieses Plugin bleibt rohes
 * HTML aus einer Modellausgabe **Text**: gemessen wird ``<b>fett</b>`` als
 * Zeichenfolge angezeigt, und ein ``<img src=x onerror=…>`` erzeugt kein
 * Element. Das ist der Unterschied zwischen „sieht harmlos aus“ und „kann
 * nichts bewirken“ — eine per Datei oder Mail eingeschleuste Injektion nähme
 * sonst den direkten Weg in eine Anwendung mit Postfachzugriff.
 *
 * **Bilder werden nicht geladen, sondern benannt.** Markdown-Bildsyntax ist
 * die Lücke, die die HTML-Regel offen lässt: ``![](https://fremd/…)`` ist
 * gültiges Markdown, und der Browser holt die Adresse **ohne Zutun** ab. In
 * einem System, dessen Läufe Fremdinhalt tragen können, ist das ein
 * Ausleitungskanal — die Adresse trägt, was das Modell hineinschreibt, und der
 * Abruf verrät nebenbei die IP. Ein Bild wird deshalb als Verweis dargestellt:
 * Wer es sehen will, klickt; nichts geschieht von selbst.
 *
 * **Verweise öffnen in einem neuen Kontext** (``noopener``), damit die
 * Oberfläche nicht durch Fremdinhalt verlassen oder ferngesteuert wird.
 * ``javascript:``-Adressen entfernt ``react-markdown`` von sich aus.
 *
 * **Quelltextblöcke gehen an ``Quelltext``** — eingefärbt und kopierbar. Warum
 * Shiki dort über Token statt über HTML läuft, steht in jener Datei; die kurze
 * Fassung: Der übliche Weg (``codeToHtml`` samt ``dangerouslySetInnerHTML``)
 * ist genau der, den diese Datei seit ihrer ersten Zeile ausschließt.
 *
 * Gegriffen wird dafür ``pre`` und nicht ``code``. In ``react-markdown`` v9
 * gibt es kein ``inline``-Kennzeichen mehr, und ein Block ohne Sprachangabe
 * (schlicht ```` ``` ````) trägt auch keine Klasse — wer am ``code``-Element
 * unterscheidet, hält ihn für eingebetteten Text mitten im Satz. Alles in
 * einem ``pre`` ist dagegen ein Block, ohne Fallunterscheidung.
 */
export function Antworttext({ text }: { text: string }) {
  return (
    <div className="markdown">
      <Markdown
        remarkPlugins={[remarkGfm]}
        components={{
          pre: ({ children }: { children?: ReactNode }) => {
            const inhalt = Array.isArray(children) ? children[0] : children;
            const eigenschaften =
              (inhalt as ReactElement<{ className?: string; children?: ReactNode }> | undefined)
                ?.props ?? {};
            // Der abschließende Zeilenumbruch gehört zum Zaun, nicht zum
            // Quelltext — ohne ihn zu entfernen, endet jeder Block mit einer
            // leeren Zeile.
            const text = String(eigenschaften.children ?? "").replace(/\n$/, "");
            const sprache = /language-([\w-]+)/.exec(eigenschaften.className ?? "")?.[1];
            return <Quelltext text={text} sprache={sprache} />;
          },
          // Tabellen können breiter sein als die Spalte; sie scrollen für
          // sich, statt die Seite auseinanderzuziehen (docs/10-ui.md §5).
          table: ({ children }: { children?: ReactNode }) => (
            <div className="tabellenrahmen">
              <table>{children}</table>
            </div>
          ),
          a: ({ href, children }: { href?: string; children?: ReactNode }) => (
            <a href={href} target="_blank" rel="noopener noreferrer">
              {children}
            </a>
          ),
          img: ({ src, alt }: { src?: string; alt?: string }) => (
            <a
              href={typeof src === "string" ? src : undefined}
              target="_blank"
              rel="noopener noreferrer"
              className="bildverweis"
              data-test="bildverweis"
            >
              Bild: {alt !== undefined && alt !== "" ? alt : (src ?? "ohne Adresse")}
            </a>
          ),
        }}
      >
        {text}
      </Markdown>
    </div>
  );
}
