import type { ReactNode } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

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
 * Was hier bewusst **noch nicht** steht: Shiki für Quelltext samt
 * Kopierbutton. Das Dokument führt es, es ist ein eigener Schritt.
 */
export function Antworttext({ text }: { text: string }) {
  return (
    <div className="markdown">
      <Markdown
        remarkPlugins={[remarkGfm]}
        components={{
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
