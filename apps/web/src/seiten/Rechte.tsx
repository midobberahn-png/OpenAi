import { useCallback, useEffect, useState } from "react";

import { api, ApiFehler } from "../api/client";
import type { ScopeSicht } from "../api/typen";

/**
 * Permission Center (docs/10-ui.md §6).
 *
 * Der Maßstab steht im Dokument: Ein Nutzer, der nicht in unter einer Minute
 * beantworten kann „darf JARVIS Mails senden?", wird dem System nicht
 * vertrauen — zu Recht.
 *
 * **Deshalb steht hier der ganze Katalog und nicht nur das Erteilte.** Die
 * Frage beantwortet gerade der Scope, zu dem nichts dasteht. Eine Liste, die
 * nur Erteiltes zeigt, kann sie nicht stellen.
 *
 * **Und der Vorgabemodus ist keine Erteilung.** Der Katalog empfiehlt; erteilt
 * hat nur, was unter „Erteilt" steht. Beides gleich darzustellen wäre die
 * Anzeige von Rechten, die niemand vergeben hat — genau die Verwechslung, vor
 * der der Kopf von ``permission_store.py`` warnt.
 */
export function Rechte() {
  const [scopes, setScopes] = useState<ScopeSicht[]>([]);
  const [fehler, setFehler] = useState<string | null>(null);
  const [laeuft, setLaeuft] = useState<string | null>(null);

  const laden = useCallback(async () => {
    try {
      setScopes(await api.get<ScopeSicht[]>("/permissions"));
      setFehler(null);
    } catch (problem) {
      setFehler(problem instanceof ApiFehler ? problem.detail : String(problem));
    }
  }, []);

  useEffect(() => {
    void laden();
  }, [laden]);

  async function setzen(scope: string, modus: string) {
    setLaeuft(scope);
    setFehler(null);
    try {
      if (modus === "") {
        await api.del(`/permissions/${scope}`);
      } else {
        await api.put(`/permissions/${scope}`, { mode: modus });
      }
      await laden();
    } catch (problem) {
      // Eine ``files.read``-Berechtigung ohne Pfadgrenze ist nicht
      // darstellbar (422). Der Satz kommt vom Server und wird gezeigt, statt
      // ihn hier neu zu erfinden.
      setFehler(problem instanceof ApiFehler ? problem.detail : String(problem));
    } finally {
      setLaeuft(null);
    }
  }

  const nachDomaene = new Map<string, ScopeSicht[]>();
  for (const scope of scopes) {
    const domaene = scope.name.split(".")[0] ?? scope.name;
    nachDomaene.set(domaene, [...(nachDomaene.get(domaene) ?? []), scope]);
  }

  return (
    <div className="inhalt">
      {fehler !== null && (
        <div className="karte fehler" data-test="rechte-fehler">
          {fehler}
        </div>
      )}

      {[...nachDomaene.entries()].map(([domaene, eintraege]) => (
        <div className="karte" key={domaene}>
          <h2>{domaene}</h2>
          <table>
            <tbody>
              {eintraege.map((scope) => (
                <tr key={scope.name} data-test={`scope-${scope.name}`}>
                  <td>
                    <div>{scope.name}</div>
                    <div className="gedaempft">{scope.description}</div>
                  </td>
                  <td style={{ width: "8rem" }}>
                    <span className="marke">{scope.risk_level}</span>
                  </td>
                  <td style={{ width: "12rem" }}>
                    <select
                      value={scope.granted?.mode ?? ""}
                      disabled={laeuft === scope.name}
                      onChange={(e) => void setzen(scope.name, e.target.value)}
                      data-test={`modus-${scope.name}`}
                    >
                      {/* Der leere Eintrag ist „nicht erteilt" und damit der
                          Zustand, in dem nichts läuft — nicht „erlaubt". */}
                      <option value="">nicht erteilt</option>
                      <option value="deny">verweigern</option>
                      <option value="confirm">bestätigen</option>
                      <option value="allow">erlauben</option>
                    </select>
                    {scope.granted === null && (
                      <div className="gedaempft" data-test={`vorgabe-${scope.name}`}>
                        Katalog empfiehlt: {scope.default_mode}
                      </div>
                    )}
                    {scope.granted?.expired === true && (
                      <div className="fehler" data-test={`abgelaufen-${scope.name}`}>
                        abgelaufen
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}
