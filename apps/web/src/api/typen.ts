/**
 * Die Formen, die die API liefert.
 *
 * **Von Hand und nicht generiert — vorerst.** `apps/web/lib/api/generated`
 * enthält OpenAPI und JSON-Schema (ADR-006); daraus TypeScript zu erzeugen ist
 * ein eigener Schritt in der Werkzeugkette, und ein halber Generator ist
 * schlimmer als keiner: Er erzeugt Vertrauen in Typen, die niemand
 * nachgeführt hat. Was hier steht, ist bewusst klein und deckt genau die
 * Endpunkte ab, die diese Oberfläche benutzt.
 */

export type LaufStatus =
  | "queued"
  | "planning"
  | "executing"
  | "awaiting_confirmation"
  | "completed"
  | "failed"
  | "cancelled"
  | "budget_exceeded";

export interface PlanSchritt {
  seq: number;
  kind: "tool" | "agent" | "llm" | "confirm";
  target: string;
  description: string;
  depends_on: number[];
  optional: boolean;
  status: "done" | "ready" | "waiting" | "blocked";
}

export interface LaufZeile {
  id: string;
  status: LaufStatus;
  trigger: string;
  taint_level: "clean" | "tainted";
  data_class: string;
  intent: string | null;
  is_multi_step: boolean;
  trace_id: string;
  started_at: string;
  finished_at: string | null;
  goal: string | null;
  /** Bei ``GET /runs`` leer — der Plan kostet je Schritt eine
   * Berechtigungsabfrage und wird nur für einen einzelnen Lauf gefüllt. */
  plan: PlanSchritt[];
}

export interface VorschauFeld {
  label: string;
  value: string;
  /** ``normal`` | ``warn`` | ``critical`` — Empfänger außerhalb bekannter
   * Kontakte werden hervorgehoben (docs/10-ui.md §7). */
  emphasis: string;
  truncated: boolean;
}

export interface OffeneAktion {
  id: string;
  run_id: string;
  tool_name: string;
  risk: string;
  reason: string;
  requested_channel: string;
  preview_title: string;
  preview_fields: VorschauFeld[];
  reversible: boolean;
  warnings: string[];
  expires_at: string;
  /** ``null`` für Bestätigungen einer **anderen** Sitzung: Was man dort nicht
   * einlösen darf, bekommt man auch nicht zu sehen. */
  nonce: string | null;
}

export interface SchrittErgebnis {
  status: string;
  reason: string;
  run_status: string;
  taint_level: string;
  display: string;
  data: Record<string, unknown> | null;
  action_id: string | null;
  code: string | null;
}

export interface ErteilteSicht {
  mode: "allow" | "confirm" | "deny";
  constraints: Record<string, unknown>;
  granted_at: string;
  expires_at: string | null;
  /** Abgelaufen, aber noch vorhanden — der verwirrendste Zustand, wenn ihn
   * niemand benennt. */
  expired: boolean;
}

export interface ScopeSicht {
  name: string;
  description: string;
  risk_level: string;
  /** Die **Empfehlung** des Katalogs, nicht die Erteilung. */
  default_mode: "allow" | "confirm" | "deny";
  /** ``null`` heißt: nicht erteilt. Nicht: verboten, und nicht: erlaubt. */
  granted: ErteilteSicht | null;
}

export interface Aufruf {
  id: string;
  tool_name: string;
  status: string;
  step_seq: number | null;
  created_at: string;
  executed_at: string | null;
  /** Momentaufnahme: ausgeführt, Werkzeug mit Rücknahme, Frist läuft noch.
   * Verbindlich entscheidet der Server beim Zurücknehmen. */
  undoable: boolean;
}
