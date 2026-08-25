import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/**
 * Entwicklungsserver und Bau der Oberfläche.
 *
 * **Der Proxy ist keine Bequemlichkeit, sondern Voraussetzung.** Die Anmeldung
 * läuft über ein Sitzungs-Cookie und über WebAuthn, und beides hängt am
 * Origin: Ein Cookie mit `SameSite` gilt für die Seite, die es gesetzt hat, und
 * ein Passkey ist an `rp_id` gebunden. Liefe die Oberfläche unter `:5173` und
 * die API unter `:8000`, wären das zwei Origins — die Anmeldung ließe sich in
 * der Entwicklung nicht durchspielen, und man baute eine Oberfläche gegen
 * Verhältnisse, die es im Betrieb nicht gibt.
 *
 * Im Betrieb stellt sich die Frage nicht: Dort liefert die API die gebauten
 * Dateien selbst aus (`jarvis_api.main`), und alles ist ohnehin ein Origin.
 */
const API = "http://127.0.0.1:8000";
const PFADE = ["/auth", "/runs", "/actions", "/permissions", "/invocations", "/audit", "/calendar"];

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      PFADE.map((pfad) => [pfad, { target: API, changeOrigin: false }]),
    ),
  },
  build: {
    // Wird von der API ausgeliefert; der Pfad steht in ``main.py``.
    outDir: "dist",
    emptyOutDir: true,
  },
});
