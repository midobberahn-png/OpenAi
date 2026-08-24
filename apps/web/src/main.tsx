import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import "./stil.css";

const wurzel = document.getElementById("wurzel");
if (wurzel === null) {
  throw new Error("Kein Wurzelelement — das HTML passt nicht zum Skript.");
}

createRoot(wurzel).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
