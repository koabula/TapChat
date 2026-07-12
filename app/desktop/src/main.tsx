import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { applyThemePreference, getStoredThemePreference } from "./lib/theme";
import { installProductionLogGuard } from "./lib/safeLogger";
import "./styles/globals.css";

installProductionLogGuard();
applyThemePreference(getStoredThemePreference());

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
