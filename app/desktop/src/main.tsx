import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { applyThemePreference, getStoredThemePreference } from "./lib/theme";
import "./styles/globals.css";

applyThemePreference(getStoredThemePreference());

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
