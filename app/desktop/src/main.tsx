import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import DesktopErrorBoundary from "./app/DesktopErrorBoundary";
import { installRendererCrashHandlers } from "./app/rendererDiagnostics";
import "./styles.css";

installRendererCrashHandlers();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <DesktopErrorBoundary>
      <App />
    </DesktopErrorBoundary>
  </React.StrictMode>,
);
