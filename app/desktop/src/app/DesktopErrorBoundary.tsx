import React from "react";
import { logRendererCrash } from "./rendererDiagnostics";

type Props = {
  children: React.ReactNode;
};

type State = {
  hasError: boolean;
};

export default class DesktopErrorBoundary extends React.Component<Props, State> {
  state: State = {
    hasError: false,
  };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    void logRendererCrash(
      "error-boundary",
      `${error.message} stack=${error.stack ?? ""} componentStack=${info.componentStack ?? ""}`,
    );
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="conversation-stage conversation-scroll">
          <div className="empty-state conversation-empty-state">
            <h3>Desktop UI hit an unexpected error</h3>
            <p>Restart the app and check the desktop trace log for renderer details.</p>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
