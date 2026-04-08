import type { ReactNode } from "react";
import Banner from "../shared/Banner";

export default function OnboardingLayout({
  title,
  subtitle,
  error,
  success,
  actions,
  children,
}: {
  title: string;
  subtitle: string;
  error: string | null;
  success: string | null;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="onboarding-window">
      <div className="onboarding-window-inner compact">
        <header className="onboarding-hero">
          <div className="onboarding-brand-mark">T</div>
          <div className="onboarding-hero-copy">
            <span className="eyebrow">TapChat Desktop</span>
            <h1>{title}</h1>
            <p>{subtitle}</p>
          </div>
          {actions && <div className="onboarding-hero-actions">{actions}</div>}
        </header>
        <main className="onboarding-window-scroll">
          <div className="onboarding-flow-card">{children}</div>
        </main>
        {(error || success) && (
          <footer className="onboarding-status-bar">
            {error && <Banner tone="error" message={error} />}
            {success && <Banner tone="success" message={success} />}
          </footer>
        )}
      </div>
    </div>
  );
}
