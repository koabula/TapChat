import type { ReactNode } from "react";

export default function OnboardingLayout({
  title,
  subtitle,
  actions,
  children,
}: {
  title: string;
  subtitle: string;
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
      </div>
    </div>
  );
}
