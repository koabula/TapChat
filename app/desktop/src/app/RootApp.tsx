import { getCurrentWindow } from "@tauri-apps/api/window";
import MainApp from "./MainApp";
import OnboardingApp from "./OnboardingApp";
import { useDesktopController } from "./useDesktopController";

export default function RootApp() {
  const windowLabel = getCurrentWindow().label;
  const controller = useDesktopController(windowLabel);

  if (windowLabel === "onboarding") {
    return <OnboardingApp controller={controller} />;
  }

  return <MainApp controller={controller} />;
}
