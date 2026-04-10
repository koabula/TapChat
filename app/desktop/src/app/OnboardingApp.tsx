import { useEffect, useRef, useState } from "react";
import type { DesktopController } from "./types";
import OnboardingLayout from "../components/onboarding/OnboardingLayout";
import ChooseProfileStep from "../components/onboarding/ChooseProfileStep";
import IdentityStep from "../components/onboarding/IdentityStep";
import MnemonicBackupStep from "../components/onboarding/MnemonicBackupStep";
import CloudflareSetupStep from "../components/onboarding/CloudflareSetupStep";
import ToastHost, { type ToastItem } from "../components/shared/ToastHost";

export default function OnboardingApp({ controller }: { controller: DesktopController }) {
  const { state } = controller;
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextToastId = useRef(1);
  const lastSuccessRef = useRef<string | null>(null);
  const lastErrorRef = useRef<string | null>(null);

  useEffect(() => {
    if (!state.success) {
      lastSuccessRef.current = null;
      return;
    }
    const successMessage = state.success;
    if (lastSuccessRef.current === successMessage) {
      return;
    }
    lastSuccessRef.current = successMessage;
    const id = nextToastId.current++;
    setToasts((current) => [...current, { id, tone: "success", message: successMessage }]);
    const timeout = window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
    }, 3200);
    return () => window.clearTimeout(timeout);
  }, [state.success]);

  useEffect(() => {
    if (!state.error) {
      lastErrorRef.current = null;
      return;
    }
    const errorMessage = state.error;
    if (lastErrorRef.current === errorMessage) {
      return;
    }
    lastErrorRef.current = errorMessage;
    const id = nextToastId.current++;
    setToasts((current) => [...current, { id, tone: "error", message: errorMessage }]);
    const timeout = window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
    }, 5200);
    return () => window.clearTimeout(timeout);
  }, [state.error]);

  let content = (
    <ChooseProfileStep
      createName={controller.createName}
      setCreateName={controller.setCreateName}
      createRoot={controller.createRoot}
      setCreateRoot={controller.setCreateRoot}
      onBrowse={controller.chooseProfileRoot}
      onCreate={controller.handleCreateProfile}
      onOpenExisting={controller.chooseExistingProfileDirectory}
      disabled={state.loading}
    />
  );

  if (controller.onboardingViewStep === "identity") {
    content = (
      <IdentityStep
        deviceName={controller.deviceName}
        setDeviceName={controller.setDeviceName}
        mnemonic={controller.mnemonic}
        setMnemonic={controller.setMnemonic}
        onBack={controller.handleOnboardingBack}
        canGoBack={controller.canGoBackInOnboarding}
        onCreate={controller.handleIdentityCreate}
        onRecover={controller.handleIdentityRecover}
        disabled={state.loading}
      />
    );
  }

  if (controller.onboardingViewStep === "mnemonic_backup") {
    content = (
      <MnemonicBackupStep
        mnemonic={controller.mnemonic}
        onBack={controller.handleOnboardingBack}
        canGoBack={controller.canGoBackInOnboarding}
        onContinue={controller.handleConfirmMnemonicBackup}
        disabled={state.loading}
      />
    );
  }

  if (controller.onboardingViewStep === "runtime") {
    content = (
      <CloudflareSetupStep
        preflight={controller.preflight}
        wizard={controller.cloudflareWizard}
        overrides={controller.overrides}
        setOverrides={controller.setOverrides}
        customOpen={controller.customWizardOpen}
        setCustomOpen={controller.setCustomWizardOpen}
        onBack={controller.handleOnboardingBack}
        canGoBack={controller.canGoBackInOnboarding}
        onStart={controller.handleStartCloudflareWizard}
        onCancel={controller.handleCancelCloudflareWizard}
        onRefreshStatus={controller.handleRefreshRuntimeStatus}
        onImportBundle={controller.chooseDeploymentBundle}
        disabled={state.loading}
        pendingAction={controller.pendingAction}
      />
    );
  }

  return (
    <>
      <OnboardingLayout
        title="Set up this desktop profile"
        subtitle="Create or open a profile, establish device identity, then bind Cloudflare transport."
        actions={(
          <button className="ghost-button compact-button" disabled={state.loading} onClick={() => void controller.chooseExistingProfileDirectory()}>
            Open existing profile
          </button>
        )}
      >
        {content}
      </OnboardingLayout>
      <ToastHost
        toasts={toasts}
        onDismiss={(id) => setToasts((current) => current.filter((toast) => toast.id !== id))}
      />
    </>
  );
}
