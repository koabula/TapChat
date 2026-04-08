import type { DesktopController } from "./types";
import OnboardingLayout from "../components/onboarding/OnboardingLayout";
import ChooseProfileStep from "../components/onboarding/ChooseProfileStep";
import IdentityStep from "../components/onboarding/IdentityStep";
import CloudflareSetupStep from "../components/onboarding/CloudflareSetupStep";

export default function OnboardingApp({ controller }: { controller: DesktopController }) {
  const { state } = controller;

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
    <OnboardingLayout
      title="Set up this desktop profile"
      subtitle="Create or open a profile, establish device identity, then bind Cloudflare transport."
      error={state.error}
      success={state.success}
      actions={(
        <button className="ghost-button compact-button" disabled={state.loading} onClick={() => void controller.chooseExistingProfileDirectory()}>
          Open existing profile
        </button>
      )}
    >
      {content}
    </OnboardingLayout>
  );
}
