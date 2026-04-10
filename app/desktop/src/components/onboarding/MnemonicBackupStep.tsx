export default function MnemonicBackupStep({
  mnemonic,
  onBack,
  canGoBack,
  onContinue,
  disabled,
}: {
  mnemonic: string;
  onBack: () => void;
  canGoBack: boolean;
  onContinue: () => void;
  disabled: boolean;
}) {
  return (
    <section className="onboarding-step">
      <div className="onboarding-step-header">
        <div className="onboarding-step-actions">
          <button className="ghost-button compact-button" disabled={!canGoBack || disabled} onClick={onBack}>
            Back
          </button>
        </div>
        <span className="eyebrow">Step 2.5</span>
        <h2>Back up your recovery phrase</h2>
        <p>Write this phrase down and keep it offline. You must have it to recover this profile later.</p>
      </div>

      <label>
        <span>Recovery phrase</span>
        <textarea className="onboarding-mnemonic-display" rows={4} readOnly value={mnemonic} />
      </label>

      <div className="button-row">
        <button className="primary-button" disabled={disabled || !mnemonic.trim()} onClick={onContinue}>
          I backed it up, continue
        </button>
      </div>
    </section>
  );
}
