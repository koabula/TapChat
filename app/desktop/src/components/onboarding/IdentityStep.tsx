export default function IdentityStep({
  deviceName,
  setDeviceName,
  mnemonic,
  setMnemonic,
  onBack,
  canGoBack,
  onCreate,
  onRecover,
  disabled,
}: {
  deviceName: string;
  setDeviceName: (value: string) => void;
  mnemonic: string;
  setMnemonic: (value: string) => void;
  onBack: () => void;
  canGoBack: boolean;
  onCreate: () => Promise<void>;
  onRecover: () => Promise<void>;
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
        <span className="eyebrow">Step 2</span>
        <h2>Create or recover this device</h2>
        <p>Create a fresh identity for this desktop, or recover an existing identity with its mnemonic.</p>
      </div>
      <div className="onboarding-form-grid">
        <label>
          <span>Device name</span>
          <input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} />
        </label>
        <label>
          <span>Recovery mnemonic</span>
          <textarea rows={5} value={mnemonic} onChange={(event) => setMnemonic(event.target.value)} placeholder="Only required when recovering an existing identity." />
        </label>
      </div>
      <div className="button-row">
        <button className="primary-button" disabled={disabled || !deviceName.trim()} onClick={() => void onCreate()}>
          Create identity
        </button>
        <button className="ghost-button" disabled={disabled || !deviceName.trim() || !mnemonic.trim()} onClick={() => void onRecover()}>
          Recover identity
        </button>
      </div>
    </section>
  );
}
