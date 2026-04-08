export default function ChooseProfileStep({
  createName,
  setCreateName,
  createRoot,
  setCreateRoot,
  onBrowse,
  onCreate,
  onOpenExisting,
  disabled,
}: {
  createName: string;
  setCreateName: (value: string) => void;
  createRoot: string;
  setCreateRoot: (value: string) => void;
  onBrowse: () => Promise<void>;
  onCreate: () => Promise<void>;
  onOpenExisting: () => Promise<void>;
  disabled: boolean;
}) {
  return (
    <section className="onboarding-step">
      <div className="onboarding-step-header">
        <span className="eyebrow">Step 1</span>
        <h2>Create or open a profile</h2>
        <p>Create a new profile for this desktop, or open an existing profile directory you already use on this machine.</p>
      </div>
      <div className="onboarding-form-grid">
        <label>
          <span>Profile name</span>
          <input value={createName} onChange={(event) => setCreateName(event.target.value)} />
        </label>
        <label>
          <span>Profile directory</span>
          <div className="inline-field">
            <input value={createRoot} onChange={(event) => setCreateRoot(event.target.value)} />
            <button className="ghost-button compact-button" onClick={() => void onBrowse()}>Browse</button>
          </div>
        </label>
      </div>
      <div className="button-row">
        <button className="primary-button" disabled={disabled || !createName.trim() || !createRoot.trim()} onClick={() => void onCreate()}>
          Create new profile
        </button>
        <button className="ghost-button" disabled={disabled} onClick={() => void onOpenExisting()}>
          Open existing profile
        </button>
      </div>
    </section>
  );
}
