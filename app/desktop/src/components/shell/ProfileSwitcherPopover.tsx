import type { ProfileSummary } from "../../lib/types";

export default function ProfileSwitcherPopover({
  activeProfile,
  onOpenExisting,
  onRevealCurrent,
  onCreateProfile,
  loading,
}: {
  activeProfile: ProfileSummary | null;
  onOpenExisting: () => Promise<void>;
  onRevealCurrent: () => Promise<void>;
  onCreateProfile: () => Promise<void>;
  loading: boolean;
}) {
  return (
    <div className="profile-switcher">
      {activeProfile && (
        <div className="profile-switcher-current">
          <div className="section-label">Current profile</div>
          <div className="profile-current-card">
            <strong>{activeProfile.name}</strong>
            <small>{activeProfile.user_id ?? "No identity yet"}</small>
          </div>
        </div>
      )}
      <div className="profile-switcher-actions">
        <button className="ghost-button compact-button full-width" disabled={loading} onClick={() => void onOpenExisting()}>
          Open another profile directory
        </button>
        <button className="ghost-button compact-button full-width" disabled={loading || !activeProfile} onClick={() => void onRevealCurrent()}>
          Reveal current profile directory
        </button>
        <button className="primary-button compact-button full-width" disabled={loading} onClick={() => void onCreateProfile()}>
          Create new profile
        </button>
      </div>
    </div>
  );
}
