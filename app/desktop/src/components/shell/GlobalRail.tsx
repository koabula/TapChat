import type { Dispatch, SetStateAction } from "react";
import type { ActiveSection, DrawerMode } from "../../app/types";
import type { ProfileSummary } from "../../lib/types";
import ProfileSwitcherPopover from "./ProfileSwitcherPopover";
import {
  ChatsIcon,
  ContactsIcon,
  DiagnosticsIcon,
  MoonIcon,
  PolicyIcon,
  RequestsIcon,
  RuntimeIcon,
  SunIcon,
} from "../icons/RailIcons";

export default function GlobalRail({
  activeSection,
  setActiveSection,
  drawerMode,
  setDrawerMode,
  activeProfile,
  profileSwitcherOpen,
  setProfileSwitcherOpen,
  onOpenExistingProfile,
  onCreateProfile,
  onRevealCurrentProfileDirectory,
  loading,
  theme,
  onToggleTheme,
}: {
  activeSection: ActiveSection;
  setActiveSection: Dispatch<SetStateAction<ActiveSection>>;
  drawerMode: DrawerMode;
  setDrawerMode: Dispatch<SetStateAction<DrawerMode>>;
  activeProfile: ProfileSummary | null;
  profileSwitcherOpen: boolean;
  setProfileSwitcherOpen: Dispatch<SetStateAction<boolean>>;
  onOpenExistingProfile: () => Promise<void>;
  onCreateProfile: () => Promise<void>;
  onRevealCurrentProfileDirectory: () => Promise<void>;
  loading: boolean;
  theme: "light" | "dark";
  onToggleTheme: () => void;
}) {
  return (
    <aside className="global-rail">
      <div className="rail-brand"><div className="brand-mark">T</div></div>
      <div className="rail-actions">
        <button className={activeSection === "chats" ? "rail-button active" : "rail-button"} onClick={() => { setActiveSection("chats"); setDrawerMode("closed"); }} title="Chats" aria-label="Chats"><ChatsIcon /></button>
        <button className={activeSection === "contacts" ? "rail-button active" : "rail-button"} onClick={() => { setActiveSection("contacts"); setDrawerMode("closed"); }} title="Contacts" aria-label="Contacts"><ContactsIcon /></button>
        <button className={activeSection === "requests" ? "rail-button active" : "rail-button"} onClick={() => { setActiveSection("requests"); setDrawerMode("closed"); }} title="Requests" aria-label="Requests"><RequestsIcon /></button>
        <button className={drawerMode === "runtime" ? "rail-button active" : "rail-button"} onClick={() => setDrawerMode((current) => current === "runtime" ? "closed" : "runtime")} title="Runtime" aria-label="Runtime"><RuntimeIcon /></button>
        <button className={drawerMode === "policy" ? "rail-button active" : "rail-button"} onClick={() => setDrawerMode((current) => current === "policy" ? "closed" : "policy")} title="Policy" aria-label="Policy"><PolicyIcon /></button>
        <button className={drawerMode === "diagnostics" ? "rail-button active" : "rail-button"} onClick={() => setDrawerMode((current) => current === "diagnostics" ? "closed" : "diagnostics")} title="Diagnostics" aria-label="Diagnostics"><DiagnosticsIcon /></button>
      </div>
      <div className="rail-spacer" />
      <button className="rail-button" title="Toggle theme" aria-label="Toggle theme" onClick={onToggleTheme}>
        {theme === "dark" ? <SunIcon /> : <MoonIcon />}
      </button>
      <div className="profile-rail">
        <button className={profileSwitcherOpen ? "profile-trigger active" : "profile-trigger"} title={activeProfile?.name ?? "Profiles"} onClick={() => setProfileSwitcherOpen((current) => !current)}>
          <span>{(activeProfile?.name ?? "P").slice(0, 1).toUpperCase()}</span>
        </button>
        {profileSwitcherOpen && (
          <ProfileSwitcherPopover
            activeProfile={activeProfile}
            onOpenExisting={onOpenExistingProfile}
            onCreateProfile={onCreateProfile}
            onRevealCurrent={onRevealCurrentProfileDirectory}
            loading={loading}
          />
        )}
      </div>
    </aside>
  );
}
