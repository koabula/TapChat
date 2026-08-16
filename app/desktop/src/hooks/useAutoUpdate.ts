import React, { useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { relaunch } from "@tauri-apps/plugin-process";
import { open } from "@tauri-apps/plugin-shell";
import { check, type Update } from "@tauri-apps/plugin-updater";

const GITHUB_LATEST_RELEASE_API = "https://api.github.com/repos/koabula/TapChat/releases/latest";

interface ManualRelease {
  version: string;
  tagName: string;
  htmlUrl: string;
}

interface UpdateState {
  checking: boolean;
  checked: boolean;
  updateAvailable: boolean;
  update?: Update;
  manualUpdateAvailable: boolean;
  manualRelease?: ManualRelease;
  downloading: boolean;
  downloaded: boolean;
  progress: number;
  warning?: string;
  error?: string;
}

export function useAutoUpdate() {
  const [state, setState] = useState<UpdateState>({
    checking: false,
    checked: false,
    updateAvailable: false,
    manualUpdateAvailable: false,
    downloading: false,
    downloaded: false,
    progress: 0,
  });

  const checkForUpdates = async () => {
    setState((prev) => ({
      ...prev,
      checking: true,
      checked: false,
      updateAvailable: false,
      update: undefined,
      manualUpdateAvailable: false,
      manualRelease: undefined,
      warning: undefined,
      error: undefined,
    }));
    try {
      const update = await check();
      if (update) {
        setState((prev) => ({
          ...prev,
          checking: false,
          checked: true,
          updateAvailable: true,
          update,
          manualUpdateAvailable: false,
          manualRelease: undefined,
        }));
      } else {
        setState((prev) => ({
          ...prev,
          checking: false,
          checked: true,
          updateAvailable: false,
        }));
      }
    } catch {
      await checkGitHubReleaseFallback();
    }
  };

  const downloadAndInstall = async () => {
    const { update } = state;
    if (!update) return;
    setState((prev) => ({ ...prev, downloading: true, progress: 0 }));
    try {
      let downloaded = 0;
      let contentLength = 0;
      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case "Started":
            contentLength = event.data.contentLength || 0;
            break;
          case "Progress":
            downloaded += event.data.chunkLength;
            const prog = contentLength > 0 ? (downloaded / contentLength) * 100 : 50;
            setState((prev) => ({ ...prev, progress: Math.round(prog) }));
            break;
          case "Finished":
            setState((prev) => ({ ...prev, downloaded: true, downloading: false }));
            break;
        }
      });
      await relaunch();
    } catch {
      setState((prev) => ({
        ...prev,
        downloading: false,
        error: "The update could not be installed. Try again later.",
      }));
    }
  };

  const openManualRelease = async () => {
    const release = state.manualRelease;
    if (!release) return;
    try {
      await open(release.htmlUrl);
    } catch {
      setState((prev) => ({
        ...prev,
        error: "The release page could not be opened.",
      }));
    }
  };

  const checkGitHubReleaseFallback = async () => {
    try {
      const [currentVersion, release] = await Promise.all([
        getVersion(),
        fetchLatestGitHubRelease(),
      ]);

      if (!release) {
        setState((prev) => ({
          ...prev,
          checking: false,
          checked: true,
          updateAvailable: false,
          warning: "Signed update metadata is not available yet, and no GitHub release was found.",
        }));
        return;
      }

      const latestVersion = normalizeVersion(release.tagName);
      if (!latestVersion) {
        setState((prev) => ({
          ...prev,
          checking: false,
          checked: true,
          updateAvailable: false,
          warning: `Signed update metadata is not available yet. Latest GitHub release ${release.tagName} is not a supported app version.`,
        }));
        return;
      }

      if (compareVersions(latestVersion, currentVersion) > 0) {
        setState((prev) => ({
          ...prev,
          checking: false,
          checked: true,
          updateAvailable: false,
          manualUpdateAvailable: true,
          manualRelease: {
            ...release,
            version: latestVersion,
          },
          warning: "Signed in-app update metadata is not available yet. Download the latest release from GitHub.",
        }));
        return;
      }

      setState((prev) => ({
        ...prev,
        checking: false,
        checked: true,
        updateAvailable: false,
        warning: "No newer GitHub release was found. Signed in-app update metadata is not available yet.",
      }));
    } catch {
      setState((prev) => ({
        ...prev,
        checking: false,
        checked: true,
        error: "Could not check updates because signed update metadata is unavailable and GitHub release lookup failed.",
      }));
    }
  };

  return { ...state, checkForUpdates, downloadAndInstall, openManualRelease };
}

export const useManualUpdate = useAutoUpdate;

async function fetchLatestGitHubRelease(): Promise<ManualRelease | null> {
  const response = await fetch(GITHUB_LATEST_RELEASE_API, {
    headers: {
      Accept: "application/vnd.github+json",
    },
  });
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`GitHub release lookup failed with HTTP ${response.status}`);
  }
  const json = (await response.json()) as {
    tag_name?: string;
    html_url?: string;
    prerelease?: boolean;
    draft?: boolean;
  };
  if (json.draft || json.prerelease || !json.tag_name || !json.html_url) {
    return null;
  }
  return {
    version: normalizeVersion(json.tag_name) ?? json.tag_name,
    tagName: json.tag_name,
    htmlUrl: json.html_url,
  };
}

function normalizeVersion(value: string): string | null {
  const normalized = value.trim().replace(/^v/i, "");
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(normalized) ? normalized : null;
}

function compareVersions(left: string, right: string): number {
  const leftParts = parseVersionCore(left);
  const rightParts = parseVersionCore(right);
  for (let index = 0; index < 3; index += 1) {
    const diff = leftParts[index] - rightParts[index];
    if (diff !== 0) return diff;
  }
  return 0;
}

function parseVersionCore(version: string): [number, number, number] {
  const [major = "0", minor = "0", patch = "0"] = version.split(/[+-]/)[0].split(".");
  return [Number(major), Number(minor), Number(patch)];
}

export function UpdateNotification(): React.ReactElement | null {
  const {
    updateAvailable,
    manualUpdateAvailable,
    manualRelease,
    update,
    downloading,
    downloaded,
    progress,
    error,
    warning,
    downloadAndInstall,
    openManualRelease,
  } = useAutoUpdate();

  if (!updateAvailable && !manualUpdateAvailable && !error && !warning) return null;

  const progressPercent = Math.round(progress);

  return React.createElement("div", { className: "fixed bottom-4 right-4 z-50" },
    updateAvailable && update && React.createElement("div", { className: "card shadow-lg p-4 max-w-sm bg-surface border border-default" },
      React.createElement("p", { className: "font-medium text-primary-color mb-2" }, "New Version Available"),
      React.createElement("p", { className: "text-sm text-secondary-color mb-2" }, "Version " + update.version + " ready."),
      downloading && React.createElement("div", { className: "mb-3" },
        React.createElement("p", { className: "text-xs text-muted-color mb-1" }, "Downloading: " + progressPercent + " percent"),
        React.createElement("div", { className: "w-full bg-surface-elevated rounded h-2" },
          React.createElement("div", { className: "bg-primary rounded h-2", style: { width: `${progressPercent}%` } })
        )
      ),
      downloaded && React.createElement("p", { className: "text-sm status-success mb-3" }, "Complete! Restarting..."),
      error && React.createElement("p", { className: "text-sm status-error mb-3" }, error),
      !downloading && !downloaded && React.createElement("button", { className: "btn btn-primary", onClick: downloadAndInstall }, "Install")
    ),
    manualUpdateAvailable && manualRelease && React.createElement("div", { className: "card shadow-lg p-4 max-w-sm bg-surface border border-default" },
      React.createElement("p", { className: "font-medium text-primary-color mb-2" }, "New Version Available"),
      React.createElement("p", { className: "text-sm text-secondary-color mb-2" }, "Version " + manualRelease.version + " is available on GitHub."),
      warning && React.createElement("p", { className: "text-sm status-warning mb-3" }, warning),
      React.createElement("button", { className: "btn btn-primary", onClick: openManualRelease }, "Open Release")
    )
  );
}
