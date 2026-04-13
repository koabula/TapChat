import React, { useEffect, useState } from "react";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";

interface UpdateState {
  checking: boolean;
  updateAvailable: boolean;
  update?: Update;
  downloading: boolean;
  downloaded: boolean;
  progress: number;
  error?: string;
}

export function useAutoUpdate() {
  const [state, setState] = useState<UpdateState>({
    checking: false,
    updateAvailable: false,
    downloading: false,
    downloaded: false,
    progress: 0,
  });

  useEffect(() => {
    checkForUpdates();
  }, []);

  const checkForUpdates = async () => {
    setState((prev) => ({ ...prev, checking: true, error: undefined }));
    try {
      const update = await check();
      if (update) {
        setState((prev) => ({ ...prev, checking: false, updateAvailable: true, update }));
      } else {
        setState((prev) => ({ ...prev, checking: false, updateAvailable: false }));
      }
    } catch (err) {
      setState((prev) => ({ ...prev, checking: false, error: String(err) }));
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
    } catch (err) {
      setState((prev) => ({ ...prev, downloading: false, error: String(err) }));
    }
  };

  return { ...state, checkForUpdates, downloadAndInstall };
}

export function UpdateNotification(): React.ReactElement | null {
  const { updateAvailable, update, downloading, downloaded, progress, error, downloadAndInstall } = useAutoUpdate();

  if (!updateAvailable && !error) return null;

  const progressPercent = Math.round(progress);

  return React.createElement("div", { className: "fixed bottom-4 right-4 z-50" },
    updateAvailable && update && React.createElement("div", { className: "card shadow-lg p-4 max-w-sm bg-surface border border-default" },
      React.createElement("p", { className: "font-medium text-primary-color mb-2" }, "New Version Available"),
      React.createElement("p", { className: "text-sm text-secondary-color mb-2" }, "Version " + update.version + " ready."),
      downloading && React.createElement("div", { className: "mb-3" },
        React.createElement("p", { className: "text-xs text-muted-color mb-1" }, "Downloading: " + progressPercent + " percent"),
        React.createElement("div", { className: "w-full bg-surface-elevated rounded h-2" },
          React.createElement("div", { className: "bg-primary rounded h-2", style: { width: progressPercent } })
        )
      ),
      downloaded && React.createElement("p", { className: "text-sm status-success mb-3" }, "Complete! Restarting..."),
      error && React.createElement("p", { className: "text-sm status-error mb-3" }, error),
      !downloading && !downloaded && React.createElement("button", { className: "btn btn-primary", onClick: downloadAndInstall }, "Install")
    )
  );
}
