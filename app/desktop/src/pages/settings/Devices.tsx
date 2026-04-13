import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useNavigate } from "react-router";

interface Device {
  device_id: string;
  name: string;
  status: string;
  last_active: number | null;
  is_current: boolean;
}

interface IdentityInfo {
  user_id: string;
  device_id: string;
  mnemonic: string;
}

export default function Devices() {
  const navigate = useNavigate();
  const [devices, setDevices] = useState<Device[]>([]);
  const [identityInfo, setIdentityInfo] = useState<IdentityInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [showMnemonic, setShowMnemonic] = useState(false);
  const [revokingDevice, setRevokingDevice] = useState<string | null>(null);

  useEffect(() => {
    loadDevices();
  }, []);

  const loadDevices = async () => {
    setLoading(true);
    try {
      // Get identity info
      const identity = await invoke<IdentityInfo | null>("get_identity_info");
      setIdentityInfo(identity);

      if (identity) {
        // For now, we only have one device (current)
        // In future, we'd query all devices from the backend
        setDevices([
          {
            device_id: identity.device_id,
            name: "This Device",
            status: "active",
            last_active: Date.now(),
            is_current: true,
          },
        ]);
      }
    } catch (err) {
      console.error("Failed to load devices:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeDevice = async (deviceId: string) => {
    if (deviceId === identityInfo?.device_id) {
      alert("Cannot revoke your current device");
      return;
    }

    setRevokingDevice(deviceId);
    try {
      await invoke("update_device_status", {
        targetDeviceId: deviceId,
        status: "revoked",
      });
      loadDevices();
    } catch (err) {
      console.error("Failed to revoke device:", err);
      alert(String(err));
    } finally {
      setRevokingDevice(null);
    }
  };

  const handleAddDevice = async () => {
    // This would initiate adding a new device
    // For now, show a message
    alert("To add another device, install TapChat on that device and use your recovery phrase during setup.");
  };

  const formatLastActive = (timestamp: number | null) => {
    if (!timestamp) return "Unknown";
    const now = Date.now();
    const diff = now - timestamp;

    if (diff < 60000) return "Just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)} min ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)} hours ago`;
    return new Date(timestamp).toLocaleDateString();
  };

  return (
    <div className="flex flex-col h-screen bg-base">
      {/* Header */}
      <header className="flex items-center p-3 border-b border-default">
        <button className="btn btn-ghost px-2" onClick={() => navigate("/settings")}>
          ← Back
        </button>
        <h1 className="ml-2 text-lg font-medium text-primary-color">Device Management</h1>
      </header>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {loading && (
          <div className="text-center text-muted-color">Loading...</div>
        )}

        {!loading && !identityInfo && (
          <div className="text-center">
            <p className="text-muted-color mb-4">No identity loaded</p>
            <button className="btn btn-primary" onClick={() => navigate("/onboarding")}>
              Set Up Identity
            </button>
          </div>
        )}

        {!loading && identityInfo && (
          <>
            {/* Identity info */}
            <div className="card mb-4">
              <h2 className="text-sm font-medium text-muted-color mb-2">Your Identity</h2>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-secondary-color">User ID</span>
                  <span className="text-primary-color text-sm truncate max-w-[200px]">
                    {identityInfo.user_id.slice(0, 12)}...
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-secondary-color">Current Device</span>
                  <span className="text-primary-color text-sm truncate max-w-[200px]">
                    {identityInfo.device_id.slice(0, 12)}...
                  </span>
                </div>
              </div>
            </div>

            {/* Recovery phrase */}
            <div className="card mb-4">
              <h2 className="text-sm font-medium text-muted-color mb-2">Recovery Phrase</h2>
              <div className="flex items-center justify-between">
                <span className="text-secondary-color text-sm">
                  {showMnemonic ? identityInfo.mnemonic : "••••••••••••"}
                </span>
                <button
                  className="btn btn-ghost text-sm"
                  onClick={() => setShowMnemonic(!showMnemonic)}
                >
                  {showMnemonic ? "Hide" : "Show"}
                </button>
              </div>
              {showMnemonic && (
                <p className="status-warning text-sm mt-2">
                  Keep this phrase secret! It's the only way to recover your identity.
                </p>
              )}
            </div>

            {/* Device list */}
            <h2 className="text-sm font-medium text-muted-color mb-2">Your Devices</h2>
            <div className="space-y-2">
              {devices.map((device) => (
                <div key={device.device_id} className="card flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-primary-color">{device.name}</span>
                      {device.is_current && (
                        <span className="badge badge-success text-xs">Current</span>
                      )}
                    </div>
                    <div className="text-muted-color text-sm">
                      {device.device_id.slice(0, 16)}...
                    </div>
                    <div className="text-muted-color text-xs">
                      Last active: {formatLastActive(device.last_active)}
                    </div>
                  </div>
                  {!device.is_current && (
                    <button
                      className="btn btn-ghost status-error text-sm"
                      onClick={() => handleRevokeDevice(device.device_id)}
                      disabled={revokingDevice === device.device_id}
                    >
                      {revokingDevice === device.device_id ? "Revoking..." : "Revoke"}
                    </button>
                  )}
                </div>
              ))}
            </div>

            {/* Add device button */}
            <button
              className="btn btn-secondary w-full mt-4"
              onClick={handleAddDevice}
            >
              Add Another Device
            </button>
          </>
        )}
      </div>
    </div>
  );
}