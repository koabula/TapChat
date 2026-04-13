import { useState } from "react";
import { useNavigate, useParams } from "react-router";
import { invoke } from "@tauri-apps/api/core";

export default function ContactDetail() {
  const navigate = useNavigate();
  const { id: userId } = useParams();
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = async () => {
    if (!userId) return;
    setRefreshing(true);
    try {
      await invoke("refresh_contact", { userId });
    } catch (err) {
      console.error("Failed to refresh:", err);
    } finally {
      setRefreshing(false);
    }
  };

  const handleStartChat = async () => {
    if (!userId) return;
    try {
      const result = await invoke<{ conversation_id: string }>("create_conversation", {
        peerUserId: userId,
      });
      navigate(`/chat/${result.conversation_id}`);
    } catch (err) {
      console.error("Failed to create conversation:", err);
    }
  };

  return (
    <div className="flex h-screen bg-base">
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <header className="flex items-center p-3 border-b border-default">
          <button
            className="btn btn-ghost px-2"
            onClick={() => navigate("/contacts")}
          >
            ←
          </button>
          <h1 className="font-semibold text-primary-color ml-2">
            Contact Details
          </h1>
          <button
            className="btn btn-ghost ml-auto"
            onClick={handleRefresh}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>
        </header>

        {/* Content */}
        <div className="p-6">
          {/* Avatar */}
          <div className="flex items-center justify-center mb-4">
            <div className="w-20 h-20 rounded-full bg-surface-elevated flex items-center justify-center">
              <span className="text-3xl">{userId?.[0] || "?"}</span>
            </div>
          </div>

          {/* Info */}
          <div className="space-y-4">
            <div className="card">
              <label className="text-muted-color text-xs block mb-1">User ID</label>
              <span className="text-primary-color truncate">{userId}</span>
            </div>

            <div className="card">
              <label className="text-muted-color text-xs block mb-1">Devices</label>
              <span className="text-primary-color">1 device</span>
            </div>

            <div className="card">
              <label className="text-muted-color text-xs block mb-1">Last refreshed</label>
              <span className="text-primary-color">Just now</span>
            </div>
          </div>

          {/* Actions */}
          <div className="mt-6 space-y-2">
            <button
              className="btn btn-primary w-full"
              onClick={handleStartChat}
            >
              Start Conversation
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}