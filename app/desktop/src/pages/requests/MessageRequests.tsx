import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";

import type { MessageRequestItem, CoreOutput } from "@/lib/types";

export default function MessageRequests() {
  const navigate = useNavigate();
  const [requests, setRequests] = useState<MessageRequestItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);

  useEffect(() => {
    loadRequests();
  }, []);

  const loadRequests = async () => {
    setLoading(true);
    try {
      const result = await invoke<CoreOutput>("list_message_requests");
      if (result.view_model?.message_requests) {
        setRequests(result.view_model.message_requests);
      }
    } catch (err) {
      console.error("Failed to load message requests:", err);
    } finally {
      setLoading(false);
    }
  };

  const formatTime = (timestamp: number) => {
    const diff = Date.now() - timestamp;
    const hours = Math.floor(diff / (1000 * 60 * 60));
    if (hours < 1) return "Just now";
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  };

  const handleAction = async (requestId: string, action: "accept" | "reject") => {
    setActing(requestId);
    try {
      await invoke("act_on_message_request", { requestId, action });
      // Remove from list
      setRequests((prev) => prev.filter((r) => r.request_id !== requestId));
    } catch (err) {
      console.error("Failed to action request:", err);
    } finally {
      setActing(null);
    }
  };

  return (
    <div className="flex h-screen bg-base">
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <header className="flex items-center p-3 border-b border-default">
          <button
            className="btn btn-ghost px-2"
            onClick={() => navigate("/")}
          >
            ←
          </button>
          <h1 className="font-semibold text-primary-color ml-2">
            Message Requests ({requests.length})
          </h1>
        </header>

        {/* Request list */}
        <div className="flex-1 overflow-y-auto p-4">
          {loading && (
            <div className="text-center text-muted-color">Loading...</div>
          )}

          {!loading && requests.length === 0 && (
            <div className="text-center text-muted-color">
              <p>No pending message requests</p>
            </div>
          )}

          {!loading && requests.map((req) => (
            <div
              key={req.request_id}
              className="card mb-4"
            >
              <div className="flex items-center gap-3 mb-2">
                <div className="avatar">
                  <span>{req.sender_display_name?.[0] || "?"}</span>
                </div>
                <div>
                  <span className="text-primary-color">
                    {req.sender_display_name || "Unknown"}
                  </span>
                  <span className="text-muted-color text-xs block truncate">
                    {req.sender_user_id}
                  </span>
                </div>
              </div>

              <div className="text-secondary-color text-sm mb-2">
                {req.message_count} messages · First seen {formatTime(req.first_seen_at)}
              </div>

              <div className="flex gap-2">
                <button
                  className="btn btn-primary"
                  onClick={() => handleAction(req.request_id, "accept")}
                  disabled={acting === req.request_id}
                >
                  Accept
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() => handleAction(req.request_id, "reject")}
                  disabled={acting === req.request_id}
                >
                  Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}