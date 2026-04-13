import { useState } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";

interface MessageRequest {
  request_id: string;
  sender_user_id: string;
  sender_display_name: string | null;
  message_count: number;
  first_seen_at: number;
}

export default function MessageRequests() {
  const navigate = useNavigate();
  const [requests, setRequests] = useState<MessageRequest[]>([]);
  const [acting, setActing] = useState<string | null>(null);

  // Placeholder requests
  const displayRequests = requests.length > 0 ? requests : [
    { request_id: "r1", sender_user_id: "user:unknown1", sender_display_name: null, message_count: 3, first_seen_at: Date.now() - 7200000 },
    { request_id: "r2", sender_user_id: "user:unknown2", sender_display_name: null, message_count: 1, first_seen_at: Date.now() - 300000 },
  ];

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
            Message Requests ({displayRequests.length})
          </h1>
        </header>

        {/* Request list */}
        <div className="flex-1 overflow-y-auto p-4">
          {displayRequests.map((req) => (
            <div
              key={req.request_id}
              className="card mb-4"
            >
              <div className="flex items-center gap-3 mb-2">
                <div className="avatar">
                  <span>?</span>
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