import { useState } from "react";
import { Outlet, useNavigate } from "react-router";
import { Plus, Users, Settings } from "lucide-react";
import ConversationList from "./ConversationList";
import { NetworkIndicator } from "@/components/SystemBanner";
import { useMessageRequestsStore } from "@/store/requests";

export default function ChatLayout() {
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState("");
  const requests = useMessageRequestsStore((s) => s.requests);

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-base">
      {/* Sidebar */}
      <aside className="sidebar flex h-full w-72 min-h-0 flex-col">
        {/* Header */}
        <div className="flex items-center p-3 border-b border-default">
          <h1 className="font-semibold text-primary-color">TapChat</h1>
          <div className="ml-auto flex items-center gap-1">
            {/* Keyboard shortcut hint */}
            <span className="text-xs text-muted-color">Ctrl+N</span>
          </div>
        </div>

        {/* Network status indicator */}
        <NetworkIndicator />

        {/* Search */}
        <div className="p-2">
          <input
            className="input text-sm"
            placeholder="Search conversations..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        {/* Conversation list */}
        <div className="flex-1 overflow-y-auto overscroll-contain">
          <ConversationList searchQuery={searchQuery} />
        </div>

        {/* Message requests badge */}
        <button
          className="flex items-center gap-2 p-3 border-t border-default hover:bg-surface-elevated"
          onClick={() => navigate("/requests")}
        >
          <span className="text-secondary-color">Message Requests</span>
          {requests.length > 0 && (
            <span className="badge badge-primary">{requests.length}</span>
          )}
        </button>

        {/* Bottom nav */}
        <div className="flex items-center justify-around p-2 border-t border-default">
          <button
            className="btn btn-ghost px-2"
            title="New conversation (Ctrl+N)"
            onClick={() => navigate("/contacts")}
          >
            <Plus size={20} />
          </button>
          <button
            className="btn btn-ghost px-2"
            title="Contacts (Ctrl+2)"
            onClick={() => navigate("/contacts")}
          >
            <Users size={20} />
          </button>
          <button
            className="btn btn-ghost px-2"
            title="Settings (Ctrl+S)"
            onClick={() => navigate("/settings")}
          >
            <Settings size={20} />
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        <Outlet />
      </main>
    </div>
  );
}
