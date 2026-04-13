import { Outlet, useNavigate } from "react-router";
import ConversationList from "./ConversationList";
import { NetworkIndicator } from "@/components/SystemBanner";

export default function ChatLayout() {
  const navigate = useNavigate();

  return (
    <div className="flex h-screen bg-base">
      {/* Sidebar */}
      <aside className="w-72 sidebar flex flex-col">
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
          />
        </div>

        {/* Conversation list */}
        <div className="flex-1 overflow-y-auto">
          <ConversationList />
        </div>

        {/* Message requests badge */}
        <button
          className="flex items-center gap-2 p-3 border-t border-default hover:bg-surface-elevated"
          onClick={() => navigate("/requests")}
        >
          <span className="text-secondary-color">Message Requests</span>
          <span className="ml-auto badge badge-warning">
            2
          </span>
        </button>

        {/* Bottom nav */}
        <div className="flex items-center justify-around p-2 border-t border-default">
          <button
            className="btn btn-ghost px-2"
            title="New conversation (Ctrl+N)"
            onClick={() => navigate("/contacts")}
          >
            +
          </button>
          <button
            className="btn btn-ghost px-2"
            title="Contacts (Ctrl+2)"
            onClick={() => navigate("/contacts")}
          >
            👥
          </button>
          <button
            className="btn btn-ghost px-2"
            title="Settings (Ctrl+S)"
            onClick={() => navigate("/settings")}
          >
            ⚙
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col">
        <Outlet />
      </main>
    </div>
  );
}