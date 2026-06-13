import { useState } from "react";
import { Outlet, useLocation, useNavigate } from "react-router";
import {
  ContactRound,
  MessageCircle,
  Plus,
  Settings,
  UsersRound,
} from "lucide-react";

import { NetworkIndicator } from "@/components/SystemBanner";
import ConversationList from "@/pages/chat/ConversationList";
import { useMessageRequestsStore } from "@/store/requests";

function shellNavButtonClass(active: boolean) {
  return [
    "inline-flex h-9 w-9 items-center justify-center rounded-md transition-colors",
    active
      ? "bg-surface-elevated text-primary-color"
      : "text-secondary-color hover:bg-surface-elevated hover:text-primary-color",
  ].join(" ");
}

export default function AppShell() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchQuery, setSearchQuery] = useState("");
  const requests = useMessageRequestsStore((s) => s.requests);

  const pathname = location.pathname;
  const inConversation = pathname === "/" || pathname.startsWith("/chat/");
  const inGroups = pathname.startsWith("/groups");
  const inContacts = pathname.startsWith("/contacts");
  const inSettings = pathname.startsWith("/settings");

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-base">
      <aside className="sidebar flex h-full w-72 min-h-0 shrink-0 flex-col">
        <div className="flex h-12 items-center border-b border-subtle px-3">
          <button
            className="min-w-0 text-left"
            onClick={() => navigate("/")}
            title="Conversations"
          >
            <h1 className="truncate font-semibold text-primary-color">TapChat</h1>
          </button>
          <span className="ml-auto text-xs text-muted-color">Ctrl+N</span>
        </div>

        <NetworkIndicator />

        <div className="p-2">
          <input
            className="input h-9 px-3 py-2 text-sm"
            placeholder="Search conversations"
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
          />
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain">
          <ConversationList searchQuery={searchQuery} />
        </div>

        <button
          className={`flex items-center gap-2 border-t border-subtle px-3 py-2.5 text-left text-sm transition-colors ${
            pathname === "/requests"
              ? "bg-surface-elevated text-primary-color"
              : "text-secondary-color hover:bg-surface-elevated hover:text-primary-color"
          }`}
          onClick={() => navigate("/requests")}
        >
          <MessageCircle size={16} />
          <span className="min-w-0 flex-1 truncate">Message Requests</span>
          {requests.length > 0 && (
            <span className="badge badge-primary">{requests.length}</span>
          )}
        </button>

        <div className="flex items-center justify-around border-t border-subtle p-2">
          <button
            className={shellNavButtonClass(inConversation)}
            title="Conversations"
            aria-label="Conversations"
            onClick={() => navigate("/")}
          >
            <MessageCircle size={18} />
          </button>
          <button
            className={shellNavButtonClass(false)}
            title="New conversation (Ctrl+N)"
            aria-label="New conversation"
            onClick={() => navigate("/contacts")}
          >
            <Plus size={18} />
          </button>
          <button
            className={shellNavButtonClass(inGroups)}
            title="Groups"
            aria-label="Groups"
            onClick={() => navigate("/groups")}
          >
            <UsersRound size={18} />
          </button>
          <button
            className={shellNavButtonClass(inContacts)}
            title="Contacts (Ctrl+2)"
            aria-label="Contacts"
            onClick={() => navigate("/contacts")}
          >
            <ContactRound size={18} />
          </button>
          <button
            className={shellNavButtonClass(inSettings)}
            title="Settings (Ctrl+S)"
            aria-label="Settings"
            onClick={() => navigate("/settings")}
          >
            <Settings size={18} />
          </button>
        </div>
      </aside>

      <main className="flex min-w-0 flex-1 flex-col overflow-hidden bg-base">
        <Outlet />
      </main>
    </div>
  );
}
