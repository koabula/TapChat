import type { ContactDetailView, ConversationDetailView, DirectShellView } from "../../lib/types";
import InfoCard from "../shared/InfoCard";

export default function DiagnosticsDrawer({
  shell,
  statusLabel,
  backgroundEnabled,
  activeConversation,
  selectedContact,
  recoveryRows,
  transferRows,
  loading,
  onToggleBackground,
}: {
  shell: DirectShellView;
  statusLabel: string;
  backgroundEnabled: boolean;
  activeConversation: ConversationDetailView | null;
  selectedContact: ContactDetailView | null;
  recoveryRows: DirectShellView["sync"]["recovery_conversations"];
  transferRows: DirectShellView["attachment_transfers"];
  loading: boolean;
  onToggleBackground: () => Promise<void>;
}) {
  return (
    <>
      <InfoCard title="Sync" rows={[
        ["Device", shell.sync.device_id ?? "Pending"],
        ["Fetched", String(shell.sync.checkpoint?.last_fetched_seq ?? 0)],
        ["Acked", String(shell.sync.checkpoint?.last_acked_seq ?? 0)],
        ["Realtime", statusLabel],
        ["Background downloads", backgroundEnabled ? "Enabled" : "Disabled"],
      ]} />
      {activeConversation && <InfoCard title="Selected conversation" rows={[
        ["Conversation", activeConversation.conversation_id],
        ["Recovery", activeConversation.recovery_status],
        ["MLS", activeConversation.mls_status ?? "Pending"],
        ["Reason", activeConversation.recovery?.reason ?? "None"],
        ["Phase", activeConversation.recovery?.phase ?? "None"],
        ["Attempts", String(activeConversation.recovery?.attempt_count ?? 0)],
        ["Refresh retries", String(activeConversation.recovery?.identity_refresh_retry_count ?? 0)],
        ["Last error", activeConversation.recovery?.last_error ?? "None"],
      ]} />}
      {selectedContact && <InfoCard title="Selected contact" rows={[
        ["User", selectedContact.user_id],
        ["Devices", String(selectedContact.devices.length)],
        ["Bundle ref", selectedContact.identity_bundle_ref ?? "Pending"],
      ]} />}
      {recoveryRows.length > 0 && <InfoCard title="Recovery queue" rows={recoveryRows.map((item) => [item.conversation_id, `${item.recovery_status} / ${item.phase} / ${item.reason}`])} />}
      {transferRows.length > 0 && <InfoCard title="Transfers" rows={transferRows.map((transfer, index) => [`${transfer.task_kind} ${index + 1}`, `${transfer.file_name ?? transfer.message_id ?? transfer.state} / ${transfer.state}`])} />}
      <button className="ghost-button full-width" disabled={loading} onClick={() => void onToggleBackground()}>
        {backgroundEnabled ? "Disable background downloads" : "Enable background downloads"}
      </button>
    </>
  );
}
