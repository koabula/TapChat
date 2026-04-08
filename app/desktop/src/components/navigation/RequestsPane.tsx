import type { MessageRequestItemView } from "../../lib/types";

export default function RequestsPane({
  requests,
  loading,
  onAction,
}: {
  requests: MessageRequestItemView[];
  loading: boolean;
  onAction: (requestId: string, action: "accept" | "reject") => Promise<void>;
}) {
  if (!requests.length) {
    return <div className="pane-empty-state"><strong>No requests</strong><small>Pending contact requests will appear here.</small></div>;
  }
  return (
    <>
      {requests.map((request) => (
        <div className="nav-item nav-request-item" key={request.request_id}>
          <div className="nav-request-copy">
            <strong>{request.sender_display_name ?? request.sender_user_id} wants to chat</strong>
            <small>{request.message_count} pending messages</small>
          </div>
          <div className="button-row">
            <button className="ghost-button compact-button" disabled={loading} onClick={() => void onAction(request.request_id, "accept")}>Accept</button>
            <button className="ghost-button compact-button" disabled={loading} onClick={() => void onAction(request.request_id, "reject")}>Reject</button>
          </div>
        </div>
      ))}
    </>
  );
}
