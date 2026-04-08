import type { Dispatch, SetStateAction } from "react";
import type { AllowlistView, MessageRequestItemView } from "../../lib/types";
import InfoCard from "../shared/InfoCard";

export default function PolicyDrawer({
  requests,
  allowlist,
  allowlistDraft,
  setAllowlistDraft,
  loading,
  onMessageRequest,
  onAllowlistAdd,
  onAllowlistRemove,
}: {
  requests: MessageRequestItemView[];
  allowlist: AllowlistView | null;
  allowlistDraft: string;
  setAllowlistDraft: Dispatch<SetStateAction<string>>;
  loading: boolean;
  onMessageRequest: (requestId: string, action: "accept" | "reject") => Promise<void>;
  onAllowlistAdd: () => Promise<void>;
  onAllowlistRemove: (userId: string) => Promise<void>;
}) {
  return (
    <>
      <div className="info-card">
        <div className="info-card-title">Message requests</div>
        <div className="info-card-rows">
          {requests.length === 0 ? <div className="info-row"><span>Requests</span><strong>None</strong></div> : requests.map((request) => (
            <div className="info-row" key={request.request_id}>
              <span>{request.sender_user_id}</span>
              <div className="button-row">
                <small>{request.message_count} msg</small>
                <button className="ghost-button compact-button" disabled={loading} onClick={() => void onMessageRequest(request.request_id, "accept")}>Accept</button>
                <button className="ghost-button compact-button" disabled={loading} onClick={() => void onMessageRequest(request.request_id, "reject")}>Reject</button>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="info-card">
        <div className="info-card-title">Allowlist</div>
        <div className="info-card-rows">
          <div className="inline-field">
            <input placeholder="user_id" value={allowlistDraft} onChange={(event) => setAllowlistDraft(event.target.value)} />
            <button className="ghost-button compact-button" disabled={loading || !allowlistDraft.trim()} onClick={() => void onAllowlistAdd()}>Add</button>
          </div>
          {(allowlist?.allowed_sender_user_ids ?? []).length === 0 ? <div className="info-row"><span>Allowed</span><strong>Empty</strong></div> : allowlist?.allowed_sender_user_ids.map((userId) => (
            <div className="info-row" key={userId}>
              <span>{userId}</span>
              <button className="ghost-button compact-button" disabled={loading} onClick={() => void onAllowlistRemove(userId)}>Remove</button>
            </div>
          ))}
          {(allowlist?.rejected_sender_user_ids ?? []).length > 0 && (
            <InfoCard title="Rejected senders" rows={(allowlist?.rejected_sender_user_ids ?? []).map((userId) => [userId, "Rejected"])} />
          )}
        </div>
      </div>
    </>
  );
}
