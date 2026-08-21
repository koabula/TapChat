import type { RelationshipViewState } from "@/lib/types";

export interface RelationshipUiPolicy {
  retryingExpired: boolean;
  poolExhausted: boolean;
  accountAcceptedDevicePending: boolean;
  joining: boolean;
  joinFailed: boolean;
  sendBlocked: boolean;
  statusText?: string;
  composerTooltip?: string;
  canonicalConversationId?: string;
}

export function relationshipUiPolicy(
  relationship: RelationshipViewState | null | undefined,
  conversationId: string | undefined,
): RelationshipUiPolicy {
  const retryingExpired = relationship?.setup_state === "retrying_expired";
  const poolExhausted = relationship?.setup_state === "pool_exhausted";
  const joining = relationship?.local_device_join_state === "joining";
  const joinFailed = relationship?.local_device_join_state === "failed";
  const accountAcceptedDevicePending =
    relationship?.account_state === "accepted" &&
    relationship.local_device_join_state === "waiting_welcome";
  const sendBlocked = Boolean(
    relationship &&
      (relationship.account_state !== "accepted" ||
        relationship.local_device_join_state !== "ready" ||
        relationship.setup_state !== "ready"),
  );
  const statusText = retryingExpired
    ? "请求已过期，正在重新建联"
    : poolExhausted
      ? "对方安全密钥库存暂不可用"
      : accountAcceptedDevicePending
        ? "账户已接受，此设备待加入"
        : joining
          ? "正在加入安全会话"
          : joinFailed
            ? "加入失败，重新同步"
            : undefined;
  const composerTooltip = statusText ? `${statusText}。` : undefined;
  const canonicalConversationId =
    relationship?.setup_state === "superseded" &&
    relationship.canonical_conversation_id &&
    relationship.canonical_conversation_id !== conversationId
      ? relationship.canonical_conversation_id
      : undefined;

  return {
    retryingExpired,
    poolExhausted,
    accountAcceptedDevicePending,
    joining,
    joinFailed,
    sendBlocked,
    statusText,
    composerTooltip,
    canonicalConversationId,
  };
}
