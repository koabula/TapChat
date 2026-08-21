import { describe, expect, it } from "vitest";

import type { RelationshipViewState } from "@/lib/types";
import { relationshipUiPolicy } from "@/lib/relationshipUi";

function relationship(
  overrides: Partial<RelationshipViewState> = {},
): RelationshipViewState {
  return {
    relationship_id: "relationship-1",
    generation: 1,
    account_state: "accepted",
    setup_state: "ready",
    local_device_join_state: "ready",
    canonical_conversation_id: "conv:canonical",
    ...overrides,
  };
}

describe("relationship UI policy", () => {
  it("shows each orthogonal setup/device state and blocks sending until fully ready", () => {
    expect(
      relationshipUiPolicy(
        relationship({ account_state: "pending", setup_state: "retrying_expired" }),
        "conv:current",
      ),
    ).toMatchObject({
      retryingExpired: true,
      sendBlocked: true,
      statusText: "请求已过期，正在重新建联",
    });
    expect(
      relationshipUiPolicy(relationship({ setup_state: "pool_exhausted" }), "conv:current"),
    ).toMatchObject({
      poolExhausted: true,
      sendBlocked: true,
      statusText: "对方安全密钥库存暂不可用",
    });
    expect(
      relationshipUiPolicy(
        relationship({ local_device_join_state: "waiting_welcome" }),
        "conv:current",
      ),
    ).toMatchObject({
      accountAcceptedDevicePending: true,
      joining: false,
      joinFailed: false,
      sendBlocked: true,
      statusText: "账户已接受，此设备待加入",
    });
    expect(
      relationshipUiPolicy(
        relationship({ local_device_join_state: "joining" }),
        "conv:current",
      ),
    ).toMatchObject({
      accountAcceptedDevicePending: false,
      joining: true,
      statusText: "正在加入安全会话",
    });
    expect(
      relationshipUiPolicy(
        relationship({ local_device_join_state: "failed" }),
        "conv:current",
      ),
    ).toMatchObject({
      accountAcceptedDevicePending: false,
      joinFailed: true,
      statusText: "加入失败，重新同步",
    });
    expect(relationshipUiPolicy(relationship(), "conv:current").sendBlocked).toBe(false);
  });

  it("redirects only superseded conversations to a different canonical conversation", () => {
    expect(
      relationshipUiPolicy(
        relationship({ setup_state: "superseded" }),
        "conv:current",
      ).canonicalConversationId,
    ).toBe("conv:canonical");
    expect(
      relationshipUiPolicy(
        relationship({ setup_state: "superseded" }),
        "conv:canonical",
      ).canonicalConversationId,
    ).toBeUndefined();
    expect(relationshipUiPolicy(relationship(), "conv:current").canonicalConversationId)
      .toBeUndefined();
  });
});
