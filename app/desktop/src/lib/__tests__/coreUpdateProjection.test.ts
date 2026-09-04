import { describe, expect, it } from "vitest";

import { mapContacts, staleGroupSnapshotIds, visibleGroupIds } from "../coreUpdateProjection";

describe("core update projections", () => {
  it("maps contact summaries into store contacts with stable defaults", () => {
    expect(
      mapContacts([
        {
          user_id: "user:alice",
          display_name: undefined,
          device_count: 2,
        },
        {
          user_id: "user:bob",
          display_name: "Bob",
          device_count: 1,
          relationship_status: "blocked",
        },
      ]),
    ).toEqual([
      {
        user_id: "user:alice",
        display_name: null,
        device_count: 2,
        last_refresh: null,
        relationship_status: "available",
        verified: false,
        key_changed_unverified: false,
      },
      {
        user_id: "user:bob",
        display_name: "Bob",
        device_count: 1,
        last_refresh: null,
        relationship_status: "blocked",
        verified: false,
        key_changed_unverified: false,
      },
    ]);
  });

  it("finds group snapshots that disappeared from the flattened conversation list", () => {
    const visible = visibleGroupIds([
      { group_id: "group:one" },
      { group_id: "group:three" },
    ]);

    expect(
      staleGroupSnapshotIds(["group:one", "group:two", "group:three"], visible),
    ).toEqual(["group:two"]);
  });
});
