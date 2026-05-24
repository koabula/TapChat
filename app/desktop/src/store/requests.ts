import { create } from "zustand";

export interface MessageRequestItem {
  request_id: string;
  recipient_device_id: string;
  sender_user_id: string;
  sender_bundle_share_url?: string;
  sender_bundle_hash?: string;
  sender_display_name?: string;
  first_seen_at: number;
  last_seen_at: number;
  message_count: number;
  last_message_id: string;
  last_conversation_id: string;
  request_kind?: "direct" | "group_invite";
  group_id?: string;
  group_title?: string;
}

interface MessageRequestsState {
  requests: MessageRequestItem[];
  setRequests: (requests: MessageRequestItem[]) => void;
  addRequest: (request: MessageRequestItem) => void;
  removeRequest: (request_id: string) => void;
}

export function isMessageRequestForSession(
  request: MessageRequestItem,
  deviceId: string | null | undefined,
  userId: string | null | undefined,
): boolean {
  if (deviceId && request.recipient_device_id !== deviceId) {
    return false;
  }
  if (userId && request.sender_user_id === userId) {
    return false;
  }
  return true;
}

export function filterMessageRequestsForSession(
  requests: MessageRequestItem[],
  deviceId: string | null | undefined,
  userId: string | null | undefined,
): MessageRequestItem[] {
  return requests.filter((request) =>
    isMessageRequestForSession(request, deviceId, userId),
  );
}

export const useMessageRequestsStore = create<MessageRequestsState>((set) => ({
  requests: [],
  setRequests: (requests) => set({ requests }),
  addRequest: (request) =>
    set((state) => ({
      requests: [
        ...state.requests.filter((r) => r.request_id !== request.request_id),
        request,
      ],
    })),
  removeRequest: (request_id) =>
    set((state) => ({
      requests: state.requests.filter((r) => r.request_id !== request_id),
    })),
}));
