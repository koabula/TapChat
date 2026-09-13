import { create } from "zustand";

export interface MessageRequestItem {
  request_id: string;
  first_seen_at: number;
  message_count: number;
  welcome_bytes?: string;
}

interface MessageRequestsState {
  requests: MessageRequestItem[];
  setRequests: (requests: MessageRequestItem[]) => void;
  addRequest: (request: MessageRequestItem) => void;
  removeRequest: (request_id: string) => void;
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
