import { create } from "zustand";

interface SessionState {
  sessionState: string;
  wsConnected: boolean;
  deviceId: string | null;
  userId: string | null;
  setSessionState: (state: string) => void;
  setWsConnected: (connected: boolean) => void;
  setDeviceId: (deviceId: string | null) => void;
  setUserId: (userId: string | null) => void;
}

export const useSessionStore = create<SessionState>((set) => ({
  sessionState: "uninitialized",
  wsConnected: false,
  deviceId: null,
  userId: null,
  setSessionState: (state) => set({ sessionState: state }),
  setWsConnected: (connected) => set({ wsConnected: connected }),
  setDeviceId: (deviceId) => set({ deviceId }),
  setUserId: (userId) => set({ userId }),
}));