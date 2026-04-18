import { create } from "zustand";

interface SessionState {
  sessionState: string;
  wsConnected: boolean;
  syncInFlight: boolean;
  deviceId: string | null;
  userId: string | null;
  setSessionState: (state: string) => void;
  setWsConnected: (connected: boolean) => void;
  setSyncInFlight: (syncInFlight: boolean) => void;
  setDeviceId: (deviceId: string | null) => void;
  setUserId: (userId: string | null) => void;
}

export const useSessionStore = create<SessionState>((set) => ({
  sessionState: "bootstrapping",
  wsConnected: false,
  syncInFlight: false,
  deviceId: null,
  userId: null,
  setSessionState: (state) => set({ sessionState: state }),
  setWsConnected: (connected) => set({ wsConnected: connected }),
  setSyncInFlight: (syncInFlight) => set({ syncInFlight }),
  setDeviceId: (deviceId) => set({ deviceId }),
  setUserId: (userId) => set({ userId }),
}));
