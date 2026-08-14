import { create } from "zustand";

interface AttachmentDownloadSessionState {
  paths: Record<string, string>;
  remember: (key: string, path: string) => void;
  forget: (key: string) => void;
}

export function attachmentDownloadKey(
  conversationId: string,
  messageId: string,
  reference: string,
): string {
  return `${conversationId}\u0000${messageId}\u0000${reference}`;
}

export const useAttachmentDownloadSession = create<AttachmentDownloadSessionState>((set) => ({
  paths: {},
  remember: (key, path) => set((state) => ({ paths: { ...state.paths, [key]: path } })),
  forget: (key) => set((state) => {
    if (!(key in state.paths)) return state;
    const paths = { ...state.paths };
    delete paths[key];
    return { paths };
  }),
}));
