import { create } from "zustand";

import type { ContactRelationshipStatus } from "@/lib/types";

interface Contact {
  user_id: string;
  display_name: string | null;
  device_count: number;
  last_refresh: number | null;
  relationship_status: ContactRelationshipStatus;
  verified: boolean;
}

interface ContactsState {
  contacts: Contact[];
  setContacts: (contacts: Contact[]) => void;
  addContact: (contact: Contact) => void;
  updateContact: (userId: string, updates: Partial<Contact>) => void;
}

export const useContactsStore = create<ContactsState>((set) => ({
  contacts: [],
  setContacts: (contacts) => set({ contacts }),
  addContact: (contact) =>
    set((state) => ({
      contacts: [...state.contacts, contact],
    })),
  updateContact: (userId, updates) =>
    set((state) => ({
      contacts: state.contacts.map((c) =>
        c.user_id === userId ? { ...c, ...updates } : c,
      ),
    })),
}));
