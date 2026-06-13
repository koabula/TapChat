import { create } from "zustand";

import {
  applyThemePreference,
  getStoredThemePreference,
  getSystemPrefersDark,
  resolveThemePreference,
  storeThemePreference,
  type ResolvedTheme,
  type ThemePreference,
} from "@/lib/theme";

interface ThemeState {
  preference: ThemePreference;
  resolvedTheme: ResolvedTheme;
  hydrateTheme: () => void;
  setThemePreference: (theme: ThemePreference) => void;
  handleSystemThemeChanged: () => void;
}

const initialPreference = getStoredThemePreference();
const initialResolvedTheme = resolveThemePreference(
  initialPreference,
  getSystemPrefersDark(),
);

export const useThemeStore = create<ThemeState>((set, get) => ({
  preference: initialPreference,
  resolvedTheme: initialResolvedTheme,
  hydrateTheme: () => {
    const preference = getStoredThemePreference();
    const resolvedTheme = applyThemePreference(preference);
    set({ preference, resolvedTheme });
  },
  setThemePreference: (theme) => {
    storeThemePreference(theme);
    const resolvedTheme = applyThemePreference(theme);
    set({ preference: theme, resolvedTheme });
  },
  handleSystemThemeChanged: () => {
    const resolvedTheme = applyThemePreference(get().preference);
    set({ resolvedTheme });
  },
}));
