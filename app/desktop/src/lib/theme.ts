export const THEME_STORAGE_KEY = "tapchat:theme-preference";

export const THEME_PREFERENCES = [
  "system",
  "nord-light",
  "nord-dark",
  "mono-light",
  "mono-dark",
  "graphite",
  "forest",
  "rose",
] as const;

export type ThemePreference = (typeof THEME_PREFERENCES)[number];
export type ResolvedTheme = Exclude<ThemePreference, "system">;

export interface ThemePreview {
  base: string;
  surface: string;
  accent: string;
}

export interface ThemeOption {
  id: ResolvedTheme;
  label: string;
  description: string;
  preview: ThemePreview;
}

export const THEME_OPTIONS: ThemeOption[] = [
  {
    id: "nord-light",
    label: "Nord Light",
    description: "Soft arctic light",
    preview: { base: "#ECEFF4", surface: "#E5E9F0", accent: "#81A1C1" },
  },
  {
    id: "nord-dark",
    label: "Nord Dark",
    description: "Calm polar night",
    preview: { base: "#2E3440", surface: "#3B4252", accent: "#88C0D0" },
  },
  {
    id: "mono-light",
    label: "Mono Light",
    description: "Black, white, gray",
    preview: { base: "#F7F7F7", surface: "#FFFFFF", accent: "#111111" },
  },
  {
    id: "mono-dark",
    label: "Mono Dark",
    description: "Low-glare grayscale",
    preview: { base: "#111111", surface: "#1C1C1C", accent: "#E5E5E5" },
  },
  {
    id: "graphite",
    label: "Graphite",
    description: "Dark gray with cool blue",
    preview: { base: "#171A1F", surface: "#23272F", accent: "#7EA7C8" },
  },
  {
    id: "forest",
    label: "Forest",
    description: "Green-gray workspace",
    preview: { base: "#EEF3ED", surface: "#F8FBF7", accent: "#3F7A55" },
  },
  {
    id: "rose",
    label: "Rose",
    description: "Warm rose neutral",
    preview: { base: "#F7F0F2", surface: "#FFF9FA", accent: "#B85C74" },
  },
];

const DARK_THEMES: ReadonlySet<ResolvedTheme> = new Set([
  "nord-dark",
  "mono-dark",
  "graphite",
]);

function isThemePreference(value: unknown): value is ThemePreference {
  return (
    typeof value === "string" &&
    THEME_PREFERENCES.includes(value as ThemePreference)
  );
}

function getStorage(): Storage | null {
  try {
    return (
      (globalThis as typeof globalThis & { localStorage?: Storage }).localStorage ??
      null
    );
  } catch {
    return null;
  }
}

function getDocumentElement(): HTMLElement | null {
  if (typeof document === "undefined") {
    return null;
  }
  return document.documentElement;
}

export function getSystemPrefersDark(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function getStoredThemePreference(): ThemePreference {
  const storage = getStorage();
  if (!storage) {
    return "system";
  }

  try {
    const value = storage.getItem(THEME_STORAGE_KEY);
    return isThemePreference(value) ? value : "system";
  } catch {
    return "system";
  }
}

export function storeThemePreference(theme: ThemePreference): void {
  const storage = getStorage();
  if (!storage) {
    return;
  }

  try {
    storage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Theme persistence is best-effort; applying the current theme still works.
  }
}

export function resolveThemePreference(
  theme: ThemePreference,
  prefersDark: boolean,
): ResolvedTheme {
  if (theme === "system") {
    return prefersDark ? "nord-dark" : "nord-light";
  }
  return theme;
}

export function isResolvedThemeDark(theme: ResolvedTheme): boolean {
  return DARK_THEMES.has(theme);
}

export function applyThemePreference(theme: ThemePreference): ResolvedTheme {
  const resolved = resolveThemePreference(theme, getSystemPrefersDark());
  const root = getDocumentElement();

  if (root) {
    root.setAttribute("data-theme", resolved);
    root.setAttribute("data-theme-preference", theme);
    root.style.colorScheme = isResolvedThemeDark(resolved) ? "dark" : "light";
  }

  return resolved;
}
