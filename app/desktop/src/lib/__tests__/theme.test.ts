import { afterEach, describe, expect, test, vi } from "vitest";

import {
  THEME_STORAGE_KEY,
  applyThemePreference,
  getStoredThemePreference,
  resolveThemePreference,
  storeThemePreference,
} from "@/lib/theme";

class MemoryStorage implements Storage {
  private values = new Map<string, string>();

  get length(): number {
    return this.values.size;
  }

  clear(): void {
    this.values.clear();
  }

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  key(index: number): string | null {
    return Array.from(this.values.keys())[index] ?? null;
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
}

function stubStorage(): MemoryStorage {
  const storage = new MemoryStorage();
  vi.stubGlobal("localStorage", storage);
  return storage;
}

function stubMatchMedia(prefersDark: boolean): void {
  vi.stubGlobal("window", {
    matchMedia: vi.fn().mockReturnValue({ matches: prefersDark }),
  });
}

function stubDocumentRoot() {
  const attributes = new Map<string, string>();
  const style: { colorScheme?: string } = {};
  vi.stubGlobal("document", {
    documentElement: {
      style,
      setAttribute(name: string, value: string) {
        attributes.set(name, value);
      },
    },
  });
  return { attributes, style };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("theme helpers", () => {
  test("defaults to system when localStorage is empty", () => {
    stubStorage();

    expect(getStoredThemePreference()).toBe("system");
  });

  test("falls back to system for invalid localStorage values", () => {
    const storage = stubStorage();
    storage.setItem(THEME_STORAGE_KEY, "solarized");

    expect(getStoredThemePreference()).toBe("system");
  });

  test("resolves system to nord-light in light OS mode", () => {
    expect(resolveThemePreference("system", false)).toBe("nord-light");
  });

  test("resolves system to nord-dark in dark OS mode", () => {
    expect(resolveThemePreference("system", true)).toBe("nord-dark");
  });

  test("stores and applies a concrete theme to the document root", () => {
    const storage = stubStorage();
    stubMatchMedia(false);
    const { attributes, style } = stubDocumentRoot();

    storeThemePreference("mono-dark");
    const resolved = applyThemePreference(getStoredThemePreference());

    expect(storage.getItem(THEME_STORAGE_KEY)).toBe("mono-dark");
    expect(resolved).toBe("mono-dark");
    expect(attributes.get("data-theme")).toBe("mono-dark");
    expect(attributes.get("data-theme-preference")).toBe("mono-dark");
    expect(style.colorScheme).toBe("dark");
  });
});
