import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      // Nord-inspired color palette
      // https://github.com/nordtheme/nord
      colors: {
        // Polar Night - dark backgrounds
        polar: {
          0: "#2E3440", // darkest
          1: "#3B4252",
          2: "#434C5E",
          3: "#4C566A",
        },
        // Snow Storm - light backgrounds
        snow: {
          0: "#D8DEE9",
          1: "#E5E9F0",
          2: "#ECEFF4", // lightest
        },
        // Frost - primary blue tones
        frost: {
          0: "#8FBCBB", // teal-ish
          1: "#88C0D0", // cyan
          2: "#81A1C1", // blue (primary accent)
          3: "#5E81AC", // deep blue
        },
        // Aurora - accent colors
        aurora: {
          red: "#BF616A",
          orange: "#D08770",
          yellow: "#EBCB8B",
          green: "#A3BE8C",
          purple: "#B48EAD",
        },
        // Aliases for convenience
        primary: {
          DEFAULT: "#81A1C1", // frost.2
          dark: "#5E81AC", // frost.3
          light: "#88C0D0", // frost.1
        },
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
      },
      borderRadius: {
        bubble: "20px",
      },
    },
  },
  plugins: [],
} satisfies Config;