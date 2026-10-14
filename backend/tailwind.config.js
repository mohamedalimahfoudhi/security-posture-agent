/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        void: "var(--void)",
        panel: "var(--panel)",
        hairline: "var(--hairline)",
        ink: "var(--ink)",
        mist: "var(--mist)",
        "ember-bright": "var(--ember-bright)",
        "ember-mid": "var(--ember-mid)",
        "ember-deep": "var(--ember-deep)",
        "ember-flat": "var(--ember-flat)",
        "sev-critical": "var(--sev-critical)",
        "sev-high": "var(--sev-high)",
        "sev-elevated": "var(--sev-elevated)",
        "sev-low": "var(--sev-low)",
        background: "var(--void)",
        foreground: "var(--ink)",
        card: "var(--panel)",
        "card-foreground": "var(--ink)",
        border: "var(--hairline)",
        primary: {
          DEFAULT: "var(--ember-bright)",
          foreground: "var(--void)",
        },
        muted: {
          DEFAULT: "var(--hairline)",
          foreground: "var(--mist)",
        },
        critical: "var(--sev-critical)",
        warning: "var(--sev-elevated)",
        success: "var(--sev-low)",
      },
      fontFamily: {
        sans: [
          "IBM Plex Sans",
          "Segoe UI",
          "system-ui",
          "-apple-system",
          "sans-serif",
        ],
        display: [
          "IBM Plex Sans Condensed",
          "IBM Plex Sans",
          "Segoe UI",
          "system-ui",
          "sans-serif",
        ],
        mono: [
          "IBM Plex Mono",
          "Consolas",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};
