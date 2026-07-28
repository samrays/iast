/**
 * Aegis Tailwind preset.
 *
 * Every surface in the product extends this rather than redefining colours, so a token
 * change in `tokens.css` propagates everywhere. Colours are declared as `hsl(var(--x) / <alpha-value>)`
 * so opacity modifiers (`bg-primary/10`) work on themed values.
 */

/** @type {import('tailwindcss').Config} */
const preset = {
  darkMode: ["class"],
  theme: {
    container: {
      center: true,
      padding: "1.5rem",
      screens: { "2xl": "1440px" },
    },
    extend: {
      colors: {
        border: "hsl(var(--border) / <alpha-value>)",
        input: "hsl(var(--input) / <alpha-value>)",
        ring: "hsl(var(--ring) / <alpha-value>)",
        background: "hsl(var(--background) / <alpha-value>)",
        foreground: "hsl(var(--foreground) / <alpha-value>)",
        primary: {
          DEFAULT: "hsl(var(--primary) / <alpha-value>)",
          foreground: "hsl(var(--primary-foreground) / <alpha-value>)",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary) / <alpha-value>)",
          foreground: "hsl(var(--secondary-foreground) / <alpha-value>)",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive) / <alpha-value>)",
          foreground: "hsl(var(--destructive-foreground) / <alpha-value>)",
        },
        muted: {
          DEFAULT: "hsl(var(--muted) / <alpha-value>)",
          foreground: "hsl(var(--muted-foreground) / <alpha-value>)",
        },
        accent: {
          DEFAULT: "hsl(var(--accent) / <alpha-value>)",
          foreground: "hsl(var(--accent-foreground) / <alpha-value>)",
        },
        popover: {
          DEFAULT: "hsl(var(--popover) / <alpha-value>)",
          foreground: "hsl(var(--popover-foreground) / <alpha-value>)",
        },
        card: {
          DEFAULT: "hsl(var(--card) / <alpha-value>)",
          foreground: "hsl(var(--card-foreground) / <alpha-value>)",
        },
        severity: {
          critical: "hsl(var(--severity-critical) / <alpha-value>)",
          "critical-surface": "hsl(var(--severity-critical-surface) / <alpha-value>)",
          high: "hsl(var(--severity-high) / <alpha-value>)",
          "high-surface": "hsl(var(--severity-high-surface) / <alpha-value>)",
          medium: "hsl(var(--severity-medium) / <alpha-value>)",
          "medium-surface": "hsl(var(--severity-medium-surface) / <alpha-value>)",
          low: "hsl(var(--severity-low) / <alpha-value>)",
          "low-surface": "hsl(var(--severity-low-surface) / <alpha-value>)",
          info: "hsl(var(--severity-info) / <alpha-value>)",
          "info-surface": "hsl(var(--severity-info-surface) / <alpha-value>)",
        },
        status: {
          online: "hsl(var(--status-online) / <alpha-value>)",
          "online-surface": "hsl(var(--status-online-surface) / <alpha-value>)",
          degraded: "hsl(var(--status-degraded) / <alpha-value>)",
          "degraded-surface": "hsl(var(--status-degraded-surface) / <alpha-value>)",
          offline: "hsl(var(--status-offline) / <alpha-value>)",
          "offline-surface": "hsl(var(--status-offline-surface) / <alpha-value>)",
          disabled: "hsl(var(--status-disabled) / <alpha-value>)",
          "disabled-surface": "hsl(var(--status-disabled-surface) / <alpha-value>)",
        },
        chart: {
          1: "hsl(var(--chart-1) / <alpha-value>)",
          2: "hsl(var(--chart-2) / <alpha-value>)",
          3: "hsl(var(--chart-3) / <alpha-value>)",
          4: "hsl(var(--chart-4) / <alpha-value>)",
          5: "hsl(var(--chart-5) / <alpha-value>)",
          6: "hsl(var(--chart-6) / <alpha-value>)",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      fontFamily: {
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        // A dense console needs a legible step below `text-sm` for table metadata.
        "2xs": ["0.6875rem", { lineHeight: "1rem", letterSpacing: "0.01em" }],
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        "fade-in": { from: { opacity: "0" }, to: { opacity: "1" } },
        "pulse-ring": {
          "0%": { transform: "scale(0.9)", opacity: "0.7" },
          "70%": { transform: "scale(1.6)", opacity: "0" },
          "100%": { transform: "scale(1.6)", opacity: "0" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "fade-in": "fade-in 0.15s ease-out",
        "pulse-ring": "pulse-ring 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
    },
  },
  plugins: [],
};

export default preset;
