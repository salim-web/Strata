/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
    "./node_modules/@tremor/react/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    transparent: "transparent",
    current: "currentColor",
    extend: {
      colors: {
        // Soft Neomorphic SaaS Theme Tokens
        saas: {
          light: {
            canvas: "#ECEBF5",
            card: "#FFFFFF",
            elevated: "#F8F8FC",
            border: "#E2E2EC",
            text: "#1E1E2D",
            muted: "#8A8FA3",
            accent: "#6366F1",
            accentHover: "#4F46E5",
          },
          dark: {
            canvas: "#1C1D21",
            card: "#26282E",
            elevated: "#2D3037",
            border: "rgba(255, 255, 255, 0.06)",
            text: "#F3F4F6",
            muted: "#9CA3AF",
            accent: "#818CF8",
            accentHover: "#6366F1",
          },
        },
        // Tremor theme colors
        tremor: {
          brand: {
            faint: "#0b132b",
            muted: "#1c2541",
            subtle: "#3a506b",
            DEFAULT: "#6366F1",
            emphasis: "#818CF8",
            inverted: "#030712",
          },
          background: {
            muted: "#0f172a",
            subtle: "#1e293b",
            DEFAULT: "#020617",
            emphasis: "#334155",
          },
          border: {
            DEFAULT: "#1e293b",
          },
          ring: {
            DEFAULT: "#6366F1",
          },
          content: {
            subtle: "#64748b",
            DEFAULT: "#94a3b8",
            emphasis: "#f8fafc",
            strong: "#ffffff",
            inverted: "#000000",
          },
        },
        // Security palette
        cyber: {
          bg: "#030712",
          card: "#0b0f19",
          border: "#1e293b",
          cyan: "#06b6d4",
          teal: "#14b8a6",
          emerald: "#10b981",
          rose: "#f43f5e",
          amber: "#f59e0b",
          purple: "#8b5cf6",
        },
      },
      boxShadow: {
        "saas-light": "0 8px 24px -4px rgba(100, 100, 130, 0.08), 0 2px 6px -1px rgba(100, 100, 130, 0.04)",
        "saas-dark": "0 8px 24px -4px rgba(0, 0, 0, 0.4), 0 2px 6px -1px rgba(0, 0, 0, 0.25)",
        "saas-light-sm": "0 4px 12px -2px rgba(100, 100, 130, 0.06)",
        "saas-dark-sm": "0 4px 12px -2px rgba(0, 0, 0, 0.3)",
        "pill-inset": "inset 0 1px 2px rgba(0, 0, 0, 0.05)",
        "glow-violet": "0 0 24px -4px rgba(99, 102, 241, 0.35)",
        "glow-cyan": "0 0 20px -5px rgba(6, 182, 212, 0.4)",
        "glow-emerald": "0 0 20px -5px rgba(16, 185, 129, 0.4)",
        "glow-rose": "0 0 20px -5px rgba(244, 63, 94, 0.4)",
        "glow-amber": "0 0 20px -5px rgba(245, 158, 11, 0.4)",
      },
      borderRadius: {
        "2xl": "1rem", // 16px
        "3xl": "1.25rem", // 20px
        "4xl": "1.5rem", // 24px
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scanline": "scanline 8s linear infinite",
      },
      keyframes: {
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(1000%)" },
        },
      },
    },
  },
  safelist: [
    {
      pattern:
        /^(bg-(?:slate|zinc|neutral|red|rose|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink)-(?:50|100|200|300|400|500|600|700|800|900|950))$/,
      variants: ["hover", "ui-selected", "dark"],
    },
    {
      pattern:
        /^(text-(?:slate|zinc|neutral|red|rose|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink)-(?:50|100|200|300|400|500|600|700|800|900|950))$/,
      variants: ["hover", "ui-selected", "dark"],
    },
    {
      pattern:
        /^(border-(?:slate|zinc|neutral|red|rose|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink)-(?:50|100|200|300|400|500|600|700|800|900|950))$/,
      variants: ["hover", "ui-selected", "dark"],
    },
    {
      pattern:
        /^(ring-(?:slate|zinc|neutral|red|rose|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink)-(?:50|100|200|300|400|500|600|700|800|900|950))$/,
    },
  ],
  plugins: [],
};
