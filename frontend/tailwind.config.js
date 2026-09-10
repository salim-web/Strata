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
        // Tremor dark theme colors
        tremor: {
          brand: {
            faint: "#0b132b",
            muted: "#1c2541",
            subtle: "#3a506b",
            DEFAULT: "#06b6d4", // cyan-500
            emphasis: "#22d3ee",
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
            DEFAULT: "#06b6d4",
          },
          content: {
            subtle: "#64748b",
            DEFAULT: "#94a3b8",
            emphasis: "#f8fafc",
            strong: "#ffffff",
            inverted: "#000000",
          },
        },
        // Cyber security palette
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
        "glow-cyan": "0 0 20px -5px rgba(6, 182, 212, 0.4)",
        "glow-emerald": "0 0 20px -5px rgba(16, 185, 129, 0.4)",
        "glow-rose": "0 0 20px -5px rgba(244, 63, 94, 0.4)",
        "glow-amber": "0 0 20px -5px rgba(245, 158, 11, 0.4)",
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
      variants: ["hover", "ui-selected"],
    },
    {
      pattern:
        /^(text-(?:slate|zinc|neutral|red|rose|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink)-(?:50|100|200|300|400|500|600|700|800|900|950))$/,
      variants: ["hover", "ui-selected"],
    },
    {
      pattern:
        /^(border-(?:slate|zinc|neutral|red|rose|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink)-(?:50|100|200|300|400|500|600|700|800|900|950))$/,
      variants: ["hover", "ui-selected"],
    },
    {
      pattern:
        /^(ring-(?:slate|zinc|neutral|red|rose|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink)-(?:50|100|200|300|400|500|600|700|800|900|950))$/,
    },
    {
      pattern:
        /^(stroke-(?:slate|zinc|neutral|red|rose|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink)-(?:50|100|200|300|400|500|600|700|800|900|950))$/,
    },
    {
      pattern:
        /^(fill-(?:slate|zinc|neutral|red|rose|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink)-(?:50|100|200|300|400|500|600|700|800|900|950))$/,
    },
  ],
  plugins: [],
};
