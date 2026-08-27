/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        navy: {
          950: "#070b19",
          900: "#0b132b",
          800: "#1c2541",
          700: "#273859",
          600: "#3a506b",
        },
        garuda: {
          red: "#ef4444",
          orange: "#f97316",
          yellow: "#eab308",
          green: "#10b981",
          blue: "#3b82f6",
          cyan: "#06b6d4",
          indigo: "#6366f1",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Courier New", "monospace"],
      },
    },
  },
  plugins: [],
}
