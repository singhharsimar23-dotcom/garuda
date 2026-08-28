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
        // --- Palantir Gotham surface hierarchy ---
        void:    '#060B14',
        surface: '#0D1521',
        raised:  '#142030',
        border:  '#1E3349',

        // --- Brand ---
        saffron: '#FF6B00',
        gold:    '#C9922A',

        // --- Status ---
        critical: '#FF3B30',
        high:     '#FF9500',
        medium:   '#FFD60A',
        low:      '#34C759',
        info:     '#0A84FF',
        neutral:  '#8E8E93',

        // --- Text ---
        primary:   '#E8F0FE',
        secondary: '#6B85A8',
        ghost:     '#3A5070',

        // --- Data grid ---
        row:    '#0D1521',
        rowalt: '#111B2A',
        rowsel: '#1A2F4A',

        // --- Legacy tokens (keep for existing pages) ---
        navy: {
          950: '#070b19',
          900: '#0b132b',
          800: '#1c2541',
          700: '#273859',
          600: '#3a506b',
        },
        garuda: {
          red:    '#ef4444',
          orange: '#f97316',
          yellow: '#eab308',
          green:  '#10b981',
          blue:   '#3b82f6',
          cyan:   '#06b6d4',
          indigo: '#6366f1',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
      },
      fontSize: {
        '2xs': ['10px', { lineHeight: '14px', letterSpacing: '0.08em' }],
      },
    },
  },
  plugins: [],
}

