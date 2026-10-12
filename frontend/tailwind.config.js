/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        // VulnWatch enterprise cybersecurity graphite & emerald theme
        brand: {
          50:  '#ecfdf5',
          100: '#d1fae5',
          200: '#a7f3d0',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          600: '#059669',
          700: '#047857',
          800: '#065f46',
          900: '#064e3b',
          950: '#022c22',
        },
        surface: {
          950: '#0e0f12', // Deep background
          900: '#121316', // Base app canvas
          850: '#15161a', // Sidebar / muted container
          800: '#18191d', // Primary card / panel
          750: '#1f2026', // Elevated card / subpanel
          700: '#262830', // Hover state
          600: '#2f323a', // Borders / dividers
          500: '#424652', // Muted borders
        },
        status: {
          critical: '#ef4444',
          high:     '#f97316',
          medium:   '#f59e0b',
          low:      '#06b6d4',
          info:     '#71717a',
          success:  '#10b981',
        },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '0.875rem' }],
      },
      borderRadius: {
        DEFAULT: '0.375rem',
      },
    },
  },
  plugins: [],
}
