/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // App background hierarchy
        void: '#0B0F14',
        'bg-base': '#0B0F14',
        panel: '#11161D',
        'bg-surface': '#151B23',
        elevated: '#1A212B',
        'table-header': '#141A21',
        
        // Borders
        hairline: '#26313D',
        'border-base': '#26313D',
        'border-subtle': '#2B3642',
        
        // Typography
        ink: '#E6EDF3',
        'text-primary': '#E6EDF3',
        mist: '#A7B0BC',
        'text-secondary': '#A7B0BC',
        'text-muted': '#737F8C',
        'text-disabled': '#525D69',
        
        // Accent
        'accent-primary': '#38BDF8',
        accent: {
          DEFAULT: '#38BDF8',
          hover: '#0284C7',
          bright: '#38BDF8',
          deep: '#0284C7',
        },
        ember: {
          bright: '#38BDF8',
          deep: '#0284C7',
        },
        
        // Severities
        sev: {
          critical: '#F87171',
          high: '#FB923C',
          medium: '#FBBF24',
          elevated: '#FBBF24',
          low: '#60A5FA',
          info: '#94A3B8',
        },
        severity: {
          critical: '#F87171',
          high: '#FB923C',
          medium: '#FBBF24',
          low: '#60A5FA',
          info: '#94A3B8',
        },
        
        // Visualization & status
        viz: {
          blue: '#3B82F6',
          cyan: '#38BDF8',
          purple: '#8B5CF6',
          teal: '#14B8A6',
          green: '#34D399',
          amber: '#FBBF24',
          red: '#F87171',
        },
        status: {
          success: '#34D399',
          warning: '#FBBF24',
          error: '#F87171',
          info: '#60A5FA',
        }
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
        display: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        body: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'slide-down': 'slideDown 200ms ease-out',
      },
      keyframes: {
        slideDown: {
          '0%': { transform: 'translateY(-10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
