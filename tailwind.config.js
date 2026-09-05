/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: '#02050A',
        'background-secondary': '#07101A',
        surface: 'rgba(255, 255, 255, 0.04)',
        'surface-hover': 'rgba(255, 255, 255, 0.07)',
        'surface-active': 'rgba(255, 255, 255, 0.10)',
        'border-subtle': 'rgba(255, 255, 255, 0.10)',
        'border-active': 'rgba(0, 102, 255, 0.40)',
        'electric-blue': {
          DEFAULT: '#0066FF',
          glow: 'rgba(0, 102, 255, 0.35)',
          muted: 'rgba(0, 102, 255, 0.15)',
          light: '#3B82F6',
          dark: '#0047B3',
        },
        'subtle-cyan': {
          DEFAULT: '#00F0FF',
          glow: 'rgba(0, 240, 255, 0.25)',
          muted: 'rgba(0, 240, 255, 0.08)',
          light: '#38BDF8',
        },
        'text-primary': '#FFFFFF',
        'text-secondary': '#94A3B8',
        'text-muted': '#64748B',
      },
      fontFamily: {
        display: ['Orbitron', 'Space Grotesk', 'Rajdhani', 'sans-serif'],
        sans: ['Space Grotesk', 'Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
      },
      letterSpacing: {
        'super-wide': '0.3em',
        'ultra-wide': '0.45em',
      },
      boxShadow: {
        'glow-blue': '0 0 25px -5px rgba(0, 102, 255, 0.4)',
        'glow-blue-lg': '0 0 50px -10px rgba(0, 102, 255, 0.5)',
        'glow-cyan': '0 0 25px -5px rgba(0, 240, 255, 0.3)',
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
        'inner-glow': 'inset 0 1px 1px 0 rgba(255, 255, 255, 0.15)',
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line': 'scanline 8s linear infinite',
        'radar-sweep': 'radarSweep 12s linear infinite',
        'float-slow': 'float 6s ease-in-out infinite',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        },
        radarSweep: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-8px)' },
        },
      },
    },
  },
  plugins: [],
};
