/**
 * Tailwind config.
 *
 * Colours are declared as `hsl(var(--token))` so every Tailwind colour utility
 * — text, bg, border, ring, divide, and every opacity modifier like
 * `bg-panel/70` — resolves through the CSS variables in `src/index.css`. That is
 * what makes the theme switch (and the accent-hue slider) a one-variable change
 * instead of a class rewrite.
 *
 * The `<alpha-value>` placeholder is required for the opacity modifiers to work
 * with a var-based colour; without it `bg-panel/70` silently renders opaque.
 */
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        bg: 'hsl(var(--bg) / <alpha-value>)',
        deep: 'hsl(var(--bg-deep) / <alpha-value>)',
        panel: 'hsl(var(--panel) / <alpha-value>)',
        raised: 'hsl(var(--panel-raised) / <alpha-value>)',
        sunk: 'hsl(var(--panel-sunk) / <alpha-value>)',
        line: 'hsl(var(--line) / <alpha-value>)',
        'line-strong': 'hsl(var(--line-strong) / <alpha-value>)',
        ink: 'hsl(var(--text) / <alpha-value>)',
        dim: 'hsl(var(--text-dim) / <alpha-value>)',
        faint: 'hsl(var(--text-faint) / <alpha-value>)',
        accent: 'var(--accent)',
        critical: 'hsl(var(--sev-critical) / <alpha-value>)',
        high: 'hsl(var(--sev-high) / <alpha-value>)',
        medium: 'hsl(var(--sev-medium) / <alpha-value>)',
        low: 'hsl(var(--sev-low) / <alpha-value>)',
        info: 'hsl(var(--sev-info) / <alpha-value>)',
      },
      textColor: {
        dim: 'hsl(var(--text-dim) / <alpha-value>)',
        faint: 'hsl(var(--text-faint) / <alpha-value>)',
      },
      borderRadius: {
        card: 'var(--radius)',
      },
      fontFamily: {
        sans: ['var(--font-sans)'],
        mono: ['var(--font-mono)'],
      },
      spacing: {
        rail: 'var(--rail)',
        topbar: 'var(--topbar)',
      },
      transitionTimingFunction: {
        // Decelerating ease used by every lift and drawer, so motion across the
        // console feels like one system rather than several.
        out: 'cubic-bezier(0.22, 1, 0.36, 1)',
      },
      keyframes: {
        'rise-in': {
          from: { opacity: '0', transform: 'translateY(6px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'rise-in': 'rise-in 260ms cubic-bezier(0.22, 1, 0.36, 1) both',
      },
    },
  },
  plugins: [],
};
