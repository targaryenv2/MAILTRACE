/**
 * Appearance and workspace preferences.
 *
 * These are the "micromanagement" knobs: theme, accent hue, density, motion,
 * depth, plus the workspace toggles that change what the console shows rather
 * than how the backend behaves. Analysis settings (thresholds, retention,
 * masking) are *not* here — those live on the server, because they change
 * verdicts and must be the same for every analyst. Confusing the two is how a
 * team ends up with two people looking at different risk scores.
 *
 * Persistence is `localStorage` guarded by try/catch: the console has to work in
 * a hardened browser profile with storage disabled, and losing a colour
 * preference is not worth a white screen.
 */

import {
  createContext, useCallback, useContext, useEffect, useMemo, useState,
  type ReactNode,
} from 'react';

export type ThemeMode = 'dark' | 'light' | 'system';
export type Density = 'compact' | 'cosy' | 'roomy';
export type MotionMode = 'full' | 'reduced' | 'off';

export interface Prefs {
  theme: ThemeMode;
  /** Accent hue in degrees, 0–360. */
  accentHue: number;
  density: Density;
  motion: MotionMode;
  /** Depth multiplier for shadows, blur and the backdrop. 0 flattens the UI. */
  depth: number;
  /** Frosted panels. Costs GPU on integrated graphics; separable from depth. */
  glass: boolean;
  /** Show the fixed backdrop washes and perspective grid. */
  backdrop: boolean;
  /** Attach to the SSE feed on load. Off = manual refresh only. */
  liveFeed: boolean;
  /** Show a provenance dot beside every enriched value. */
  showProvenance: boolean;
  /** Render raw headers and bodies monospaced and unwrapped. */
  rawMode: boolean;
  /** Auto-open the newest case when the live feed reports one. */
  followNewCases: boolean;
  /** Queue rows per page. */
  pageSize: number;
  /** Analyst identity sent as X-Analyst on decisions. Not a credential. */
  analyst: string;
}

export const DEFAULT_PREFS: Prefs = {
  theme: 'dark',
  accentHue: 224,
  density: 'cosy',
  motion: 'full',
  depth: 1,
  glass: true,
  backdrop: true,
  liveFeed: true,
  showProvenance: true,
  rawMode: false,
  followNewCases: false,
  pageSize: 25,
  analyst: '',
};

const KEY = 'mailtrace.prefs.v1';

function load(): Prefs {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return DEFAULT_PREFS;
    const parsed = JSON.parse(raw) as Partial<Prefs>;
    // Merge over the defaults rather than trusting the stored object: a build
    // that adds a preference must not read `undefined` out of an older payload.
    return { ...DEFAULT_PREFS, ...parsed };
  } catch {
    return DEFAULT_PREFS;
  }
}

function save(prefs: Prefs): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(prefs));
  } catch {
    /* storage disabled or full; preferences stay in-memory for this session */
  }
}

interface ThemeCtx {
  prefs: Prefs;
  /** Effective theme after resolving `system`. */
  resolved: 'dark' | 'light';
  set: <K extends keyof Prefs>(key: K, value: Prefs[K]) => void;
  patch: (next: Partial<Prefs>) => void;
  reset: () => void;
}

const Ctx = createContext<ThemeCtx | null>(null);

function systemPrefersDark(): boolean {
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  } catch {
    return true;
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [prefs, setPrefs] = useState<Prefs>(load);
  const [systemDark, setSystemDark] = useState<boolean>(systemPrefersDark);

  // Track the OS theme only while `system` is selected, so we are not holding a
  // listener for a signal nobody is reading.
  useEffect(() => {
    if (prefs.theme !== 'system') return;
    let mq: MediaQueryList;
    try {
      mq = window.matchMedia('(prefers-color-scheme: dark)');
    } catch {
      return;
    }
    const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    setSystemDark(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [prefs.theme]);

  const resolved: 'dark' | 'light' =
    prefs.theme === 'system' ? (systemDark ? 'dark' : 'light') : prefs.theme;

  // Everything visual is driven off attributes and variables on <html>, so a
  // preference change is one style recalculation and no component re-renders
  // for styling reasons.
  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = resolved;
    root.dataset.density = prefs.density;
    root.dataset.motion = prefs.motion;
    root.style.setProperty('--accent-h', String(prefs.accentHue));
    root.style.setProperty('--depth', prefs.backdrop || prefs.depth > 0
      ? String(prefs.depth) : '0');
    root.style.setProperty('--radius', prefs.density === 'compact' ? '11px' : '14px');
    save(prefs);
  }, [prefs, resolved]);

  const set = useCallback(<K extends keyof Prefs>(key: K, value: Prefs[K]) => {
    setPrefs((p) => ({ ...p, [key]: value }));
  }, []);

  const patch = useCallback((next: Partial<Prefs>) => {
    setPrefs((p) => ({ ...p, ...next }));
  }, []);

  const reset = useCallback(() => setPrefs(DEFAULT_PREFS), []);

  const value = useMemo<ThemeCtx>(() => ({ prefs, resolved, set, patch, reset }),
    [prefs, resolved, set, patch, reset]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function usePrefs(): ThemeCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('usePrefs must be used inside <ThemeProvider>');
  return ctx;
}

/** Named accent presets for the settings drawer swatch row. */
export const ACCENTS: { name: string; hue: number }[] = [
  { name: 'Indigo', hue: 224 },
  { name: 'Violet', hue: 268 },
  { name: 'Cyan', hue: 190 },
  { name: 'Emerald', hue: 156 },
  { name: 'Amber', hue: 38 },
  { name: 'Rose', hue: 348 },
];
