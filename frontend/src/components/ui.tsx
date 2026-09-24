/**
 * Presentational primitives shared across every view.
 *
 * These carry the 3-D surface language (see index.css) so views compose depth
 * instead of re-deriving box-shadows. Everything here is display-only: no data
 * fetching, no routing. Anything with logic lives in a view or a hook.
 */

import {
  useEffect, useRef, useState, type CSSProperties, type ReactNode,
} from 'react';
import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion';
import { usePrefs } from '../lib/theme';
import { provClass, provLabel } from '../lib/format';
import type { Provenance } from '../lib/types';

export function Card({ children, className = '', glass, sunk, onClick, title, style }: {
  children: ReactNode; className?: string; glass?: boolean; sunk?: boolean;
  onClick?: () => void; title?: string; style?: CSSProperties;
}) {
  const cls = sunk ? 'surface-sunk' : `surface${glass ? ' surface-glass' : ''}`;
  return (
    <div className={`${cls} ${onClick ? 'lift cursor-pointer' : ''} ${className}`}
         onClick={onClick} title={title} style={style}>
      {children}
    </div>
  );
}

export function Panel({ title, subtitle, right, children, icon, className = '', pad = true }: {
  title?: ReactNode; subtitle?: ReactNode; right?: ReactNode; children: ReactNode;
  icon?: ReactNode; className?: string; pad?: boolean;
}) {
  return (
    <Card className={className}>
      {(title || right) && (
        <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-line">
          <div className="flex items-center gap-2 min-w-0">
            {icon && <span className="text-dim shrink-0">{icon}</span>}
            <div className="min-w-0">
              {title && <h3 className="text-sm font-semibold truncate">{title}</h3>}
              {subtitle && <p className="text-xs text-faint truncate">{subtitle}</p>}
            </div>
          </div>
          {right && <div className="shrink-0">{right}</div>}
        </div>
      )}
      <div className={pad ? 'p-4' : ''}>{children}</div>
    </Card>
  );
}

export function Chip({ tone = 'info', children, className = '' }: {
  tone?: string; children: ReactNode; className?: string;
}) {
  return <span className={`chip chip-${tone} ${className}`}>{children}</span>;
}

export function Prov({ source }: { source?: Provenance | string }) {
  const { prefs } = usePrefs();
  if (!prefs.showProvenance || !source) return null;
  return <span className={provClass(source)} title={`provenance: ${provLabel(source)}`}>
    {provLabel(source)}</span>;
}

export function Button({ variant = 'default', size, children, className = '', ...rest }: {
  variant?: 'default' | 'primary' | 'ghost' | 'danger'; size?: 'sm';
  children: ReactNode; className?: string;
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const v = variant === 'default' ? '' : ` btn-${variant}`;
  return <button className={`btn${v}${size === 'sm' ? ' btn-sm' : ''} ${className}`} {...rest}>
    {children}</button>;
}

export function Toggle({ on, onChange, label, disabled }: {
  on: boolean; onChange: (v: boolean) => void; label?: string; disabled?: boolean;
}) {
  return (
    <button type="button" className="flex items-center gap-2" onClick={() => onChange(!on)}
            aria-pressed={on} aria-label={label} disabled={disabled}>
      <span className="switch" data-on={on} />
      {label && <span className="text-xs text-dim">{label}</span>}
    </button>
  );
}

export function Stat({ label, value, tone, sub, prov }: {
  label: string; value: ReactNode; tone?: string; sub?: ReactNode; prov?: Provenance;
}) {
  const color = tone ? { color: `hsl(var(--sev-${tone}))` } : undefined;
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-faint uppercase tracking-wide">{label}</span>
      <span className="text-2xl font-semibold leading-none" style={color as CSSProperties}>{value}</span>
      {sub && <span className="text-xs text-dim">{sub}</span>}
      {prov && <Prov source={prov} />}
    </div>
  );
}

/** Labelled key/value grid used by every evidence panel. */
export function KV({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt>{k}</dt>
          <dd>{v ?? <span className="text-faint">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Horizontal meter, 0–100. Colour follows the value, not a fixed accent, so a
 *  high score reads as danger without reading the number. */
export function Meter({ value, tone, height = 8 }: { value: number; tone?: string; height?: number }) {
  const t = tone ?? (value >= 80 ? 'critical' : value >= 60 ? 'high'
    : value >= 35 ? 'medium' : value >= 15 ? 'low' : 'info');
  return (
    <div className="w-full rounded-full bg-sunk overflow-hidden" style={{ height }}>
      <motion.div className="h-full rounded-full"
        style={{ background: `hsl(var(--sev-${t}))` }}
        initial={{ width: 0 }} animate={{ width: `${Math.max(0, Math.min(100, value))}%` }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }} />
    </div>
  );
}

/** Radial gauge for the headline risk score. SVG, so it prints. */
export function Gauge({ value, size = 132, label }: { value: number; size?: number; label?: string }) {
  const t = value >= 80 ? 'critical' : value >= 60 ? 'high'
    : value >= 35 ? 'medium' : value >= 15 ? 'low' : 'low';
  const r = size / 2 - 10;
  const circ = 2 * Math.PI * r;
  const dash = (Math.max(0, Math.min(100, value)) / 100) * circ;
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke="hsl(var(--line-strong))" strokeWidth={9} />
        <motion.circle cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke={`hsl(var(--sev-${t}))`} strokeWidth={9} strokeLinecap="round"
          strokeDasharray={circ} initial={{ strokeDashoffset: circ }}
          animate={{ strokeDashoffset: circ - dash }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }} />
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        <div className="text-center">
          <div className="text-3xl font-bold leading-none" style={{ color: `hsl(var(--sev-${t}))` }}>
            {Math.round(value)}</div>
          {label && <div className="text-[10px] uppercase tracking-wider text-faint mt-1">{label}</div>}
        </div>
      </div>
    </div>
  );
}

/** Pointer-tracking parallax tile for the dashboard hero row. Degrades to a flat
 *  card when depth is 0 or motion is off — the tilt would fight reduced-motion. */
export function TiltTile({ children, className = '' }: { children: ReactNode; className?: string }) {
  const { prefs } = usePrefs();
  const ref = useRef<HTMLDivElement>(null);
  const mx = useMotionValue(0);
  const my = useMotionValue(0);
  const rx = useSpring(useTransform(my, [-0.5, 0.5], [6, -6]), { stiffness: 200, damping: 20 });
  const ry = useSpring(useTransform(mx, [-0.5, 0.5], [-6, 6]), { stiffness: 200, damping: 20 });
  const flat = prefs.depth === 0 || prefs.motion === 'off';
  return (
    <div className="tilt-root">
      <motion.div ref={ref} className={`tilt surface p-4 ${className}`}
        style={flat ? {} : { rotateX: rx, rotateY: ry }}
        onPointerMove={flat ? undefined : (e) => {
          const b = ref.current!.getBoundingClientRect();
          mx.set((e.clientX - b.left) / b.width - 0.5);
          my.set((e.clientY - b.top) / b.height - 0.5);
        }}
        onPointerLeave={() => { mx.set(0); my.set(0); }}>
        <div className={flat ? '' : 'tilt-layer'}>{children}</div>
      </motion.div>
    </div>
  );
}

export function Empty({ icon, title, hint }: { icon?: ReactNode; title: string; hint?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-14 px-6">
      {icon && <div className="text-faint mb-3 opacity-60">{icon}</div>}
      <p className="text-sm font-medium text-dim">{title}</p>
      {hint && <p className="text-xs text-faint mt-1 max-w-sm">{hint}</p>}
    </div>
  );
}

export function Skeleton({ className = '', lines }: { className?: string; lines?: number }) {
  if (lines) {
    return <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }).map((_, i) =>
        <div key={i} className="skeleton h-3" style={{ width: `${70 + (i % 3) * 10}%` }} />)}
    </div>;
  }
  return <div className={`skeleton ${className}`} />;
}

/** Copy-to-clipboard hash/id pill. */
export function Mono({ children, copy, className = '' }: {
  children: ReactNode; copy?: boolean; className?: string;
}) {
  const [done, setDone] = useState(false);
  const onCopy = () => {
    try {
      void navigator.clipboard.writeText(String(children));
      setDone(true);
      setTimeout(() => setDone(false), 1200);
    } catch { /* clipboard blocked */ }
  };
  return (
    <code className={`mono text-xs break-hash ${copy ? 'cursor-pointer hover:text-accent' : ''} ${className}`}
      onClick={copy ? onCopy : undefined} title={copy ? 'click to copy' : undefined}>
      {done ? 'copied ✓' : children}
    </code>
  );
}

/** Toast/notification, dismisses itself. Rendered by Shell. */
export function useToasts() {
  const [toasts, setToasts] = useState<{ id: number; msg: string; tone: string }[]>([]);
  const add = (msg: string, tone: 'info' | 'critical' | 'low' = 'info') => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, msg, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200);
  };
  const view = (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 no-print">
      {toasts.map((t) => (
        <motion.div key={t.id} initial={{ opacity: 0, x: 24 }} animate={{ opacity: 1, x: 0 }}
          className="surface surface-glass px-4 py-2.5 text-sm max-w-sm"
          style={{ borderColor: `hsl(var(--sev-${t.tone}) / 0.5)` }}>
          {t.msg}
        </motion.div>
      ))}
    </div>
  );
  return { add, view };
}

/** Collapse a long list behind a "show N more" toggle. */
export function Expand({ items, render, initial = 5, noun = 'items' }: {
  items: unknown[]; render: (item: unknown, i: number) => ReactNode; initial?: number; noun?: string;
}) {
  const [open, setOpen] = useState(false);
  const shown = open ? items : items.slice(0, initial);
  return (
    <>
      {shown.map((it, i) => render(it, i))}
      {items.length > initial && (
        <button className="btn btn-ghost btn-sm mt-1" onClick={() => setOpen(!open)}>
          {open ? 'Show less' : `Show ${items.length - initial} more ${noun}`}
        </button>
      )}
    </>
  );
}

export function useMounted() {
  const [m, setM] = useState(false);
  useEffect(() => setM(true), []);
  return m;
}
