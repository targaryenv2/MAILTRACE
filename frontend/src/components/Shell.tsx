/**
 * Application shell: nav rail, top bar, settings drawer, command palette.
 *
 * The shell owns chrome and preferences; it knows nothing about case data. Views
 * are handed the current route and a `navigate` function and render themselves.
 *
 * The settings drawer is where the "micromanagement" lives, split into two
 * groups the user must not confuse: **Appearance** (local, cosmetic — theme,
 * accent, depth, motion, density) and **Analysis** (server-side, consequential —
 * thresholds, retention, masking). The second group writes to the backend and is
 * labelled as affecting every analyst, because a per-browser risk threshold would
 * mean two people seeing different verdicts for the same mail.
 */

import { useEffect, useRef, useState, type ReactNode } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Activity, Boxes, Command, Inbox, LayoutDashboard, Moon, Radio, Search,
  Settings2, Shield, Sun, X, Zap,
} from 'lucide-react';
import { ACCENTS, usePrefs, type Density, type MotionMode, type ThemeMode } from '../lib/theme';
import { api, currentMode, forceDemo, onModeChange, type Mode } from '../lib/api';
import type { LiveStatus } from '../lib/live';
import { Toggle } from './ui';

export type Route =
  | { name: 'landing' } | { name: 'dashboard' } | { name: 'ingest' } | { name: 'queue' }
  | { name: 'campaigns' } | { name: 'settings' } | { name: 'case'; ref: string };

const NAV: { name: Route['name']; label: string; icon: ReactNode }[] = [
  { name: 'dashboard', label: 'Overview', icon: <LayoutDashboard size={17} /> },
  { name: 'ingest', label: 'Analyse mail', icon: <Inbox size={17} /> },
  { name: 'campaigns', label: 'Campaigns', icon: <Activity size={17} /> },
  { name: 'queue', label: 'Case queue', icon: <Boxes size={17} /> },
  { name: 'settings', label: 'Settings', icon: <Settings2 size={17} /> },
];

function ModeBadge({ mode, live }: { mode: Mode; live: LiveStatus }) {
  if (mode === 'demo') {
    return <span className="chip chip-medium" title="Backend unreachable — reading the frozen demo snapshot">
      <Radio size={11} /> offline demo</span>;
  }
  const tone = live === 'live' ? 'low' : live === 'polling' ? 'medium' : 'info';
  const label = live === 'live' ? 'live' : live === 'polling' ? 'polling' : live === 'connecting' ? 'connecting' : 'idle';
  return <span className={`chip chip-${tone}`} title="Connected to the live backend">
    <span className="relative flex h-2 w-2">
      {live === 'live' && <span className="absolute inline-flex h-full w-full rounded-full opacity-75"
        style={{ background: `hsl(var(--sev-low))`, animation: 'pulse-ring 2s ease-out infinite' }} />}
      <span className="relative inline-flex rounded-full h-2 w-2" style={{ background: `hsl(var(--sev-${tone}))` }} />
    </span> {label}</span>;
}

export function Shell({ route, navigate, live, children, onCommand }: {
  route: Route; navigate: (r: Route) => void; live: LiveStatus;
  children: ReactNode; onCommand?: (q: string) => void;
}) {
  const { resolved, set } = usePrefs();
  const [drawer, setDrawer] = useState(false);
  const [palette, setPalette] = useState(false);
  const [mode, setMode] = useState<Mode>(currentMode());
  const [q, setQ] = useState('');

  useEffect(() => onModeChange(setMode), []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault(); setPalette((p) => !p);
      }
      if (e.key === 'Escape') { setPalette(false); setDrawer(false); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const submitSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (q.trim() && onCommand) onCommand(q.trim());
  };

  return (
    <div className="min-h-screen flex">
      {/* nav rail */}
      <aside className="hidden md:flex flex-col w-rail shrink-0 border-r border-line
                        surface-glass sticky top-0 h-screen no-print z-20">
        <div className="flex items-center gap-2 px-4 h-topbar border-b border-line">
          <div className="grid place-items-center w-8 h-8 rounded-lg"
               style={{ background: 'var(--accent-soft)', border: '1px solid var(--accent-line)' }}>
            <Shield size={18} className="text-accent" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-bold tracking-tight">MailTrace</div>
            <div className="text-[10px] text-faint">Forensic threat intelligence</div>
          </div>
        </div>
        <nav className="flex-1 p-2 space-y-0.5">
          {NAV.map((item) => {
            const active = route.name === item.name;
            return (
              <button key={item.name} onClick={() => navigate({ name: item.name } as Route)}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors
                  ${active ? 'text-ink' : 'text-dim hover:text-ink hover:bg-raised/60'}`}
                style={active ? { background: 'var(--accent-soft)', border: '1px solid var(--accent-line)' } : {}}>
                {item.icon}<span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <div className="p-3 border-t border-line space-y-2">
          <button onClick={() => setPalette(true)}
            className="w-full flex items-center justify-between px-3 py-1.5 rounded-lg text-xs
                       text-faint border border-line hover:text-ink hover:border-line-strong">
            <span className="flex items-center gap-1.5"><Command size={12} /> Command</span>
            <kbd className="text-[10px]">⌘K</kbd>
          </button>
        </div>
      </aside>

      {/* main column */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="sticky top-0 z-10 h-topbar flex items-center gap-3 px-4
                           border-b border-line surface-glass no-print">
          <button className="md:hidden btn btn-ghost btn-sm" onClick={() => navigate({ name: 'dashboard' })}>
            <Shield size={16} className="text-accent" />
          </button>
          <form onSubmit={submitSearch} className="flex-1 max-w-md relative">
            <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
            <input value={q} onChange={(e) => setQ(e.target.value)}
              placeholder="Search cases, senders, IOCs…"
              className="field pl-8 py-1.5 text-sm" />
          </form>
          <div className="flex items-center gap-2">
            <ModeBadge mode={mode} live={live} />
            <button className="btn btn-ghost btn-sm" title="Toggle theme"
              onClick={() => set('theme', resolved === 'dark' ? 'light' : 'dark')}>
              {resolved === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
            <button className="btn btn-ghost btn-sm" title="Settings" onClick={() => setDrawer(true)}>
              <Settings2 size={15} />
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 md:p-6 max-w-[1500px] w-full mx-auto animate-rise-in">
          {children}
        </main>

        {/* mobile nav */}
        <nav className="md:hidden sticky bottom-0 grid grid-cols-5 border-t border-line surface-glass no-print z-20">
          {NAV.map((item) => (
            <button key={item.name} onClick={() => navigate({ name: item.name } as Route)}
              className={`flex flex-col items-center py-2 text-[10px] gap-0.5
                ${route.name === item.name ? 'text-accent' : 'text-faint'}`}>
              {item.icon}{item.label.split(' ')[0]}
            </button>
          ))}
        </nav>
      </div>

      <SettingsDrawer open={drawer} onClose={() => setDrawer(false)} />
      <Palette open={palette} onClose={() => setPalette(false)} navigate={navigate}
               onSearch={(text) => { onCommand?.(text); setPalette(false); }} />
    </div>
  );
}

// ---------------------------------------------------------------------------

function Section({ title, note, children }: { title: string; note?: string; children: ReactNode }) {
  return (
    <div className="space-y-3">
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-dim">{title}</h4>
        {note && <p className="text-[11px] text-faint mt-0.5">{note}</p>}
      </div>
      {children}
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-sm text-dim">{label}</span>
      {children}
    </div>
  );
}

function SettingsDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { prefs, set, reset } = usePrefs();
  const [demo, setDemo] = useState(currentMode() === 'demo');
  const [analysis, setAnalysis] = useState<Record<string, string | number | boolean> | null>(null);
  const [saving, setSaving] = useState<string>('');

  useEffect(() => onModeChange((m) => setDemo(m === 'demo')), []);
  useEffect(() => {
    if (open) api.config().then((c) => setAnalysis(c.settings)).catch(() => setAnalysis(null));
  }, [open]);

  const saveAnalysis = async (patch: Record<string, unknown>) => {
    setSaving(Object.keys(patch)[0]);
    try {
      const next = await api.patchConfig(patch);
      setAnalysis(next.settings);
    } catch {
      // leave the previous value; the field will snap back on next open
    } finally {
      setSaving('');
    }
  };

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div className="fixed inset-0 bg-black/50 z-30 no-print"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} />
          <motion.aside className="fixed right-0 top-0 h-screen w-[min(420px,92vw)] z-40 no-print
                                   surface surface-glass overflow-y-auto"
            initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
            transition={{ type: 'spring', stiffness: 320, damping: 34 }}>
            <div className="flex items-center justify-between px-5 h-topbar border-b border-line sticky top-0 surface-glass z-10">
              <h3 className="font-semibold flex items-center gap-2"><Settings2 size={16} /> Settings</h3>
              <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={16} /></button>
            </div>

            <div className="p-5 space-y-6">
              <Section title="Appearance" note="Stored in this browser. Cosmetic only.">
                <Row label="Theme">
                  <div className="flex gap-1">
                    {(['dark', 'light', 'system'] as ThemeMode[]).map((t) => (
                      <button key={t} onClick={() => set('theme', t)}
                        className={`btn btn-sm ${prefs.theme === t ? 'btn-primary' : ''}`}>{t}</button>
                    ))}
                  </div>
                </Row>
                <Row label="Accent">
                  <div className="flex gap-1.5">
                    {ACCENTS.map((a) => (
                      <button key={a.hue} title={a.name} onClick={() => set('accentHue', a.hue)}
                        className="w-5 h-5 rounded-full border-2 transition-transform hover:scale-110"
                        style={{ background: `hsl(${a.hue} 90% 60%)`,
                          borderColor: prefs.accentHue === a.hue ? 'hsl(var(--text))' : 'transparent' }} />
                    ))}
                  </div>
                </Row>
                <Row label="Density">
                  <div className="flex gap-1">
                    {(['compact', 'cosy', 'roomy'] as Density[]).map((d) => (
                      <button key={d} onClick={() => set('density', d)}
                        className={`btn btn-sm ${prefs.density === d ? 'btn-primary' : ''}`}>{d}</button>
                    ))}
                  </div>
                </Row>
                <Row label="Motion">
                  <div className="flex gap-1">
                    {(['full', 'reduced', 'off'] as MotionMode[]).map((m) => (
                      <button key={m} onClick={() => set('motion', m)}
                        className={`btn btn-sm ${prefs.motion === m ? 'btn-primary' : ''}`}>{m}</button>
                    ))}
                  </div>
                </Row>
                <div>
                  <Row label={`Depth · ${prefs.depth.toFixed(1)}`}>
                    <input type="range" className="field w-40" min={0} max={3} step={0.5}
                      value={prefs.depth} onChange={(e) => set('depth', Number(e.target.value))} />
                  </Row>
                  <p className="text-[11px] text-faint mt-1">Scales every shadow, blur and the backdrop. 0 flattens the UI for weak GPUs.</p>
                </div>
                <Row label="Frosted glass"><Toggle on={prefs.glass} onChange={(v) => set('glass', v)} /></Row>
                <Row label="3-D backdrop"><Toggle on={prefs.backdrop} onChange={(v) => set('backdrop', v)} /></Row>
                <Row label="Show provenance"><Toggle on={prefs.showProvenance} onChange={(v) => set('showProvenance', v)} /></Row>
              </Section>

              <Section title="Workspace" note="How the console behaves for you.">
                <Row label="Live feed on load"><Toggle on={prefs.liveFeed} onChange={(v) => set('liveFeed', v)} /></Row>
                <Row label="Follow new cases"><Toggle on={prefs.followNewCases} onChange={(v) => set('followNewCases', v)} /></Row>
                <Row label="Raw header mode"><Toggle on={prefs.rawMode} onChange={(v) => set('rawMode', v)} /></Row>
                <Row label="Queue page size">
                  <input type="number" min={10} max={100} step={5} className="field w-20 text-sm"
                    value={prefs.pageSize} onChange={(e) => set('pageSize', Number(e.target.value))} />
                </Row>
                <div>
                  <label className="text-sm text-dim">Analyst identity</label>
                  <input className="field mt-1 text-sm" placeholder="e.g. j.okoro"
                    value={prefs.analyst} onChange={(e) => set('analyst', e.target.value)} />
                  <p className="text-[11px] text-faint mt-1">Attached to your decisions as <code>X-Analyst</code>. Not a credential; it labels the audit trail.</p>
                </div>
                <Row label="Offline demo mode">
                  <Toggle on={demo} onChange={(v) => forceDemo(v)} />
                </Row>
              </Section>

              <Section title="Analysis" note="Server-side. Changes affect verdicts for every analyst, not just you.">
                {!analysis ? (
                  <p className="text-xs text-faint">{demo ? 'Unavailable in offline demo mode.' : 'Loading…'}</p>
                ) : (
                  <div className="space-y-3">
                    <div>
                      <Row label={`Conclusive-safe below ${analysis.conclusive_low ?? '—'}`}>
                        <input type="range" className="field w-36" min={0} max={50} step={1} disabled={demo}
                          value={Number(analysis.conclusive_low ?? 15)}
                          onChange={(e) => setAnalysis({ ...analysis, conclusive_low: Number(e.target.value) })}
                          onMouseUp={(e) => saveAnalysis({ conclusive_low: Number((e.target as HTMLInputElement).value) })} />
                      </Row>
                      <Row label={`Conclusive-malicious above ${analysis.conclusive_high ?? '—'}`}>
                        <input type="range" className="field w-36" min={50} max={100} step={1} disabled={demo}
                          value={Number(analysis.conclusive_high ?? 85)}
                          onChange={(e) => setAnalysis({ ...analysis, conclusive_high: Number(e.target.value) })}
                          onMouseUp={(e) => saveAnalysis({ conclusive_high: Number((e.target as HTMLInputElement).value) })} />
                      </Row>
                      <p className="text-[11px] text-faint mt-1">The agent stops early only outside this band; inside it, the case goes to a human.</p>
                    </div>
                    <Row label="SLA target (min)">
                      <input type="number" min={1} max={240} className="field w-20 text-sm" disabled={demo}
                        value={Number(analysis.sla_minutes ?? 20)}
                        onChange={(e) => setAnalysis({ ...analysis, sla_minutes: Number(e.target.value) })}
                        onBlur={(e) => saveAnalysis({ sla_minutes: Number(e.target.value) })} />
                    </Row>
                    <Row label="Retention (days)">
                      <input type="number" min={0} max={3650} className="field w-20 text-sm" disabled={demo}
                        value={Number(analysis.retention_days ?? 90)}
                        onChange={(e) => setAnalysis({ ...analysis, retention_days: Number(e.target.value) })}
                        onBlur={(e) => saveAnalysis({ retention_days: Number(e.target.value) })} />
                    </Row>
                    <Row label="PII masking">
                      <Toggle on={!!analysis.pii_masking} onChange={(v) => { setAnalysis({ ...analysis, pii_masking: v }); saveAnalysis({ pii_masking: v }); }} />
                    </Row>
                    <Row label="Allow live network">
                      <Toggle on={!!analysis.allow_network} onChange={(v) => { setAnalysis({ ...analysis, allow_network: v }); saveAnalysis({ allow_network: v }); }} />
                    </Row>
                    <Row label="Allow link detonation">
                      <Toggle on={!!analysis.allow_detonation} onChange={(v) => { setAnalysis({ ...analysis, allow_detonation: v }); saveAnalysis({ allow_detonation: v }); }} />
                    </Row>
                    {saving && <p className="text-[11px] text-accent">saving {saving}…</p>}
                  </div>
                )}
              </Section>

              <button className="btn btn-danger btn-sm w-full" onClick={reset}>Reset appearance to defaults</button>
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

function Palette({ open, onClose, navigate, onSearch }: {
  open: boolean; onClose: () => void; navigate: (r: Route) => void; onSearch: (q: string) => void;
}) {
  const [q, setQ] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => { if (open) { setQ(''); setTimeout(() => inputRef.current?.focus(), 40); } }, [open]);

  const actions = [
    { label: 'Go to Overview', icon: <LayoutDashboard size={15} />, run: () => navigate({ name: 'dashboard' }) },
    { label: 'Analyse a mail', icon: <Inbox size={15} />, run: () => navigate({ name: 'ingest' }) },
    { label: 'View campaigns', icon: <Activity size={15} />, run: () => navigate({ name: 'campaigns' }) },
    { label: 'Open case queue', icon: <Boxes size={15} />, run: () => navigate({ name: 'queue' }) },
    { label: 'Open settings', icon: <Settings2 size={15} />, run: () => navigate({ name: 'settings' }) },
  ].filter((a) => a.label.toLowerCase().includes(q.toLowerCase()));

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div className="fixed inset-0 bg-black/50 z-40 no-print"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} />
          <motion.div className="fixed left-1/2 top-24 -translate-x-1/2 w-[min(560px,92vw)] z-50 no-print surface surface-glass overflow-hidden"
            initial={{ opacity: 0, y: -12, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -12, scale: 0.98 }}>
            <form onSubmit={(e) => { e.preventDefault(); if (q.trim()) onSearch(q.trim()); }}
                  className="flex items-center gap-2 px-4 py-3 border-b border-line">
              <Zap size={16} className="text-accent" />
              <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)}
                placeholder="Jump to… or search cases / IOCs and press Enter"
                className="flex-1 bg-transparent outline-none text-sm" />
              <kbd className="text-[10px] text-faint">esc</kbd>
            </form>
            <div className="max-h-72 overflow-y-auto p-1.5">
              {actions.map((a) => (
                <button key={a.label} onClick={() => { a.run(); onClose(); }}
                  className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-dim hover:text-ink hover:bg-raised/60">
                  {a.icon}{a.label}
                </button>
              ))}
              {q.trim() && (
                <button onClick={() => onSearch(q.trim())}
                  className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-accent hover:bg-raised/60">
                  <Search size={15} /> Search for “{q.trim()}”
                </button>
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
