/** Presentation helpers. Pure functions, no React — unit-tested in isolation. */

import type { Provenance, RiskLevel } from './types';

/** Severity/risk-level → the chip class defined in index.css. */
export function riskChip(level: RiskLevel | string): string {
  switch (level) {
    case 'critical': return 'chip chip-critical';
    case 'high': return 'chip chip-high';
    case 'medium': return 'chip chip-medium';
    case 'low': return 'chip chip-low';
    case 'clean': return 'chip chip-clean';
    default: return 'chip chip-info';
  }
}

export function sevChip(sev: string): string {
  return riskChip(sev === 'info' ? 'info' : (sev as RiskLevel));
}

/** Map a 0–100 risk score to a level, matching the backend's own bands. */
export function levelFor(score: number): RiskLevel {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  if (score >= 15) return 'low';
  return 'clean';
}

export function verdictLabel(v: string): string {
  const map: Record<string, string> = {
    phishing: 'Phishing', suspicious: 'Suspicious', benign: 'Benign',
    indeterminate: 'Indeterminate',
  };
  return map[v] ?? v;
}

export function threatLabel(t: string): string {
  const map: Record<string, string> = {
    legitimate: 'Legitimate', suspicious: 'Suspicious', impersonated: 'Impersonation',
    phishing: 'Phishing', fraud: 'Fraud / BEC',
  };
  return map[t] ?? t;
}

export function actorLabel(a: string): string {
  const map: Record<string, string> = {
    'compromised-account': 'Compromised account',
    'spoofed-domain': 'Spoofed domain',
    'anonymised-infrastructure': 'Anonymised infrastructure',
    'direct-actor': 'Direct actor',
    unknown: 'Insufficient evidence',
  };
  return map[a] ?? a;
}

export function provLabel(p: Provenance | string | undefined): string {
  if (!p) return '';
  const map: Record<string, string> = {
    live: 'live', fixture: 'fixture', simulated: 'simulated',
    'offline-table': 'offline db', computed: 'computed', unavailable: 'n/a',
  };
  return map[p] ?? p;
}
export function provClass(p: Provenance | string | undefined): string {
  return 'prov prov-' + String(p ?? 'computed');
}

const AUTH_TONE: Record<string, string> = {
  pass: 'low', fail: 'critical', softfail: 'high', neutral: 'info',
  none: 'medium', temperror: 'medium', permerror: 'high', bestguesspass: 'medium',
};
export function authChip(result?: string): string {
  return riskChip((AUTH_TONE[(result ?? '').toLowerCase()] ?? 'info') as RiskLevel);
}

/** Short, locale-stable timestamp. Avoids toLocaleString's per-machine variance
 *  so screenshots and the exported report agree. */
export function fmtTime(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z').slice(0, 19) + 'Z';
}

export function fmtDate(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
}

export function ago(iso?: string): string {
  if (!iso) return '';
  const then = new Date(iso).getTime();
  if (isNaN(then)) return '';
  const s = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function fmtDuration(seconds?: number): string {
  if (seconds === undefined || seconds === null) return '—';
  const s = Math.abs(Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

/** SLA remaining, signed: negative means breached. */
export function slaText(remaining: number, breached: boolean): string {
  if (breached) return `breached ${fmtDuration(-remaining)} ago`;
  return `${fmtDuration(remaining)} left`;
}

export function bytes(n?: number): string {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}

export function truncateMiddle(s: string, max = 22): string {
  if (!s || s.length <= max) return s;
  const half = Math.floor((max - 1) / 2);
  return `${s.slice(0, half)}…${s.slice(-half)}`;
}

export function flag(cc?: string): string {
  if (!cc || cc.length !== 2 || !/^[a-zA-Z]{2}$/.test(cc)) return '🏳️';
  const base = 0x1f1e6;
  return String.fromCodePoint(
    base + cc.toUpperCase().charCodeAt(0) - 65,
    base + cc.toUpperCase().charCodeAt(1) - 65,
  );
}

export function pct(n?: number | string): string {
  if (n === undefined || n === null || n === '') return '—';
  if (typeof n === 'string') {
    const num = parseFloat(n);
    if (isNaN(num)) return n;
    return `${Math.round(num <= 1 && num > 0 ? num * 100 : num)}%`;
  }
  return `${Math.round(n <= 1 && n > 0 ? n * 100 : n)}%`;
}

/** Coerce backend rationale (string | string[]) into a list for rendering. */
export function asList(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === 'string' && v.trim()) return [v];
  return [];
}
