/**
 * Typed API client with an offline fallback.
 *
 * One rule governs this file: the console must render *something real* whether or
 * not the Python backend is reachable. So every read has two sources — the live
 * API and a frozen snapshot (`demoSnapshot.json`, generated from a real pipeline
 * run) — and the client picks between them per request rather than per session.
 * A judge can open the built `dist/` from a file server with no backend and still
 * click through ten real cases; start the backend and the same UI goes live with
 * no code path change.
 *
 * Writes (ingest, decision, retention) have no offline equivalent, because
 * pretending to anchor a decision that was never recorded would be a lie the
 * demo tells about itself. In demo mode they surface a clear, honest error.
 */

import demoSnapshot from './demoSnapshot.json';
import type {
  CaseBundle, CampaignRow, CaseSummary, ChainPayload, ConfigPayload, GraphPayload,
  Health, MapLayout, ModelCard, QueuePage, RetentionStatus, SearchResult, Stats, TakedownDraft,
} from './types';

type Snapshot = {
  health?: Health; stats?: Stats; config?: ConfigPayload; model?: ModelCard;
  privacy?: Record<string, unknown>; retention?: RetentionStatus;
  queue?: { items?: CaseSummary[] }; cases?: Record<string, CaseBundle>;
  maps?: Record<string, MapLayout>; graphs?: Record<string, GraphPayload>;
  audits?: Record<string, unknown>; takedowns?: Record<string, TakedownDraft>;
  chains?: Record<string, unknown>; campaigns?: CampaignRow[];
  generated_at?: string; _note?: string;
};
const snap = demoSnapshot as unknown as Snapshot;

export type Mode = 'live' | 'demo' | 'probing';

class ApiError extends Error {
  constructor(public status: number, message: string, public reference?: string) {
    super(message);
    this.name = 'ApiError';
  }
}
export { ApiError };

/** Base URL. In dev the Vite proxy forwards /api; in the bundled build the same
 *  origin serves both, so an empty base is correct in both cases. An explicit
 *  VITE_API_BASE overrides for split deployments. */
const BASE = (import.meta.env.VITE_API_BASE ?? '').replace(/\/$/, '');

let mode: Mode = 'probing';
const listeners = new Set<(m: Mode) => void>();
export function onModeChange(fn: (m: Mode) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}
function setMode(next: Mode) {
  if (next === mode) return;
  mode = next;
  listeners.forEach((fn) => fn(mode));
}
export function currentMode(): Mode {
  return mode;
}

/** Force demo mode from the UI (the "offline demo" toggle), or clear the force. */
let forcedDemo = false;
export function forceDemo(on: boolean) {
  forcedDemo = on;
  setMode(on ? 'demo' : 'probing');
}

function analystHeader(): Record<string, string> {
  try {
    const raw = localStorage.getItem('mailtrace.prefs.v1');
    const name = raw ? (JSON.parse(raw).analyst as string) : '';
    return { 'X-Analyst': name || 'analyst@mailtrace.soc' };
  } catch {
    return { 'X-Analyst': 'analyst@mailtrace.soc' };
  }
}

async function http<T>(method: string, path: string, body?: unknown,
                       headers: Record<string, string> = {}): Promise<T> {
  const init: RequestInit = { method, headers: { ...analystHeader(), ...headers } };
  if (body !== undefined) {
    if (body instanceof FormData) {
      init.body = body;
    } else {
      init.body = JSON.stringify(body);
      (init.headers as Record<string, string>)['Content-Type'] = 'application/json';
    }
  }
  const res = await fetch(BASE + path, init);
  const text = await res.text();
  let payload: unknown = text;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON (e.g. a PDF served to the wrong caller) — surface as text */
  }
  if (!res.ok) {
    const error = payload && typeof payload === 'object' ? payload as Record<string, unknown> : {};
    const msg = typeof error.error === 'string' ? error.error : res.statusText || 'request failed';
    throw new ApiError(res.status, msg, typeof error.reference === 'string' ? error.reference : undefined);
  }
  return payload as T;
}

/**
 * A GET that falls back to the snapshot.
 *
 * `pick` extracts the equivalent value from the snapshot. If we are forced into
 * demo mode we never touch the network; otherwise we try live first, mark the
 * mode from the outcome, and fall back on any network error. A 4xx from a live
 * server is a real answer, not a connectivity failure, so it is *not* caught —
 * falling back there would hide a genuine bug behind stale demo data.
 */
async function read<T>(path: string, pick: () => T | undefined): Promise<T> {
  const fallback = () => {
    const value = pick();
    if (value === undefined) {
      throw new ApiError(404, 'not in the offline demo snapshot');
    }
    setMode('demo');
    return value;
  };
  if (forcedDemo) return fallback();
  try {
    const value = await http<T>('GET', path);
    setMode('live');
    return value;
  } catch (err) {
    if (err instanceof ApiError) throw err; // server answered; trust it
    return fallback(); // network/DNS/connection error → offline
  }
}

/** Writes never fall back — see the module docstring. */
async function write<T>(method: string, path: string, body?: unknown,
                        headers?: Record<string, string>): Promise<T> {
  if (forcedDemo) {
    throw new ApiError(503, 'This action needs the live backend. '
      + 'You are in offline demo mode — start the API and turn the demo toggle off.');
  }
  try {
    const value = await http<T>(method, path, body, headers);
    setMode('live');
    return value;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(503, 'The backend is unreachable. Start it with '
      + '`python mailtrace.py serve`, or use offline demo mode for read-only browsing.');
  }
}

export const api = {
  get mode() { return mode; },

  health: () => read<Health>('/api/health', () => snap.health),
  stats: () => read<Stats>('/api/stats', () => snap.stats),
  config: () => read<ConfigPayload>('/api/config', () => snap.config),
  model: () => read<ModelCard>('/api/model', () => snap.model),
  privacy: () => read<Record<string, unknown>>('/api/privacy', () => snap.privacy),
  retention: () => read<RetentionStatus>('/api/privacy/retention', () => snap.retention),

  cases: (q: Record<string, string | number | boolean | undefined> = {}) => {
    const qs = new URLSearchParams();
    Object.entries(q).forEach(([k, v]) => v !== undefined && v !== '' && qs.set(k, String(v)));
    const query = qs.toString();
    return read<QueuePage>('/api/cases' + (query ? '?' + query : ''), () => {
      // Client-side filter/sort over the snapshot so the queue controls still
      // work offline. Cheap: the demo set is a few dozen rows.
      const all = snap.queue?.items ?? [];
      let items = all.slice();
      if (q.verdict) items = items.filter((c) => c.verdict === q.verdict);
      if (q.threat_class) items = items.filter((c) => c.threat_class === q.threat_class);
      if (q.status) items = items.filter((c) => c.status === q.status);
      if (q.min_risk) items = items.filter((c) => c.risk_score >= Number(q.min_risk));
      if (q.campaign_id) items = items.filter((c) => c.campaign_id === q.campaign_id);
      const sort = String(q.sort ?? 'created');
      const key = sort === 'risk' ? 'risk_score' : sort === 'updated' ? 'updated_at' : 'created_at';
      items.sort((a, b) => (a[key] < b[key] ? 1 : -1));
      const offset = Number(q.offset ?? 0);
      const limit = Number(q.limit ?? 100);
      return { total: items.length, count: Math.min(limit, items.length),
        offset, sort, items: items.slice(offset, offset + limit) };
    });
  },

  case: (ref: string, mask = true) =>
    read<CaseBundle>(`/api/cases/${encodeURIComponent(ref)}?mask=${mask}`,
      () => snap.cases?.[ref]),

  caseMap: (ref: string) =>
    read<MapLayout>(`/api/cases/${encodeURIComponent(ref)}/map`, () => snap.maps?.[ref]),

  caseGraph: (ref: string) =>
    read<GraphPayload>(`/api/cases/${encodeURIComponent(ref)}/graph`, () => snap.graphs?.[ref]),

  caseAudit: (ref: string) =>
    read<unknown>(`/api/cases/${encodeURIComponent(ref)}/audit`, () => snap.audits?.[ref]),

  caseTakedown: (ref: string) =>
    read<TakedownDraft>(`/api/cases/${encodeURIComponent(ref)}/takedown`, () => snap.takedowns?.[ref]),

  chain: (ref: string) =>
    read<ChainPayload>(`/api/chain/${encodeURIComponent(ref)}`, () => snap.chains?.[ref] as ChainPayload | undefined),

  campaigns: () =>
    read<{ campaigns: CampaignRow[] }>('/api/campaigns', () => snap.campaigns ? { campaigns: snap.campaigns } : undefined),

  search: (query: string) => {
    const q = encodeURIComponent(query);
    return read<SearchResult>(`/api/search?q=${q}`, () => {
      const items = (snap.queue?.items ?? []).filter((c) =>
        JSON.stringify(c).toLowerCase().includes(query.toLowerCase()));
      return { backend: 'offline-substring', query, count: items.length, items };
    });
  },

  // Report can be viewed inline; in demo mode we point at the stored path.
  reportUrl: (ref: string) =>
    forcedDemo ? '' : `${BASE}/api/cases/${encodeURIComponent(ref)}/report`,

  // -- writes (live only) --------------------------------------------------
  ingest: (file: File, anchor = true) => {
    const fd = new FormData();
    fd.append('file', file, file.name);
    return write<CaseBundle>('POST', `/api/ingest?anchor=${anchor}`, fd);
  },
  ingestBytes: (fd: FormData, anchor = true) =>
    write<CaseBundle>('POST', `/api/ingest?anchor=${anchor}`, fd),
  ingestDemo: () => write<CaseBundle & { count?: number }>('POST', '/api/ingest/demo?wave=true', {}),
  decision: (ref: string, decision: string, note = '', overrideVerdict = '') => {
    let analyst = 'analyst@mailtrace.soc';
    try {
      const raw = localStorage.getItem('mailtrace.prefs.v1');
      if (raw && JSON.parse(raw).analyst) analyst = JSON.parse(raw).analyst;
    } catch {}
    return write<CaseBundle>('POST', `/api/cases/${encodeURIComponent(ref)}/decision`,
      { decision, note, override_verdict: overrideVerdict, analyst });
  },
  reinvestigate: (ref: string) =>
    write<CaseBundle>('POST', `/api/cases/${encodeURIComponent(ref)}/reinvestigate`, {}),
  patchConfig: (patch: Record<string, unknown>) =>
    write<ConfigPayload>('PATCH', '/api/config', patch),
  runRetention: (dryRun: boolean) =>
    write<RetentionStatus>('POST', `/api/privacy/retention?dry_run=${dryRun}`, {}),
  clearCases: () =>
    write<{ purged: number; message: string }>('POST', '/api/cases/clear', {}),
};

/** The snapshot's own metadata, for the "offline demo" banner. */
export const demoMeta = {
  generatedAt: snap.generated_at as string | undefined,
  note: snap._note as string | undefined,
  caseCount: Object.keys(snap.cases ?? {}).length,
};
