/**
 * Overview dashboard.
 *
 * The first screen a judge sees, so it has to answer "what does this system do"
 * in one glance: volume and disposition up top, the live agent feed on the right
 * (proof it is actually working, not a static mock), and the highest-risk open
 * cases below as the obvious next click. Every number is a real aggregate from
 * `/api/stats`; nothing here is illustrative.
 */

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  AlertTriangle, Boxes, BrainCircuit, Link2, ShieldAlert, ShieldCheck, TrendingUp,
} from 'lucide-react';
import { api } from '../lib/api';
import type { CaseSummary, Health, LiveEvent, ModelCard, Stats } from '../lib/types';
import type { Route } from '../components/Shell';
import {
  Button, Chip, Empty, Meter, Panel, Prov, Skeleton, Stat, TiltTile,
} from '../components/ui';
import { pct, riskChip, threatLabel, truncateMiddle, verdictLabel } from '../lib/format';

export function Dashboard({ navigate, events }: {
  navigate: (r: Route) => void; events: LiveEvent[];
}) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [model, setModel] = useState<ModelCard | null>(null);
  const [top, setTop] = useState<CaseSummary[] | null>(null);

  useEffect(() => {
    api.stats().then(setStats).catch(() => setStats(null));
    api.health().then(setHealth).catch(() => setHealth(null));
    api.model().then(setModel).catch(() => setModel(null));
    api.cases({ sort: 'risk', limit: 6 }).then((q) => setTop(q.items)).catch(() => setTop([]));
  }, []);

  const heroes = [
    { label: 'Cases analysed', value: stats?.total ?? '—', icon: <Boxes size={18} />, tone: undefined },
    { label: 'Phishing', value: stats?.phishing ?? '—', icon: <ShieldAlert size={18} />, tone: 'critical' },
    { label: 'Awaiting review', value: stats?.awaiting_review ?? '—', icon: <AlertTriangle size={18} />, tone: 'high' },
    { label: 'Anchored on-chain', value: stats?.chain_anchored ?? '—', icon: <Link2 size={18} />, tone: 'low' },
  ];

  const total = stats?.total ?? 0;
  const benignCount = stats?.benign ?? (total > 0 ? Math.max(0, total - (stats?.phishing ?? 0) - (stats?.suspicious ?? 0) - (stats?.indeterminate ?? 0)) : 0);
  const dist = [
    { label: 'Phishing', n: stats?.phishing ?? 0, tone: 'critical' },
    { label: 'Suspicious', n: stats?.suspicious ?? 0, tone: 'high' },
    { label: 'Indeterminate', n: stats?.indeterminate ?? 0, tone: 'medium' },
    { label: 'Benign', n: benignCount, tone: 'low' },
  ];

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Threat overview</h1>
          <p className="text-sm text-dim">
            {health?.organisation ?? 'MailTrace'} · agentic email forensics
            {health && <span className="text-faint"> · v{health.version}</span>}
          </p>
        </div>
        <Button variant="primary" onClick={() => navigate({ name: 'ingest' })}>
          <Boxes size={15} /> Analyse a mail
        </Button>
      </div>

      {/* hero tiles with parallax tilt */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {heroes.map((h, i) => (
          <motion.div key={h.label} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.06 }}>
            <TiltTile>
              <div className="flex items-start justify-between">
                <Stat label={h.label} value={h.value} tone={h.tone} />
                <span className="text-dim opacity-70">{h.icon}</span>
              </div>
            </TiltTile>
          </motion.div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 space-y-5">
          <Panel title="Disposition" subtitle="How analysed mail was classified"
                 icon={<TrendingUp size={16} />}>
            {!stats ? <Skeleton lines={4} /> : (
              <div className="space-y-3">
                {dist.map((d) => (
                  <div key={d.label}>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-dim">{d.label}</span>
                      <span className="text-faint">{d.n} · {pct(total > 0 ? (d.n / total) * 100 : 0)}</span>
                    </div>
                    <Meter value={total > 0 ? (d.n / total) * 100 : 0} tone={d.tone} />
                  </div>
                ))}

                <div className="pt-2 flex flex-wrap gap-2">
                  {stats.threat_classes && Object.entries(stats.threat_classes).map(([k, v]) => (
                    <Chip key={k} tone={k === 'fraud' || k === 'phishing' ? 'critical' : k === 'impersonated' ? 'high' : 'info'}>
                      {threatLabel(k)} · {v}</Chip>
                  ))}
                </div>
              </div>
            )}
          </Panel>

          <Panel title="Highest-risk open cases" icon={<ShieldAlert size={16} />}
            right={<Button size="sm" variant="ghost" onClick={() => navigate({ name: 'queue' })}>All cases →</Button>}>
            {!top ? <Skeleton lines={5} /> : top.length === 0 ? (
              <Empty title="No cases yet" hint="Analyse a mail or seed the demo set to populate the queue." />
            ) : (
              <div className="divide-y divide-line -mx-1">
                {top.map((c) => (
                  <button key={c.id} onClick={() => navigate({ name: 'case', ref: c.case_number })}
                    className="w-full text-left px-1 py-2.5 flex items-center gap-3 hover:bg-raised/40 rounded transition-colors">
                    <span className="text-lg font-bold tabular-nums w-9 text-right"
                      style={{ color: `hsl(var(--sev-${c.risk_level}))` }}>{Math.round(c.risk_score)}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm truncate">{c.subject || '(no subject)'}</div>
                      <div className="text-xs text-faint truncate">{c.sender_address}</div>
                    </div>
                    <div className="flex flex-col items-end gap-1 shrink-0">
                      <span className={riskChip(c.risk_level)}>{verdictLabel(c.verdict)}</span>
                      {c.action_status === 'approved' || c.status === 'approved' ? (
                        <span className="text-[10px] text-emerald-400 font-medium">✓ approved</span>
                      ) : c.action_status === 'escalated' || c.status === 'escalated' ? (
                        <span className="text-[10px] text-red-400 font-semibold uppercase tracking-wider">▲ escalated</span>
                      ) : c.action_status === 'overridden' || c.status === 'overridden' ? (
                        <span className="text-[10px] text-amber-400 font-medium">⟲ overridden</span>
                      ) : c.requires_human_review ? (
                        <span className="text-[10px] text-high">needs review</span>
                      ) : null}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </Panel>
        </div>

        <div className="space-y-5">
          <LivePanel events={events} navigate={navigate} />

          <Panel title="Detection model" subtitle="TF-IDF + logistic regression"
                 icon={<BrainCircuit size={16} />}>
            {!model ? <Skeleton lines={3} /> : (
              <div className="space-y-2 text-sm">
                <div className="flex justify-between"><span className="text-dim">Corpus</span>
                  <span>{model.corpus?.total ?? model.corpus?.documents ?? '—'} messages</span></div>
                <div className="flex justify-between"><span className="text-dim">Features</span>
                  <span>{model.feature_space?.vocabulary ?? model.feature_space?.features ?? '—'}</span></div>
                {model.cross_validation && (
                  <div className="flex justify-between"><span className="text-dim">CV AUC</span>
                    <span className="tabular-nums">{Number(model.cross_validation.auc ?? model.cross_validation.roc_auc ?? 0).toFixed(3)}</span></div>
                )}
                <div className="flex items-center justify-between pt-1">
                  <Prov source="computed" />
                  <span className="text-[11px] text-faint">held-out metrics are synthetic-corpus</span>
                </div>
              </div>
            )}
          </Panel>

          {health && (
            <Panel title="Capabilities" subtitle="Live vs offline fallback" icon={<ShieldCheck size={16} />}>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(health.capabilities).map(([k, v]) => {
                  const val = String(v);
                  const isLiveOrActive = val === 'live' || val === 'on' || val === 'trained' || val === 'allowed';
                  return (
                    <span
                      key={k}
                      className={`chip flex items-center gap-1 ${isLiveOrActive ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'chip-info'}`}
                      title={`${k}: ${val}`}
                    >
                      <span>{k}</span>
                      <span className="text-[10px] px-1 py-0.5 rounded bg-black/30 font-mono opacity-80">{val}</span>
                    </span>
                  );
                })}
              </div>
            </Panel>
          )}

        </div>
      </div>
    </div>
  );
}

function LivePanel({ events, navigate }: { events: LiveEvent[]; navigate: (r: Route) => void }) {
  const recent = [...events].reverse().slice(0, 12);
  return (
    <Panel title="Live investigation feed" subtitle="Agent activity, streamed"
           icon={<span className="relative flex h-2.5 w-2.5">
             <span className="absolute inline-flex h-full w-full rounded-full bg-accent opacity-60"
               style={{ animation: 'pulse-ring 2s ease-out infinite' }} />
             <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-accent" /></span>}>
      {recent.length === 0 ? (
        <p className="text-xs text-faint py-4 text-center">Waiting for agent activity…</p>
      ) : (
        <div className="space-y-1.5 max-h-72 overflow-y-auto no-scrollbar">
          {recent.map((e) => (
            <motion.div key={e.seq} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }}
              className="text-xs flex items-start gap-2 flash-in">
              <span className="text-faint tabular-nums shrink-0">#{e.seq}</span>
              <div className="min-w-0">
                <span className="text-dim">{describe(e)}</span>
                {typeof e.data.case_number === 'string' && (
                  <button className="text-accent ml-1 hover:underline"
                    onClick={() => navigate({ name: 'case', ref: e.data.case_number as string })}>
                    {e.data.case_number}</button>
                )}
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function describe(e: LiveEvent): string {
  const d = e.data;
  switch (e.kind) {
    case 'step': return `${d.action ?? 'step'} — ${truncateMiddle(String(d.result ?? ''), 48)}`;
    case 'case': return `case ready · risk ${Math.round(Number(d.risk_score ?? 0))}`;
    case 'ingest_start': return 'ingest started';
    case 'demo_start': return 'seeding demo corpus…';
    case 'demo_complete': return `demo seeded (${d.count ?? '?'} cases)`;
    case 'decision': return `analyst ${d.decision ?? 'decided'}`;
    case 'retention': return 'retention policy run';
    case 'config': return 'settings changed';
    default: return e.kind;
  }
}
