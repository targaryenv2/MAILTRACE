/**
 * Investigator — the full forensic view of one case.
 *
 * This is where every PS-26106 module surfaces: NLP/ML verdict with reasoning,
 * header & protocol authentication, origin trace + geo map, evidence signals,
 * ML explainability (exact Shapley), identity-correlation graph + attribution,
 * threat-intel, link detonation, blast radius, IOCs, MITRE mapping, and the
 * blockchain chain-of-custody. Tabs keep it navigable without hiding anything.
 *
 * The decision bar is the human-in-the-loop gate: nothing is "actioned" until an
 * analyst approves, overrides or escalates, and that action is what gets anchored.
 */

import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { motion } from 'framer-motion';
import {
  ArrowLeft, CheckCircle2, FileDown, FileText, Fingerprint, Gavel, Globe2, Link2, ListTree,
  Lock, Mail, MapPin, Network, Radar, ScrollText, ShieldAlert, ShieldQuestion,
  Siren, TestTube2,
} from 'lucide-react';
import { api, ApiError } from '../lib/api';
import type {
  CaseBundle, ChainPayload, EmailUrl, GraphPayload, Ioc, MapLayout, TakedownDraft,
} from '../lib/types';
import type { Route } from '../components/Shell';
import {
  Button, Card, Chip, Empty, Expand, Gauge, KV, Meter, Mono, Panel, Prov,
  Skeleton,
} from '../components/ui';
import { RelayMap } from '../components/RelayMap';
import { GraphView } from '../components/GraphView';
import {
  actorLabel, ago, asList, authChip, bytes, flag, fmtTime, pct,
  riskChip, sevChip, slaText, threatLabel, verdictLabel,
} from '../lib/format';

type Tab = 'overview' | 'auth' | 'trace' | 'evidence' | 'ml' | 'attribution'
  | 'intel' | 'custody' | 'raw';

const TABS: { id: Tab; label: string; icon: ReactNode }[] = [
  { id: 'overview', label: 'Overview', icon: <ShieldAlert size={15} /> },
  { id: 'auth', label: 'Authentication', icon: <Lock size={15} /> },
  { id: 'trace', label: 'Origin & trace', icon: <MapPin size={15} /> },
  { id: 'evidence', label: 'Evidence', icon: <Radar size={15} /> },
  { id: 'ml', label: 'ML explainability', icon: <TestTube2 size={15} /> },
  { id: 'attribution', label: 'Attribution', icon: <Network size={15} /> },
  { id: 'intel', label: 'Intel & detonation', icon: <Globe2 size={15} /> },
  { id: 'custody', label: 'Chain of custody', icon: <Link2 size={15} /> },
  { id: 'raw', label: 'Headers & raw', icon: <ScrollText size={15} /> },
];

export function Investigator({ caseRef, navigate, toast }: {
  caseRef: string; navigate: (r: Route) => void;
  toast: (m: string, tone?: 'info' | 'critical' | 'low') => void;
}) {
  const [bundle, setBundle] = useState<CaseBundle | null>(null);
  const [tab, setTab] = useState<Tab>('overview');
  const [notFound, setNotFound] = useState(false);
  const [deciding, setDeciding] = useState(false);

  const load = () => {
    setBundle(null); setNotFound(false);
    api.case(caseRef).then(setBundle).catch(() => setNotFound(true));
  };
  useEffect(load, [caseRef]);

  const decide = async (decision: string, note = '', override = '') => {
    setDeciding(true);
    try {
      await api.decision(caseRef, decision, note, override);
      const refreshed = await api.case(caseRef);
      setBundle(refreshed);
      toast(`Decision recorded: ${decision}`, 'low');
    } catch (e) {
      toast(e instanceof ApiError ? e.message : 'Decision failed', 'critical');
    } finally {
      setDeciding(false);
    }
  };

  if (notFound) {
    return <Empty icon={<ShieldQuestion size={40} />} title={`Case ${caseRef} not found`}
      hint={<Button size="sm" variant="ghost" onClick={() => navigate({ name: 'queue' })}>Back to queue</Button>} />;
  }
  if (!bundle) {
    return <div className="space-y-4"><Skeleton className="h-32" /><Skeleton lines={10} /></div>;
  }

  return (
    <div className="space-y-5">
      <button onClick={() => navigate({ name: 'queue' })}
        className="text-xs text-faint hover:text-ink flex items-center gap-1"><ArrowLeft size={13} /> Queue</button>

      <CaseHeader bundle={bundle} deciding={deciding} decide={decide} />

      {/* tab bar */}
      <div className="flex gap-1 overflow-x-auto no-scrollbar border-b border-line pb-px">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-2 text-sm whitespace-nowrap border-b-2 transition-colors
              ${tab === t.id ? 'text-ink' : 'text-faint hover:text-dim border-transparent'}`}
            style={tab === t.id ? { borderColor: 'var(--accent)' } : {}}>
            {t.icon}{t.label}
          </button>
        ))}
      </div>

      <motion.div key={tab} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}>
        {tab === 'overview' && <OverviewTab bundle={bundle} navigate={navigate} />}
        {tab === 'auth' && <AuthTab bundle={bundle} />}
        {tab === 'trace' && <TraceTab caseRef={caseRef} bundle={bundle} />}
        {tab === 'evidence' && <EvidenceTab bundle={bundle} />}
        {tab === 'ml' && <MlTab bundle={bundle} />}
        {tab === 'attribution' && <AttributionTab caseRef={caseRef} bundle={bundle} navigate={navigate} />}
        {tab === 'intel' && <IntelTab caseRef={caseRef} bundle={bundle} />}
        {tab === 'custody' && <CustodyTab caseRef={caseRef} bundle={bundle} />}
        {tab === 'raw' && <RawTab bundle={bundle} />}
      </motion.div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// header + decision bar
// ---------------------------------------------------------------------------

function CaseHeader({ bundle, deciding, decide }: {
  bundle: CaseBundle; deciding: boolean; decide: (d: string, n?: string, o?: string) => void;
}) {
  const c = bundle.case;
  const rawVerdict = c.verdict as any;
  const v = typeof rawVerdict === 'object' && rawVerdict !== null
    ? rawVerdict
    : {
        risk_score: (c as any).risk_score ?? 0,
        risk_level: (c as any).risk_level ?? 'clean',
        label: typeof rawVerdict === 'string' ? rawVerdict : (c as any).verdict ?? 'clean',
        threat_class: (c as any).threat_class ?? 'legitimate',
        confidence: (c as any).confidence ?? 0,
        confidence_band: (c as any).confidence_band ?? 'low',
      };
  const decided = c.action?.status && c.action.status !== 'pending';
  return (
    <Card className="p-5">
      <div className="flex flex-col lg:flex-row gap-5">
        <div className="flex items-center gap-5">
          <Gauge value={v.risk_score} label={v.risk_level} />
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <Mono>{c.case_number}</Mono>
              <span className={riskChip(v.risk_level)}>{verdictLabel(v.label)}</span>
              <span className={riskChip(v.threat_class === 'legitimate' ? 'clean' : 'high')}>{threatLabel(v.threat_class)}</span>
              {c.campaign?.is_duplicate && <Chip tone="medium">duplicate</Chip>}
            </div>
            <h1 className="text-xl font-bold tracking-tight mt-1 truncate">{c.subject || '(no subject)'}</h1>
            <p className="text-sm text-dim truncate">
              <Mail size={12} className="inline mr-1" />
              {c.sender_display ? `${c.sender_display} · ` : ''}{c.sender_address}</p>
            <div className="flex items-center gap-3 mt-1 text-xs text-faint">
              <span>confidence {pct(v.confidence)} ({v.confidence_band})</span>
              <span>· {ago(c.created_at)}</span>
              {c.origin?.place && <span>· {flag(c.origin.country_code)} {c.origin.place}</span>}
            </div>
          </div>
        </div>

        <div className="lg:ml-auto flex flex-col gap-2 lg:items-end justify-center">
          {c.sla && (
            <div className={`text-xs ${c.sla.breached ? 'text-critical' : 'text-dim'}`}>
              SLA · {slaText(c.sla.remaining_seconds, c.sla.breached)}
            </div>
          )}
          {decided ? (
            <div className="flex items-center gap-2 text-sm flex-wrap">
              <CheckCircle2 size={16} className="text-low" />
              <span className="text-dim">{c.action.status} by {c.action.analyst || 'analyst'}</span>
              {c.action.tx_hash && <Mono copy>{c.action.tx_hash.slice(0, 14)}…</Mono>}
              <a href={api.reportUrl(c.case_number)} target="_blank" rel="noreferrer" download>
                <Button variant="default" size="sm">
                  <FileDown size={14} /> PDF Report
                </Button>
              </a>
            </div>
          ) : (
            <div className="flex gap-2 flex-wrap">
              <Button variant="primary" disabled={deciding} onClick={() => decide('approve')}>
                <CheckCircle2 size={14} /> Approve verdict</Button>
              <Button variant="default" disabled={deciding} onClick={() => decide('override', '', v.label === 'phishing' ? 'benign' : 'phishing')}>
                <Gavel size={14} /> Override</Button>
              <Button variant="danger" disabled={deciding} onClick={() => decide('escalate')}>
                <Siren size={14} /> Escalate</Button>
              <a href={api.reportUrl(c.case_number)} target="_blank" rel="noreferrer" download>
                <Button variant="default" size="sm">
                  <FileDown size={14} /> PDF Report
                </Button>
              </a>
            </div>
          )}
          <div className="text-xs text-faint mt-1">{c.verdict.recommended_action}</div>
        </div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// tabs
// ---------------------------------------------------------------------------

function OverviewTab({ bundle, navigate }: { bundle: CaseBundle; navigate: (r: Route) => void }) {
  const c = bundle.case;
  const v = c.verdict;
  const blast = c.blast_radius;
  return (
    <div className="grid lg:grid-cols-3 gap-5">
      <div className="lg:col-span-2 space-y-5">
        <Panel title="Verdict reasoning" icon={<ShieldAlert size={16} />}>
          {v.narrative && <p className="text-sm text-dim leading-relaxed mb-3">{v.narrative}</p>}
          {asList(v.rationale).length > 0 && (
            <ul className="space-y-1.5 text-sm">
              {asList(v.rationale).map((r, i) => (
                <li key={i} className="flex gap-2"><span className="text-accent">›</span><span>{r}</span></li>
              ))}
            </ul>
          )}
          {v.ambiguity_flags && v.ambiguity_flags.length > 0 && (
            <div className="mt-3 pt-3 border-t border-line">
              <p className="text-xs text-faint mb-1">Why a human should look:</p>
              <div className="flex flex-wrap gap-1.5">
                {v.ambiguity_flags.map((a, i) => <Chip key={i} tone="medium">{a}</Chip>)}
              </div>
            </div>
          )}
          <div className="mt-3"><Prov source={v.narrative_source ?? 'computed'} /></div>
        </Panel>

        <Panel title="Next actions" icon={<ListTree size={16} />}>
          {bundle.next_actions?.length ? (
            <div className="space-y-2">
              {bundle.next_actions.map((a, i) => (
                <div key={i} className="flex items-start gap-3 text-sm">
                  <Chip tone={a.urgency === 'high' ? 'critical' : a.urgency === 'medium' ? 'high' : 'info'} className="shrink-0">
                    {a.urgency ?? 'info'}</Chip>
                  <div className="flex-1 min-w-0"><span className="font-medium">{a.action}</span>
                    <span className="text-faint"> — {a.detail}</span></div>
                </div>
              ))}
            </div>
          ) : <Empty title="No recommended follow-ups" />}
        </Panel>
      </div>

      <div className="space-y-5">
        <Panel title="Blast radius" icon={<Radar size={16} />}>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <KVBig label="Recipients" value={blast.total_recipients} />
            <KVBig label="Opened" value={blast.total_opened} />
            <KVBig label="Clicked" value={blast.total_clicked} tone="high" />
            <KVBig label="Submitted creds" value={blast.total_credentials_submitted} tone="critical" />
            <KVBig label="Reported" value={blast.total_reported} tone="low" />
            <KVBig label="High-value targets" value={blast.high_value_targets} tone="high" />
          </div>
          {blast.departments_affected && blast.departments_affected.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {blast.departments_affected.map((d) => <Chip key={d} tone="info">{d}</Chip>)}
            </div>
          )}
          {blast.is_campaign && c.campaign?.id && (
            <Button size="sm" variant="ghost" className="mt-3 w-full"
              onClick={() => navigate({ name: 'campaigns' })}>View campaign →</Button>
          )}
          <div className="mt-2"><Prov source={blast.source} /></div>
        </Panel>

        <Panel title="Indicators of compromise" icon={<Fingerprint size={16} />}
          right={<span className="text-xs text-faint">{c.iocs?.length ?? 0}</span>}>
          {c.iocs?.length ? (
            <div className="space-y-1.5">
              <Expand items={c.iocs} initial={6} noun="IOCs" render={(ioc: unknown, i) => {
                const item = ioc as Ioc;
                return (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className="chip chip-info shrink-0">{item.ioc_type}</span>
                  <Mono copy className="truncate flex-1">{item.value}</Mono>
                </div>
                );
              }} />
            </div>
          ) : <Empty title="No IOCs extracted" />}
        </Panel>
      </div>
    </div>
  );
}

function KVBig({ label, value, tone }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div>
      <div className="text-xl font-bold tabular-nums" style={tone ? { color: `hsl(var(--sev-${tone}))` } : {}}>{value}</div>
      <div className="text-[11px] text-faint">{label}</div>
    </div>
  );
}

function AuthTab({ bundle }: { bundle: CaseBundle }) {
  const auth = bundle.case.parsed_email.auth ?? {};
  const rows: { proto: string; result?: string; domain?: string; aligned?: boolean; extra?: string }[] = [
    { proto: 'SPF', result: auth.spf_result, domain: auth.spf_domain, aligned: auth.spf_aligned },
    { proto: 'DKIM', result: auth.dkim_result, domain: auth.dkim_domain, aligned: auth.dkim_aligned },
    { proto: 'DMARC', result: auth.dmarc_result, aligned: auth.dmarc_aligned, extra: auth.dmarc_policy ? `policy: ${auth.dmarc_policy}` : undefined },
    { proto: 'ARC', result: auth.arc_result },
  ];
  const pe = bundle.case.parsed_email;
  return (
    <div className="grid lg:grid-cols-2 gap-5">
      <Panel title="Email authentication" subtitle="SPF · DKIM · DMARC alignment" icon={<Lock size={16} />}>
        <div className="space-y-3">
          {rows.map((r) => (
            <div key={r.proto} className="flex items-center justify-between gap-3 row-hair pb-3">
              <div>
                <div className="font-medium text-sm">{r.proto}</div>
                {r.domain && <div className="text-xs text-faint">{r.domain}</div>}
                {r.extra && <div className="text-xs text-faint">{r.extra}</div>}
              </div>
              <div className="flex items-center gap-2">
                {r.aligned !== undefined && (
                  <span className={`text-xs ${r.aligned ? 'text-low' : 'text-critical'}`}>
                    {r.aligned ? 'aligned' : 'not aligned'}</span>
                )}
                <span className={authChip(r.result)}>{r.result ?? 'none'}</span>
              </div>
            </div>
          ))}
        </div>
        {asList(auth.alignment_notes ?? auth.notes).length > 0 && (
          <ul className="mt-3 space-y-1 text-xs text-dim">
            {asList(auth.alignment_notes ?? auth.notes).map((n, i) => <li key={i}>• {n}</li>)}
          </ul>
        )}
        <div className="mt-2"><Prov source={auth.source ?? 'computed'} /></div>
      </Panel>

      <Panel title="Header identity chain" subtitle="Return-Path · From · Reply-To" icon={<Mail size={16} />}>
        <KV rows={[
          ['From', <Mono>{pe.from_address}</Mono>],
          ['Display', pe.from_name || <span className="text-faint">none</span>],
          ['Return-Path', pe.return_path ? <Mono>{pe.return_path}</Mono> : '—'],
          ['Reply-To', pe.reply_to ? <Mono>{pe.reply_to}</Mono> : '—'],
          ['Message-ID', pe.message_id ? <Mono>{pe.message_id}</Mono> : '—'],
          ['Date', pe.date || '—'],
          ['To', (pe.to ?? []).join(', ') || '—'],
        ]} />
        {pe.parse_errors && pe.parse_errors.length > 0 && (
          <div className="mt-3 text-xs text-medium">Parse anomalies: {pe.parse_errors.join('; ')}</div>
        )}
      </Panel>

      {pe.urls && pe.urls.length > 0 && (
        <Panel title="Links" subtitle="Extracted URLs and anchor mismatches" icon={<Link2 size={16} />}
          className="lg:col-span-2">
          <div className="space-y-2">
            <Expand items={pe.urls} initial={8} noun="links" render={(url: unknown, i) => {
              const u = url as EmailUrl;
              return (
              <div key={i} className="flex items-center gap-2 text-xs row-hair pb-2">
                <Mono className="flex-1 truncate">{u.url}</Mono>
                {u.anchor_mismatch && <Chip tone="critical">anchor mismatch</Chip>}
                {u.is_punycode && <Chip tone="high">punycode</Chip>}
                {u.is_shortener && <Chip tone="medium">shortener</Chip>}
                {u.is_ip_literal && <Chip tone="high">IP literal</Chip>}
              </div>
              );
            }} />
          </div>
        </Panel>
      )}
    </div>
  );
}

function TraceTab({ caseRef, bundle }: { caseRef: string; bundle: CaseBundle }) {
  const [map, setMap] = useState<MapLayout | null>(null);
  useEffect(() => { api.caseMap(caseRef).then(setMap).catch(() => setMap(null)); }, [caseRef]);
  const c = bundle.case;
  const o = c.origin;
  return (
    <div className="space-y-5">
      <div className="grid lg:grid-cols-3 gap-5">
        <Panel title="Determined origin" icon={<MapPin size={16} />} className="lg:col-span-1">
          {o?.determined ? (
            <KV rows={[
              ['Place', <>{flag(o.country_code)} {o.place || o.country}</>],
              ['IP', o.ip ? <Mono copy>{o.ip}</Mono> : '—'],
              ['Host', o.hostname || '—'],
              ['ASN / ISP', <>{o.asn} · {o.isp}</>],
              ['Precision', o.precision],
              ['Confidence', pct(o.confidence)],
              ['Hop', o.hop_index !== undefined ? `#${o.hop_index} of chain` : '—'],
            ]} />
          ) : <Empty title="Origin not conclusively determined"
            hint={asList(o?.indicators).join('; ')} />}
          {asList(o?.indicators).length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {asList(o?.indicators).map((ind, i) => (
                <Chip key={i} tone="high" className="max-w-full whitespace-normal break-words">
                  {ind}
                </Chip>
              ))}
            </div>
          )}
          <div className="mt-2"><Prov source={o?.geo_source ?? 'computed'} /></div>
        </Panel>

        <Panel title="Relay trace map" subtitle="Reconstructed Received chain" icon={<Globe2 size={16} />}
          className="lg:col-span-2" pad>
          <RelayMap layout={map ?? undefined} />
        </Panel>
      </div>

      <Panel title="Relay hops" subtitle="Earliest (bottom) to delivery (top)" icon={<ListTree size={16} />} pad={false}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-faint border-b border-line">
              <th className="px-4 py-2">#</th><th className="px-4 py-2">IP / host</th>
              <th className="px-4 py-2 hidden md:table-cell">Location</th>
              <th className="px-4 py-2 hidden lg:table-cell">ASN</th>
              <th className="px-4 py-2">Flags</th>
            </tr></thead>
            <tbody>
              {c.relay_hops.map((h) => (
                <tr key={h.index} className="border-b border-line last:border-0">
                  <td className="px-4 py-2 text-faint">{h.index}</td>
                  <td className="px-4 py-2"><Mono>{h.ip || '—'}</Mono>
                    {h.hostname && <div className="text-xs text-faint truncate max-w-[16rem]">{h.hostname}</div>}</td>
                  <td className="px-4 py-2 hidden md:table-cell text-xs">
                    {h.location?.resolved ? <>{flag(h.location.country_code)} {h.location.city || h.location.country}</>
                      : h.is_private ? <span className="text-faint">private</span> : <span className="text-faint">unresolved</span>}</td>
                  <td className="px-4 py-2 hidden lg:table-cell text-xs text-dim">{h.location?.asn || '—'}</td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {h.is_anomalous && <Chip tone="high">anomaly</Chip>}
                      {h.location?.tor && <Chip tone="critical">TOR</Chip>}
                      {h.location?.proxy && <Chip tone="high">proxy</Chip>}
                      {h.location?.vpn && <Chip tone="high">VPN</Chip>}
                      {h.location?.hosting && <Chip tone="medium">hosting</Chip>}
                    </div>
                    {h.anomaly_reasons && h.anomaly_reasons.length > 0 &&
                      <div className="text-[11px] text-faint mt-1">{h.anomaly_reasons.join('; ')}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function EvidenceTab({ bundle }: { bundle: CaseBundle }) {
  const sigs = [...bundle.case.signals].sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0));
  const byCat = useMemo(() => {
    const m: Record<string, typeof sigs> = {};
    for (const s of sigs) (m[s.category] ??= []).push(s);
    return m;
  }, [bundle]);
  return (
    <div className="space-y-5">
      <div className="grid md:grid-cols-2 gap-5">
        {Object.entries(byCat).map(([cat, list]) => (
          <Panel key={cat} title={cat} subtitle={`${list.length} signal${list.length === 1 ? '' : 's'}`}
            icon={<Radar size={16} />}>
            <div className="space-y-2.5">
              {list.map((s) => (
                <div key={s.id} className="row-hair pb-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium">{s.title}</span>
                    <div className="flex items-center gap-1.5">
                      <span className={sevChip(s.severity)}>{s.severity}</span>
                      <span className="text-xs text-faint tabular-nums">{s.weight > 0 ? '+' : ''}{s.weight.toFixed(1)}</span>
                    </div>
                  </div>
                  {s.result && <p className="text-xs text-dim mt-0.5">{s.result}</p>}
                  {s.evidence && <p className="text-[11px] text-faint mt-0.5 break-hash">{s.evidence}</p>}
                  {s.mitre_technique && (
                    <span className="text-[10px] text-accent mt-1 inline-block">{s.mitre_technique} {s.mitre_technique_name}</span>
                  )}
                </div>
              ))}
            </div>
          </Panel>
        ))}
      </div>

      {bundle.case.mitre?.length > 0 && (
        <Panel title="MITRE ATT&CK mapping" icon={<Network size={16} />}>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {bundle.case.mitre.map((m) => (
              <div key={m.technique} className="surface-sunk p-3">
                <div className="flex items-center justify-between">
                  <Mono>{m.technique}</Mono>
                  <span className="text-[10px] text-faint uppercase">{m.tactic}</span>
                </div>
                <div className="text-sm mt-1">{m.name}</div>
                {m.evidence && <p className="text-xs text-faint mt-1">{m.evidence}</p>}
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

function MlTab({ bundle }: { bundle: CaseBundle }) {
  const ml = bundle.case.ml;
  if (!ml?.available) {
    return <Empty icon={<TestTube2 size={36} />} title="ML model not available for this case"
      hint={asList(ml?.notes).join('; ')} />;
  }
  const feats = [...(ml.top_features ?? [])].sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  const maxAbs = Math.max(0.01, ...feats.map((f) => Math.abs(f.contribution)));
  return (
    <div className="grid lg:grid-cols-3 gap-5">
      <Panel title="Model prediction" icon={<TestTube2 size={16} />}>
        <div className="text-center py-2">
          <div className="text-4xl font-bold" style={{ color: `hsl(var(--sev-${ml.probability >= 0.5 ? 'critical' : 'low'}))` }}>
            {pct(ml.probability * 100)}</div>
          <div className="text-xs text-faint mt-1">P(phishing) · label “{ml.label}”</div>
        </div>
        <KV rows={[
          ['Model', ml.model_name || '—'],
          ['Version', ml.model_version || '—'],
          ['Threshold', ml.threshold ?? '—'],
          ['Base rate', ml.base_value !== undefined ? pct(ml.base_value * 100) : '—'],
        ]} />
        <div className="mt-2"><Prov source={ml.source ?? 'computed'} /></div>
      </Panel>

      <Panel title="Feature attribution" subtitle="Exact Shapley contributions (linear model)"
        icon={<Radar size={16} />} className="lg:col-span-2">
        <p className="text-xs text-faint mb-3">Contributions sum to the log-odds shift from the base rate — the local-accuracy identity, asserted server-side.</p>
        <div className="space-y-1.5">
          {feats.slice(0, 14).map((f, i) => {
            const pos = f.contribution >= 0;
            return (
              <div key={i} className="flex items-center gap-2 text-xs">
                <span className="w-40 truncate mono text-dim">{f.feature || f.token}</span>
                <div className="flex-1 flex items-center">
                  <div className="w-1/2 flex justify-end">
                    {!pos && <div className="h-3 rounded-l" style={{ width: `${(Math.abs(f.contribution) / maxAbs) * 100}%`, background: 'hsl(var(--sev-low))' }} />}
                  </div>
                  <div className="w-px h-4 bg-line-strong" />
                  <div className="w-1/2">
                    {pos && <div className="h-3 rounded-r" style={{ width: `${(Math.abs(f.contribution) / maxAbs) * 100}%`, background: 'hsl(var(--sev-critical))' }} />}
                  </div>
                </div>
                <span className="w-14 text-right tabular-nums text-faint">{f.contribution >= 0 ? '+' : ''}{f.contribution.toFixed(3)}</span>
              </div>
            );
          })}
        </div>
        <div className="flex justify-between text-[10px] text-faint mt-2">
          <span>← lowers risk (benign)</span><span>raises risk (phishing) →</span>
        </div>
      </Panel>
    </div>
  );
}

function AttributionTab({ caseRef, bundle, navigate }: {
  caseRef: string; bundle: CaseBundle; navigate: (r: Route) => void;
}) {
  const [graph, setGraph] = useState<GraphPayload | null>(null);
  useEffect(() => { api.caseGraph(caseRef).then(setGraph).catch(() => setGraph(null)); }, [caseRef]);
  const a = bundle.case.attribution;
  return (
    <div className="grid lg:grid-cols-3 gap-5">
      <div className="space-y-5">
        <Panel title="Attribution hypothesis" icon={<Fingerprint size={16} />} className="overflow-hidden">
          <div className="text-center py-2">
            <div className="text-lg font-bold">{actorLabel(a.actor_type)}</div>
            <Meter value={a.confidence} tone="high" />
            <div className="text-xs text-faint mt-1">{pct(a.confidence)} confidence · {a.confidence_band}</div>
          </div>
          {a.reasons?.length > 0 && (
            <ul className="space-y-1.5 text-xs mt-2 overflow-hidden">
              {a.reasons.map((r, i) => (
                <li key={i} className="flex items-start gap-1.5 break-words">
                  <span className="text-accent shrink-0">›</span>
                  <span className="break-all">{r}</span>
                </li>
              ))}
            </ul>
          )}
          {a.notes && <p className="text-[11px] text-faint mt-2 italic break-words">{a.notes}</p>}
          <div className="mt-2"><Prov source={a.source ?? 'computed'} /></div>
        </Panel>

        {a.alternatives?.length > 0 && (
          <Panel title="Alternative hypotheses" icon={<ShieldQuestion size={16} />} className="overflow-hidden">
            <div className="space-y-2">
              {a.alternatives.map((alt, i) => (
                <div key={i} className="text-xs row-hair pb-2">
                  <div className="flex justify-between"><span>{actorLabel(alt.actor_type)}</span>
                    <span className="text-faint tabular-nums">{pct(alt.confidence)}</span></div>
                  {alt.why && <p className="text-faint mt-0.5 break-words">{alt.why}</p>}
                </div>
              ))}
            </div>
          </Panel>
        )}

        {a.related_case_ids && a.related_case_ids.length > 0 && (
          <Panel title="Correlated cases" icon={<Link2 size={16} />} className="overflow-hidden">
            <div className="space-y-1">
              {a.related_case_ids.slice(0, 8).map((id) => (
                <button key={id} onClick={() => navigate({ name: 'case', ref: id })}
                  className="block text-xs text-accent hover:underline truncate max-w-full text-left">{id}</button>
              ))}
            </div>
            {a.shared_indicators && a.shared_indicators.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5 overflow-hidden">
                {a.shared_indicators.slice(0, 10).map((s, i) => (
                  <Chip key={i} tone="info" className="max-w-full break-all whitespace-normal">
                    {s}
                  </Chip>
                ))}
              </div>
            )}
          </Panel>
        )}
      </div>

      <Panel title="Identity-correlation graph" subtitle="Shared senders, domains, IPs, ASNs"
        icon={<Network size={16} />} className="lg:col-span-2" pad>
        <GraphView graph={graph ?? undefined} />
      </Panel>
    </div>
  );
}

function IntelTab({ caseRef, bundle }: { caseRef: string; bundle: CaseBundle }) {
  const [takedown, setTakedown] = useState<TakedownDraft | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const c = bundle.case;

  const loadTakedown = () => {
    setLoading(true);
    api.caseTakedown(caseRef)
      .then((res) => { setTakedown(res); })
      .catch(() => setTakedown(null))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadTakedown();
  }, [caseRef]);

  const copyDraft = () => {
    if (!takedown?.body) return;
    navigator.clipboard.writeText(takedown.body);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="grid lg:grid-cols-2 gap-5">
      <Panel title="Threat intelligence" subtitle="Reputation lookups (cached)" icon={<Globe2 size={16} />}>
        {c.intel?.length ? (
          <div className="space-y-2.5">
            {c.intel.map((it, i) => (
              <div key={i} className="row-hair pb-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{it.provider}</span>
                  <div className="flex items-center gap-1.5">
                    {it.cached && <span className="chip chip-info">cached</span>}
                    <Prov source={it.source} />
                  </div>
                </div>
                <div className="text-xs text-dim">{it.subject}</div>
                {it.summary && <div className="text-xs mt-0.5">{it.summary}</div>}
                {it.error && <div className="text-xs text-medium">{it.error}</div>}
              </div>
            ))}
          </div>
        ) : <Empty title="No intel lookups recorded" />}
      </Panel>

      <Panel title="Link detonation" subtitle="Disposable headless sandbox" icon={<TestTube2 size={16} />}>
        {c.sandbox?.length ? (
          <div className="space-y-3">
            {c.sandbox.map((s, i) => (
              <div key={i} className="surface-sunk p-3">
                <Mono className="break-hash">{s.url}</Mono>
                <div className="flex items-center gap-2 mt-1.5">
                  {s.verdict && <span className={riskChip(s.verdict === 'malicious' ? 'critical' : 'low')}>{s.verdict}</span>}
                  {s.has_password_field && <Chip tone="critical">credential form</Chip>}
                  {s.detected_brand && <Chip tone="high">impersonates {s.detected_brand}</Chip>}
                  <Prov source={s.source} />
                </div>
                {s.page_title && <div className="text-xs text-faint mt-1">“{s.page_title}”</div>}
                {s.redirect_chain && s.redirect_chain.length > 0 && (
                  <div className="text-[11px] text-faint mt-1">redirects: {s.redirect_chain.length}</div>
                )}
              </div>
            ))}
          </div>
        ) : <Empty title="No links detonated"
          hint="Detonation is off by default; enable it in settings, then reinvestigate." />}
      </Panel>

      <Panel title="Takedown / abuse notice" subtitle="Draft only — RFC 2142 / DMCA / Registrar abuse letter" icon={<FileText size={16} />}
        className="lg:col-span-2"
        right={
          <div className="flex items-center gap-2">
            {takedown?.body && (
              <Button size="sm" variant="ghost" onClick={copyDraft}>
                {copied ? '✓ Copied' : 'Copy Notice'}
              </Button>
            )}
            <Button size="sm" variant="ghost" onClick={loadTakedown} disabled={loading}>
              {loading ? 'Generating…' : 'Regenerate'}
            </Button>
          </div>
        }>
        {loading ? (
          <Skeleton lines={4} />
        ) : takedown ? (
          <div className="space-y-2">
            <KV rows={[
              ['Target', takedown.target_domain],
              ['Registrar', takedown.registrar || '—'],
              ['Abuse contact', takedown.abuse_contact || '—'],
              ['Subject', takedown.subject],
            ]} />
            <pre className="surface-sunk p-3 text-xs whitespace-pre-wrap mono max-h-64 overflow-y-auto select-all">{takedown.body}</pre>
          </div>
        ) : (
          <p className="text-xs text-faint">No external domain identified to generate abuse notice.</p>
        )}
      </Panel>
    </div>
  );
}

function CustodyTab({ caseRef, bundle }: { caseRef: string; bundle: CaseBundle }) {
  const [chain, setChain] = useState<ChainPayload | null>(null);
  useEffect(() => { api.chain(caseRef).then(setChain).catch(() => setChain(null)); }, [caseRef]);
  const receipts = bundle.case.chain_receipts ?? [];
  const simulated = receipts.some((r) => r.simulated);
  const trail = bundle.case.trail ?? [];
  return (
    <div className="space-y-5">
      <Panel title="Chain of custody" subtitle="Evidence anchored on the custody contract" icon={<Link2 size={16} />}
        right={
          <div className="flex items-center gap-2">
            <a href={api.reportUrl(caseRef)} target="_blank" rel="noreferrer" download>
              <Button variant="primary" size="sm">
                <FileDown size={14} /> Download Section 65B Certificate
              </Button>
            </a>
            {simulated
              ? <Chip tone="medium">simulated (no chain configured)</Chip>
              : <Chip tone="low">on-chain</Chip>}
          </div>
        }>
        {chain?.local && (!chain.local.verified && !chain.local.ok) ? (
          <div className="mb-4 p-3 rounded-lg border border-red-500/50 bg-red-500/10 text-xs space-y-1">
            <div className="flex items-center gap-2 font-semibold text-red-400">
              <ShieldAlert size={16} />
              <span>⚠️ Cryptographic Chain Broken at Entry #{chain.local.broken_at ?? 0}</span>
            </div>
            <div className="text-white/80">
              {chain.local.reason || 'Cryptographic integrity mismatch detected: Entry does not link to predecessor.'}
            </div>
          </div>
        ) : chain?.local ? (
          <div className="mb-3 flex items-center gap-2 text-sm">
            <CheckCircle2 size={16} className="text-low" />
            <span className="text-dim">Local hash-chain verified · {chain.local.entries ?? 0} entries intact</span>
          </div>
        ) : null}
        {receipts.length === 0 ? <Empty title="No custody receipts yet" /> : (
          <div className="space-y-2">
            {receipts.map((r, i) => {
              const isBroken = Boolean(chain?.local && !chain.local.verified && !chain.local.ok && chain.local.broken_at === i);
              return (
                <div key={i} className={isBroken
                  ? "p-3 text-xs rounded border-2 border-red-500 bg-red-500/10 shadow-[0_0_15px_rgba(239,68,68,0.2)]"
                  : "surface-sunk p-3 text-xs"}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{r.action || r.kind}</span>
                      {isBroken && <Chip tone="critical">❌ BROKEN LINK HERE</Chip>}
                    </div>
                    <span className="text-faint">{fmtTime(r.written_at)}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <span className="text-faint">tx</span>
                    <Mono copy className="flex-1 truncate">{r.tx_hash}</Mono>
                    {r.explorer_url && <a href={r.explorer_url} target="_blank" rel="noreferrer" className="text-accent">explorer ↗</a>}
                  </div>
                  <div className="mt-0.5 flex items-center gap-2">
                    <span className="text-faint">hash</span><Mono className="truncate">{r.payload_hash}</Mono>
                  </div>
                  {r.block_number != null && <div className="text-faint mt-0.5">block {r.block_number} · gas {r.gas_used ?? '—'}</div>}
                </div>
              );
            })}
          </div>
        )}
        {simulated && (
          <p className="text-[11px] text-faint mt-3">
            No RPC/contract configured, so receipts are simulated deterministically. Deploy the
            MailCustody contract and set the RPC to anchor real transactions — the payload hashes are identical either way.
          </p>
        )}
      </Panel>

      <Panel title="Investigation timeline" subtitle="Every agent step, hash-chained" icon={<ListTree size={16} />}>
        <div className="space-y-4">
          {trail.map((step) => (
            <div key={step.index} className="flex gap-4" style={{ alignItems: 'flex-start' }}>
              {/* Dot — fixed width column */}
              <div className="flex-none" style={{ width: 12 }}>
                <span
                  className="block rounded-full"
                  style={{
                    width: 10,
                    height: 10,
                    marginTop: 5,
                    background: step.status === 'ok' ? 'hsl(var(--sev-low))' : 'hsl(var(--sev-medium))',
                    border: '2px solid hsl(var(--panel))',
                    boxShadow: `0 0 6px ${step.status === 'ok' ? 'hsl(152 62% 46% / 0.4)' : 'hsl(42 94% 56% / 0.4)'}`,
                  }}
                />
              </div>
              {/* Text content */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold">{step.action}</span>
                  <span className="text-[11px] text-faint flex-none">{step.duration_ms != null ? `${step.duration_ms}ms` : ''}</span>
                </div>
                {step.result && <p className="text-xs text-dim mt-0.5">{step.result}</p>}
                {step.reasoning && <p className="text-[11px] text-faint italic mt-0.5">{step.reasoning}</p>}
                {step.tx_hash && <Mono className="text-[10px] text-faint mt-0.5">{step.tx_hash.slice(0, 22)}…</Mono>}
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function RawTab({ bundle }: { bundle: CaseBundle }) {
  const pe = bundle.case.parsed_email;
  const [show, setShow] = useState<'headers' | 'text' | 'html' | 'received'>('headers');
  const content = show === 'headers'
    ? Object.entries(pe.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n')
    : show === 'received' ? (pe.received_chain ?? []).join('\n\n')
    : show === 'text' ? (pe.body_text ?? '')
    : (pe.body_html ?? '');
  return (
    <Panel title="Raw message" subtitle="As received — masked per privacy policy" icon={<ScrollText size={16} />}
      right={
        <div className="flex gap-1">
          {(['headers', 'received', 'text', 'html'] as const).map((k) => (
            <button key={k} onClick={() => setShow(k)}
              className={`btn btn-sm ${show === k ? 'btn-primary' : ''}`}>{k}</button>
          ))}
        </div>
      }>
      <div className="mb-2 flex items-center gap-3 text-xs text-faint">
        <span>sha256 <Mono copy>{pe.raw_sha256 ? `${pe.raw_sha256.slice(0, 24)}…` : '—'}</Mono></span>
        <span>{bytes(pe.size_bytes)}</span>
        {bundle.masked && <Chip tone="info">PII masked</Chip>}
      </div>
      {content ? (
        <pre className="surface-sunk p-3 text-xs whitespace-pre-wrap mono max-h-[32rem] overflow-y-auto break-hash">{content}</pre>
      ) : <Empty title={`No ${show} content`} />}
    </Panel>
  );
}
