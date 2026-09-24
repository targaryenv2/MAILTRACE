/**
 * Case queue — the triage list.
 *
 * A projection of `/api/cases` with the filters the endpoint actually supports
 * (verdict, threat class, minimum risk, campaign) plus sort. Filtering is done
 * server-side when live and client-side against the snapshot when offline, but
 * the control surface is identical either way. Rows are the primary navigation
 * into the investigator.
 */

import { useEffect, useState } from 'react';
import { Filter, SortDesc, Trash2 } from 'lucide-react';
import { api } from '../lib/api';
import type { CaseSummary, QueuePage } from '../lib/types';
import type { Route } from '../components/Shell';
import { usePrefs } from '../lib/theme';
import { Button, Chip, Empty, Panel, Skeleton } from '../components/ui';
import { riskChip, slaText, threatLabel, verdictLabel } from '../lib/format';

const VERDICTS = ['', 'phishing', 'suspicious', 'indeterminate', 'benign'];
const CLASSES = ['', 'phishing', 'fraud', 'impersonated', 'suspicious', 'legitimate'];
const SORTS = [['risk', 'Risk'], ['created', 'Newest'], ['updated', 'Updated']];

export function Queue({ navigate, campaignFilter, toast }: {
  navigate: (r: Route) => void; campaignFilter?: string;
  toast?: (m: string, tone?: 'info' | 'critical' | 'low') => void;
}) {
  const { prefs } = usePrefs();
  const [page, setPage] = useState<QueuePage | null>(null);
  const [verdict, setVerdict] = useState('');
  const [threat, setThreat] = useState('');
  const [minRisk, setMinRisk] = useState(0);
  const [sort, setSort] = useState('risk');
  const [offset, setOffset] = useState(0);
  const [clearing, setClearing] = useState(false);

  const fetchCases = () => {
    setPage(null);
    api.cases({
      verdict: verdict || undefined, threat_class: threat || undefined,
      min_risk: minRisk || undefined, campaign_id: campaignFilter || undefined,
      sort, limit: prefs.pageSize, offset,
    }).then(setPage).catch(() => setPage({ total: 0, count: 0, offset: 0, sort, items: [] }));
  };

  useEffect(fetchCases, [verdict, threat, minRisk, sort, offset, campaignFilter, prefs.pageSize]);

  const handleClearAll = async () => {
    if (!window.confirm('Are you sure you want to clear all imported cases and evidence?')) return;
    setClearing(true);
    try {
      const res = await api.clearCases();
      toast?.(`Cleared ${res.purged} case(s) successfully`, 'low');
      fetchCases();
    } catch {
      toast?.('Failed to clear cases', 'critical');
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Case queue</h1>
          <p className="text-sm text-dim">
            {campaignFilter ? <>Campaign <code className="mono">{campaignFilter}</code> · </> : null}
            {page ? `${page.total} case${page.total === 1 ? '' : 's'}` : 'loading…'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {campaignFilter && (
            <Button size="sm" variant="ghost" onClick={() => navigate({ name: 'queue' })}>Clear campaign filter</Button>
          )}
          {Boolean(page?.total) && (
            <Button size="sm" variant="danger" onClick={handleClearAll} disabled={clearing}>
              <Trash2 size={14} /> {clearing ? 'Clearing…' : 'Clear all cases'}
            </Button>
          )}
        </div>
      </div>

      <Panel icon={<Filter size={16} />} title="Filters" pad>
        <div className="flex flex-wrap items-center gap-4">
          <label className="text-xs text-dim flex items-center gap-2">Verdict
            <select className="field text-sm py-1 w-36" value={verdict}
              onChange={(e) => { setVerdict(e.target.value); setOffset(0); }}>
              {VERDICTS.map((v) => <option key={v} value={v}>{v ? verdictLabel(v) : 'Any'}</option>)}
            </select>
          </label>
          <label className="text-xs text-dim flex items-center gap-2">Class
            <select className="field text-sm py-1 w-36" value={threat}
              onChange={(e) => { setThreat(e.target.value); setOffset(0); }}>
              {CLASSES.map((v) => <option key={v} value={v}>{v ? threatLabel(v) : 'Any'}</option>)}
            </select>
          </label>
          <label className="text-xs text-dim flex items-center gap-2 flex-1 min-w-[180px]">
            Min risk · {minRisk}
            <input type="range" className="field flex-1" min={0} max={100} step={5} value={minRisk}
              onChange={(e) => { setMinRisk(Number(e.target.value)); setOffset(0); }} />
          </label>
          <label className="text-xs text-dim flex items-center gap-2"><SortDesc size={13} />
            <select className="field text-sm py-1 w-28" value={sort} onChange={(e) => setSort(e.target.value)}>
              {SORTS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
        </div>
      </Panel>

      <Panel pad={false}>
        {!page ? <div className="p-4"><Skeleton lines={8} /></div>
          : page.items.length === 0 ? (
            <Empty title="No matching cases" hint="Loosen the filters, or analyse a new mail." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-faint border-b border-line">
                    <th className="px-4 py-2 font-medium">Risk</th>
                    <th className="px-4 py-2 font-medium">Subject / sender</th>
                    <th className="px-4 py-2 font-medium hidden md:table-cell">Class</th>
                    <th className="px-4 py-2 font-medium hidden lg:table-cell">Origin</th>
                    <th className="px-4 py-2 font-medium hidden lg:table-cell">SLA</th>
                    <th className="px-4 py-2 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((c) => <QueueRow key={c.id} c={c} navigate={navigate} />)}
                </tbody>
              </table>
            </div>
          )}
        {page && page.total > prefs.pageSize && (
          <div className="flex items-center justify-between p-3 border-t border-line text-xs text-dim">
            <span>{offset + 1}–{Math.min(offset + prefs.pageSize, page.total)} of {page.total}</span>
            <div className="flex gap-2">
              <Button size="sm" variant="ghost" disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - prefs.pageSize))}>Prev</Button>
              <Button size="sm" variant="ghost" disabled={offset + prefs.pageSize >= page.total}
                onClick={() => setOffset(offset + prefs.pageSize)}>Next</Button>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}

function QueueRow({ c, navigate }: { c: CaseSummary; navigate: (r: Route) => void }) {
  return (
    <tr onClick={() => navigate({ name: 'case', ref: c.case_number })}
        className="border-b border-line last:border-0 hover:bg-raised/40 cursor-pointer transition-colors">
      <td className="px-4 py-3">
        <span className="text-lg font-bold tabular-nums" style={{ color: `hsl(var(--sev-${c.risk_level}))` }}>
          {Math.round(c.risk_score)}</span>
      </td>
      <td className="px-4 py-3 max-w-sm">
        <div className="truncate">{c.subject || '(no subject)'}</div>
        <div className="text-xs text-faint truncate">{c.sender_address}
          {c.is_duplicate && <span className="ml-1 text-medium">· dup</span>}
          {c.is_campaign && <span className="ml-1 text-high">· campaign</span>}
        </div>
      </td>
      <td className="px-4 py-3 hidden md:table-cell">
        <span className={riskChip(c.risk_level)}>{threatLabel(c.threat_class)}</span>
      </td>
      <td className="px-4 py-3 hidden lg:table-cell text-xs text-dim">
        {c.origin_place ? <>{c.origin_place}</> : <span className="text-faint">—</span>}
      </td>
      <td className="px-4 py-3 hidden lg:table-cell text-xs">
        <span className={c.sla?.breached ? 'text-critical' : 'text-dim'}>
          {c.sla ? slaText(c.sla.remaining_seconds, c.sla.breached) : '—'}</span>
      </td>
      <td className="px-4 py-3">
        {c.action_status === 'approved' || c.status === 'approved' ? (
          <Chip tone="low">approved</Chip>
        ) : c.action_status === 'escalated' || c.status === 'escalated' ? (
          <Chip tone="critical">escalated</Chip>
        ) : c.action_status === 'overridden' || c.status === 'overridden' ? (
          <Chip tone="medium">overridden</Chip>
        ) : c.requires_human_review ? (
          <Chip tone="high">review</Chip>
        ) : (
          <span className="text-xs text-faint">{c.status}</span>
        )}
      </td>
    </tr>
  );
}
