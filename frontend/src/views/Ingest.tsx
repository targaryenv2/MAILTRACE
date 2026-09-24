/**
 * Ingest — submit a mail for analysis.
 *
 * Three ways in: drop/pick an .eml file, paste raw headers+body, or seed the
 * bundled demo corpus. All three post to the live backend; there is no offline
 * ingest, because a case that was never actually scored cannot be shown as if it
 * were (see api.ts). While a submission runs, the live feed on the right shows
 * the agent's real steps, so the wait is the demo.
 */

import { useCallback, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { FileUp, Play, Sparkles, UploadCloud } from 'lucide-react';
import { api, ApiError, currentMode } from '../lib/api';
import type { CaseBundle, LiveEvent } from '../lib/types';
import type { Route } from '../components/Shell';
import { Button, Card, Panel } from '../components/ui';
import { truncateMiddle } from '../lib/format';

export function Ingest({ navigate, events, toast }: {
  navigate: (r: Route) => void; events: LiveEvent[];
  toast: (m: string, tone?: 'info' | 'critical' | 'low') => void;
}) {
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState<string>('');
  const [raw, setRaw] = useState('');
  const [error, setError] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);
  const offline = currentMode() === 'demo';

  const run = useCallback(async (fn: () => Promise<CaseBundle & { count?: number }>, label: string) => {
    setError('');
    setBusy(label);
    try {
      const res = await fn() as any;
      const ref = res?.case?.case_number ?? res?.summary?.case_number ?? (res?.cases && res.cases[0]?.case_number);
      if (ref) {
        toast(`Case ${ref} analysed`, 'low');
        setTimeout(() => navigate({ name: 'case', ref }), 900);
      } else if (res?.count) {
        toast(`Seeded ${res.count} demo cases`, 'low');
        setTimeout(() => navigate({ name: 'queue' }), 900);
      }
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : 'Submission failed';
      setError(msg);
      toast(msg, 'critical');
    } finally {
      setBusy('');
    }
  }, [navigate, toast]);

  const submitFile = (file: File) =>
    run(() => { const fd = new FormData(); fd.append('file', file, file.name); return api.ingestBytes(fd); },
      'file');

  const submitRaw = () => {
    if (!raw.trim()) return;
    const blob = new File([raw], 'pasted.eml', { type: 'message/rfc822' });
    void submitFile(blob);
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Analyse a mail</h1>
        <p className="text-sm text-dim">Submit a suspect message; the agent parses, scores, traces and anchors it.</p>
      </div>

      {offline && (
        <Card className="p-3 text-sm" glass>
          <span className="chip chip-medium mr-2">offline demo</span>
          Ingestion needs the live backend. Start it with <code className="mono">python mailtrace.py serve</code>,
          then turn off offline demo mode in settings. You can still browse the seeded cases in the queue.
        </Card>
      )}

      <div className="grid lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 space-y-5">
          {/* drop zone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault(); setDragging(false);
              const f = e.dataTransfer.files?.[0];
              if (f) void submitFile(f);
            }}
            onClick={() => fileRef.current?.click()}
            className="surface lift cursor-pointer grid place-items-center py-16 px-6 text-center transition-colors"
            style={dragging ? { borderColor: 'var(--accent)', background: 'var(--accent-soft)' } : {}}>
            <input ref={fileRef} type="file" accept=".eml,.txt,message/rfc822" className="hidden"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) void submitFile(f); }} />
            <motion.div animate={busy === 'file' ? { y: [0, -6, 0] } : {}}
              transition={{ repeat: Infinity, duration: 1.2 }}>
              <UploadCloud size={40} className="text-accent mx-auto mb-3" />
            </motion.div>
            <p className="font-medium">{busy === 'file' ? 'Analysing…' : 'Drop an .eml here, or click to browse'}</p>
            <p className="text-xs text-faint mt-1">Raw RFC 822 message. Treated as hostile — links are never opened without detonation enabled.</p>
          </div>

          {/* paste */}
          <Panel title="…or paste raw headers + body" icon={<FileUp size={16} />}
            right={<Button size="sm" variant="primary" disabled={!raw.trim() || !!busy || offline}
              onClick={submitRaw}><Play size={13} /> Analyse</Button>}>
            <textarea value={raw} onChange={(e) => setRaw(e.target.value)}
              placeholder={'Return-Path: <...>\nReceived: from ...\nFrom: "CEO" <ceo@...>\nSubject: Urgent wire request\n\n<body>'}
              className="field font-mono text-xs h-44 resize-y" spellCheck={false} />
          </Panel>

          {error && <Card className="p-3 text-sm border-critical/50" style={{ borderColor: 'hsl(var(--sev-critical) / 0.5)' }}>
            <span className="text-critical">{error}</span></Card>}
        </div>

        <div className="space-y-5">
          <Panel title="Try it instantly" icon={<Sparkles size={16} />}>
            <p className="text-xs text-dim mb-3">Seed a realistic corpus — a BEC wire-fraud wave, brand impersonation,
              AI-written phishing and clean mail — to explore every feature end to end.</p>
            <Button variant="primary" className="w-full" disabled={!!busy || offline}
              onClick={() => run(() => api.ingestDemo(), 'demo')}>
              {busy === 'demo' ? 'Seeding…' : 'Seed demo corpus'}
            </Button>
          </Panel>

          <Panel title="Agent activity" subtitle="Live, as it works"
            icon={<span className="relative flex h-2.5 w-2.5">
              <span className="absolute inline-flex h-full w-full rounded-full bg-accent opacity-60 animate-ping" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-accent" /></span>}>
            {events.length === 0 ? (
              <p className="text-xs text-faint py-4 text-center">Submit a mail or seed the demo corpus to watch the investigation stream.</p>
            ) : (
              <div className="space-y-2 max-h-80 overflow-y-auto no-scrollbar timeline pr-1">
                {[...events].reverse().slice(0, 16).map((e) => (
                  <div key={e.seq} className="relative text-xs flex items-start gap-2 bg-[#121217] p-2 rounded border border-white/5">
                    <span className="text-[10px] text-accent font-mono">#{e.seq}</span>
                    <div className="min-w-0 flex-1">
                      <div className="font-medium text-white/90 capitalize">{String(e.data.action ?? e.kind).replace(/_/g, ' ')}</div>
                      {e.data.result ? <div className="text-[11px] text-faint mt-0.5 break-words">{String(e.data.result)}</div> : null}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
