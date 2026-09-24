/**
 * Live investigation feed.
 *
 * `useLiveEvents` connects to the SSE stream at `/api/events`. Two things make it
 * robust rather than a demo toy:
 *
 * 1. `EventSource` reconnects on its own and resumes from `Last-Event-ID`, but
 *    some proxies buffer `text/event-stream` into uselessness. So when the
 *    stream errors repeatedly we fall back to polling `/api/events/since?since=`,
 *    which returns the identical events keyed by the same monotonic `seq`. The
 *    UI cannot tell which transport delivered an event, which is the point.
 * 2. In offline demo mode there is no server to stream from, so the hook stays
 *    dormant and reports `disconnected` rather than hammering a dead endpoint.
 *
 * `seq` dedup guarantees an event is delivered once even if the stream reconnects
 * mid-flight and the poller also picks it up.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { currentMode } from './api';
import type { LiveEvent } from './types';

export type LiveStatus = 'connecting' | 'live' | 'polling' | 'disconnected';

const BASE = (import.meta.env.VITE_API_BASE ?? '').replace(/\/$/, '');

interface LiveState {
  status: LiveStatus;
  events: LiveEvent[];
  lastSeq: number;
}

export function useLiveEvents(enabled: boolean, keep = 120) {
  const [state, setState] = useState<LiveState>({
    status: 'disconnected', events: [], lastSeq: 0,
  });
  const seenRef = useRef<number>(0);
  const esRef = useRef<EventSource | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const failuresRef = useRef(0);

  const push = useCallback((batch: LiveEvent[]) => {
    if (!batch.length) return;
    setState((prev) => {
      const fresh = batch.filter((e) => e.seq > seenRef.current);
      if (!fresh.length) return prev;
      seenRef.current = Math.max(seenRef.current, ...fresh.map((e) => e.seq));
      const merged = [...prev.events, ...fresh].slice(-keep);
      return { ...prev, events: merged, lastSeq: seenRef.current };
    });
  }, [keep]);

  const stopAll = useCallback(() => {
    esRef.current?.close();
    esRef.current = null;
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  const startPolling = useCallback(() => {
    if (pollRef.current) return;
    setState((p) => ({ ...p, status: 'polling' }));
    const tick = async () => {
      try {
        const res = await fetch(`${BASE}/api/events/since?since=${seenRef.current}`);
        if (!res.ok) return;
        const body = await res.json();
        push((body.events ?? []) as LiveEvent[]);
      } catch {
        setState((p) => ({ ...p, status: 'disconnected' }));
      }
    };
    void tick();
    pollRef.current = setInterval(tick, 2500);
  }, [push]);

  const startStream = useCallback(() => {
    if (typeof EventSource === 'undefined') { startPolling(); return; }
    setState((p) => ({ ...p, status: 'connecting' }));
    let es: EventSource;
    try {
      es = new EventSource(`${BASE}/api/events?since=${seenRef.current}`);
    } catch {
      startPolling();
      return;
    }
    esRef.current = es;
    es.onopen = () => { failuresRef.current = 0; setState((p) => ({ ...p, status: 'live' })); };
    es.onmessage = (ev) => {
      try {
        push([JSON.parse(ev.data) as LiveEvent]);
      } catch { /* comment/heartbeat frame */ }
    };
    es.onerror = () => {
      failuresRef.current += 1;
      // EventSource retries on its own; only after it has failed to hold a
      // connection several times do we assume a buffering proxy and switch to
      // polling, which always gets through.
      if (failuresRef.current >= 3) {
        es.close();
        esRef.current = null;
        startPolling();
      }
    };
  }, [push, startPolling]);

  useEffect(() => {
    if (!enabled || currentMode() === 'demo') {
      stopAll();
      setState((p) => ({ ...p, status: 'disconnected' }));
      return;
    }
    startStream();
    return stopAll;
  }, [enabled, startStream, stopAll]);

  const clear = useCallback(() => setState((p) => ({ ...p, events: [] })), []);
  return { ...state, clear };
}
