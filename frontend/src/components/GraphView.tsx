/**
 * Identity-correlation graph — Interactive, zoomable, draggable SVG
 * with anti-clumping force layout and filter controls.
 */

import React, { useMemo, useState, useRef, useEffect } from 'react';
import { Empty } from './ui';
import type { GraphEdge, GraphNode, GraphPayload } from '../lib/types';

const KIND_CONFIG: Record<string, { color: string; label: string; icon: string }> = {
  case: { color: '#3b82f6', label: 'case', icon: '📁' },
  sender: { color: '#f97316', label: 'sender', icon: '✉️' },
  domain: { color: '#eab308', label: 'domain', icon: '🌐' },
  ip: { color: '#ef4444', label: 'ip', icon: '🖥️' },
  asn: { color: '#a855f7', label: 'asn', icon: '🏢' },
  url: { color: '#06b6d4', label: 'url', icon: '🔗' },
  attachment: { color: '#60a5fa', label: 'attachment', icon: '📎' },
  recipient: { color: '#10b981', label: 'recipient', icon: '👤' },
};

interface Pt {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  node: GraphNode;
}

// Deterministic pseudo-random seed
function seed(s: string): number {
  let h = 2166136261;
  const str = String(s || '');
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 10000) / 10000;
}

function computeLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  W: number,
  H: number,
  spacingMultiplier: number
): Pt[] {
  if (!nodes || !nodes.length) return [];
  const cx = W / 2;
  const cy = H / 2;

  const kindAngles: Record<string, number> = {
    case: 0,
    sender: 0.8,
    domain: 1.6,
    ip: 2.4,
    asn: 3.2,
    url: 4.0,
    attachment: 4.8,
    recipient: 5.6,
  };

  const pts: Pt[] = nodes.map((n, idx) => {
    const isFocus = n.kind === 'case' && (n.detail?.focus || n.detail?.is_focus);
    if (isFocus) {
      return { id: n.id, x: cx, y: cy, vx: 0, vy: 0, node: n };
    }
    const baseAngle = kindAngles[n.kind] ?? 0;
    const angle = baseAngle + (idx * 0.7) + (seed(n.id) - 0.5) * 0.8;
    const ringRadius = (100 + (seed(n.id + 'r') * 160)) * (0.8 + spacingMultiplier * 0.4);

    return {
      id: n.id,
      x: cx + Math.cos(angle) * ringRadius,
      y: cy + Math.sin(angle) * ringRadius,
      vx: 0,
      vy: 0,
      node: n,
    };
  });

  const index = new Map(pts.map((p, i) => [p.id, i]));
  const focus = pts.find((p) => p.node.kind === 'case' && (p.node.detail?.focus || p.node.detail?.is_focus));

  const k = Math.sqrt((W * H) / Math.max(1, pts.length)) * 0.8 * spacingMultiplier;
  const iterations = 160;

  for (let iter = 0; iter < iterations; iter++) {
    const disp = pts.map(() => ({ x: 0, y: 0 }));

    // 1. Repulsion
    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        let dx = pts[i].x - pts[j].x;
        let dy = pts[i].y - pts[j].y;
        const d = Math.hypot(dx, dy) || 0.1;
        const rep = (k * k * 1.5) / d;
        dx = (dx / d) * rep;
        dy = (dy / d) * rep;
        disp[i].x += dx;
        disp[i].y += dy;
        disp[j].x -= dx;
        disp[j].y -= dy;
      }
    }

    // 2. Attraction along edges
    if (edges && edges.length) {
      for (const e of edges) {
        const a = index.get(e.source);
        const b = index.get(e.target);
        if (a === undefined || b === undefined) continue;
        const dx = pts[a].x - pts[b].x;
        const dy = pts[a].y - pts[b].y;
        const d = Math.hypot(dx, dy) || 0.1;
        const targetLen = 80 * spacingMultiplier;
        const att = Math.max(0, d - targetLen) * 0.08;
        const fx = (dx / d) * att;
        const fy = (dy / d) * att;
        disp[a].x -= fx;
        disp[a].y -= fy;
        disp[b].x += fx;
        disp[b].y += fy;
      }
    }

    // 3. Central gravity
    pts.forEach((p, i) => {
      if (p === focus) return;
      const dx = cx - p.x;
      const dy = cy - p.y;
      disp[i].x += dx * 0.02;
      disp[i].y += dy * 0.02;
    });

    // 4. Position update
    const temp = (1 - iter / iterations) * (W * 0.07);
    for (let i = 0; i < pts.length; i++) {
      if (pts[i] === focus) continue;
      const d = Math.hypot(disp[i].x, disp[i].y) || 0.1;
      pts[i].x += (disp[i].x / d) * Math.min(d, temp);
      pts[i].y += (disp[i].y / d) * Math.min(d, temp);
    }
  }

  return pts;
}

export function GraphView({ graph, height = 480 }: { graph?: GraphPayload; height?: number }) {
  const W = 900;
  const H = 540;

  // ALL HOOKS UNCONDITIONALLY AT THE TOP
  const [scale, setScale] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const [draggedNodeId, setDraggedNodeId] = useState<string | null>(null);
  const [nodePositions, setNodePositions] = useState<Map<string, { x: number; y: number }>>(new Map());

  const [spacing, setSpacing] = useState(1.6);
  const [search, setSearch] = useState('');
  const [hover, setHover] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [showLabels, setShowLabels] = useState(true);
  const [activeKinds, setActiveKinds] = useState<Record<string, boolean>>({
    case: true,
    sender: true,
    domain: true,
    ip: true,
    asn: true,
    url: true,
    attachment: true,
    recipient: true,
  });

  const svgRef = useRef<SVGSVGElement>(null);

  // Compute base layout
  const basePts = useMemo(() => {
    if (!graph?.nodes || !Array.isArray(graph.nodes) || graph.nodes.length === 0) return [];
    const sorted = [...graph.nodes].sort((a, b) => (b.weight ?? 1) - (a.weight ?? 1));
    const kept = sorted.slice(0, 64);
    const keptIds = new Set(kept.map((n) => n.id));
    const edges = (graph.edges ?? []).filter((e) => keptIds.has(e.source) && keptIds.has(e.target));
    return computeLayout(kept, edges, W, H, spacing);
  }, [graph?.nodes, graph?.edges, spacing]);

  // Sync positions map
  useEffect(() => {
    const posMap = new Map<string, { x: number; y: number }>();
    basePts.forEach((p) => {
      posMap.set(p.id, { x: p.x, y: p.y });
    });
    setNodePositions(posMap);
  }, [basePts]);

  // Filtered nodes
  const filteredPts = useMemo(() => {
    return basePts.filter((p) => {
      const kind = p.node?.kind || 'case';
      if (activeKinds[kind] === false) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchLabel = String(p.node?.label || '').toLowerCase().includes(q);
        const matchId = String(p.node?.id || '').toLowerCase().includes(q);
        const matchKind = String(p.node?.kind || '').toLowerCase().includes(q);
        return matchLabel || matchId || matchKind;
      }
      return true;
    });
  }, [basePts, activeKinds, search]);

  const visibleIds = useMemo(() => new Set(filteredPts.map((p) => p.id)), [filteredPts]);

  const edges = useMemo(() => {
    if (!graph?.edges || !Array.isArray(graph.edges)) return [];
    return graph.edges.filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target));
  }, [graph?.edges, visibleIds]);

  // Connected nodes map for highlighting
  const connectedIds = useMemo(() => {
    const target = hover || selectedNode?.id;
    if (!target) return null;
    const set = new Set<string>([target]);
    edges.forEach((e) => {
      if (e.source === target) set.add(e.target);
      if (e.target === target) set.add(e.source);
    });
    return set;
  }, [hover, selectedNode, edges]);

  const canvasContainerRef = useRef<HTMLDivElement>(null);

  // Non-passive wheel event listener to fully prevent window/page scrolling & shaking
  useEffect(() => {
    const el = canvasContainerRef.current;
    if (!el) return;

    const onWheelNative = (e: WheelEvent) => {
      e.preventDefault();
      e.stopPropagation();

      const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
      const rect = svgRef.current?.getBoundingClientRect();
      if (!rect) return;

      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      setScale((prevScale) => {
        const nextScale = Math.min(Math.max(prevScale * zoomFactor, 0.2), 20.0);
        const scaleRatio = nextScale / prevScale;

        setPan((prevPan) => ({
          x: mouseX - (mouseX - prevPan.x) * scaleRatio,
          y: mouseY - (mouseY - prevPan.y) * scaleRatio,
        }));

        return nextScale;
      });
    };

    el.addEventListener('wheel', onWheelNative, { passive: false });
    return () => {
      el.removeEventListener('wheel', onWheelNative);
    };
  }, []);

  // Drag-to-pan & node dragging
  const handleMouseDown = (e: React.MouseEvent) => {
    if (draggedNodeId) return;
    setIsPanning(true);
    setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (draggedNodeId) {
      const rect = svgRef.current?.getBoundingClientRect();
      if (!rect) return;
      const rawX = e.clientX - rect.left;
      const rawY = e.clientY - rect.top;
      const canvasX = (rawX - pan.x) / scale;
      const canvasY = (rawY - pan.y) / scale;

      setNodePositions((prev) => {
        const next = new Map(prev);
        next.set(draggedNodeId, { x: canvasX, y: canvasY });
        return next;
      });
    } else if (isPanning) {
      setPan({
        x: e.clientX - panStart.x,
        y: e.clientY - panStart.y,
      });
    }
  };

  const handleMouseUp = () => {
    setIsPanning(false);
    setDraggedNodeId(null);
  };

  const toggleKind = (kind: string) => {
    setActiveKinds((prev) => ({ ...prev, [kind]: !prev[kind] }));
  };

  const zoomIn = () => setScale((s) => Math.min(s * 1.3, 20.0));
  const zoomOut = () => setScale((s) => Math.max(s * 0.75, 0.2));
  const resetView = () => {
    setScale(1);
    setPan({ x: 0, y: 0 });
    setSpacing(1.6);
  };

  // Empty state check (SAFE NOW: ALL HOOKS EXECUTED)
  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    return (
      <Empty
        title="No correlation graph"
        hint={graph?.note || 'This case shares no indicators with any other case yet.'}
      />
    );
  }

  return (
    <div className="surface-sunk relative rounded-2xl border border-white/8 overflow-hidden flex flex-col select-none">
      {/* Top Toolbar */}
      <div className="p-3 bg-[#111116] border-b border-white/8 flex flex-wrap items-center justify-between gap-2 z-10">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs uppercase font-bold text-brand flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-brand animate-pulse" />
            Identity-Correlation Graph
          </span>
          <span className="text-[11px] font-mono text-white/40">
            ({filteredPts.length} of {graph.nodes.length} nodes)
          </span>
        </div>

        {/* Search Input */}
        <div className="relative">
          <input
            type="text"
            placeholder="Search node, IP, domain..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-[#181820] text-xs font-mono text-white px-3 py-1.5 pl-7 rounded-lg border border-white/10 focus:border-brand focus:outline-none w-48 transition-all"
          />
          <span className="absolute left-2.5 top-1.5 text-white/30 text-xs">🔍</span>
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-2 top-1 text-white/40 hover:text-white text-xs"
            >
              ✕
            </button>
          )}
        </div>

        {/* Zoom & Spacing Controls */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 bg-[#181820] px-2.5 py-1 rounded-lg border border-white/8">
            <span className="text-[10px] font-mono text-white/40 uppercase">Spread:</span>
            <input
              type="range"
              min="0.8"
              max="3.5"
              step="0.2"
              value={spacing}
              onChange={(e) => setSpacing(parseFloat(e.target.value))}
              className="w-16 h-1 bg-white/10 rounded appearance-none cursor-pointer accent-brand"
              title="Expand graph spacing to declutter clumps"
            />
            <span className="text-[10px] font-mono text-brand font-bold">{spacing.toFixed(1)}x</span>
          </div>

          <button
            onClick={zoomIn}
            className="p-1.5 px-2 bg-[#181820] hover:bg-brand/20 hover:text-brand text-white/70 rounded-lg border border-white/8 text-xs font-mono transition-colors"
            title="Zoom In (Max 20x)"
          >
            ➕
          </button>
          <button
            onClick={zoomOut}
            className="p-1.5 px-2 bg-[#181820] hover:bg-brand/20 hover:text-brand text-white/70 rounded-lg border border-white/8 text-xs font-mono transition-colors"
            title="Zoom Out"
          >
            ➖
          </button>
          <button
            onClick={resetView}
            className="px-2.5 py-1 bg-[#181820] hover:bg-white/10 text-white/70 rounded-lg border border-white/8 text-xs font-mono transition-colors"
            title="Reset Zoom & Pan"
          >
            Reset ({(scale * 100).toFixed(0)}%)
          </button>
          <button
            onClick={() => setShowLabels(!showLabels)}
            className={`px-2 py-1 rounded-lg border text-xs font-mono transition-colors ${
              showLabels
                ? 'bg-brand/10 border-brand/40 text-brand font-bold'
                : 'bg-[#181820] border-white/8 text-white/40'
            }`}
            title="Toggle Labels"
          >
            Labels: {showLabels ? 'ON' : 'OFF'}
          </button>
        </div>
      </div>

      {/* SVG Canvas Area */}
      <div
        ref={canvasContainerRef}
        className="relative flex-1 cursor-grab active:cursor-grabbing overflow-hidden bg-[#0a0a0f]"
        style={{ height, touchAction: 'none', overscrollBehavior: 'contain' }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          width="100%"
          height="100%"
          className="w-full h-full block"
        >
          <defs>
            <pattern id="graph-grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="1" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#graph-grid)" />

          <g transform={`translate(${pan.x}, ${pan.y}) scale(${scale})`}>
            {/* Edges */}
            {edges.map((e, i) => {
              const a = nodePositions.get(e.source);
              const b = nodePositions.get(e.target);
              if (!a || !b) return null;

              const isHighlighted = connectedIds
                ? connectedIds.has(e.source) && connectedIds.has(e.target)
                : false;

              return (
                <line
                  key={i}
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke={
                    isHighlighted
                      ? 'var(--accent, #3b82f6)'
                      : connectedIds
                      ? 'rgba(255,255,255,0.04)'
                      : 'hsl(var(--line-strong, 220 13% 18%) / 0.7)'
                  }
                  strokeWidth={isHighlighted ? 2.2 / Math.sqrt(scale) : 1.0 / Math.sqrt(scale)}
                  strokeOpacity={isHighlighted ? 0.9 : 0.4}
                />
              );
            })}

            {/* Nodes */}
            {filteredPts.map((p) => {
              const pos = nodePositions.get(p.id) || { x: p.x, y: p.y };
              const isFocus = p.node?.kind === 'case' && (p.node?.detail?.focus || p.node?.detail?.is_focus);
              const isSelected = selectedNode?.id === p.id;
              const isHovered = hover === p.id;
              const isDimmed = connectedIds && !connectedIds.has(p.id);

              const r = isFocus ? 12 : 5 + Math.min(7, p.node?.weight ?? 1);
              const cfg = KIND_CONFIG[p.node?.kind] || KIND_CONFIG.case;
              const color = cfg.color;
              const nodeText = String(p.node?.label || p.node?.id || '');

              return (
                <g
                  key={p.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onMouseEnter={() => setHover(p.id)}
                  onMouseLeave={() => setHover(null)}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNode(isSelected ? null : p.node);
                  }}
                  onMouseDown={(e) => {
                    e.stopPropagation();
                    setDraggedNodeId(p.id);
                  }}
                  style={{ cursor: 'pointer' }}
                >
                  {(isSelected || isHovered) && (
                    <circle
                      r={r + 6 / Math.sqrt(scale)}
                      fill={color}
                      fillOpacity={0.25}
                      stroke={color}
                      strokeWidth={1.5 / Math.sqrt(scale)}
                    />
                  )}

                  <circle
                    r={r}
                    fill={isDimmed ? '#222' : color}
                    stroke="hsl(var(--bg, 220 15% 8%))"
                    strokeWidth={isFocus ? 2.5 : 1.5}
                    opacity={isDimmed ? 0.3 : 1}
                  />

                  {(showLabels || isFocus || isHovered || isSelected || scale > 1.2) && (
                    <g transform={`translate(${r + 4}, 0)`}>
                      <rect
                        x="-2"
                        y="-7"
                        width={nodeText.slice(0, 30).length * 6.2 + 8}
                        height="14"
                        rx="3"
                        fill="rgba(10,10,14,0.85)"
                        stroke="rgba(255,255,255,0.06)"
                        strokeWidth="0.5"
                      />
                      <text
                        x="2"
                        y="3"
                        fontSize={Math.max(9, 10 / Math.sqrt(scale))}
                        fill={isDimmed ? 'rgba(255,255,255,0.2)' : isSelected || isHovered ? '#fff' : 'rgba(255,255,255,0.75)'}
                        className="mono font-semibold select-none"
                      >
                        {nodeText.slice(0, 30)}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}
          </g>
        </svg>

        {/* Floating Node Inspector Card */}
        {(hover || selectedNode) && (
          <div className="absolute bottom-4 right-4 bg-[#14141d]/95 backdrop-blur-md p-3.5 rounded-xl border border-white/10 shadow-2xl max-w-xs pointer-events-auto z-20 font-mono text-xs">
            {(() => {
              const activeId = hover || selectedNode?.id;
              const activePt = basePts.find((p) => p.id === activeId);
              if (!activePt) return null;
              const cfg = KIND_CONFIG[activePt.node?.kind] || KIND_CONFIG.case;

              return (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2 border-b border-white/8 pb-1.5">
                    <div className="flex items-center gap-1.5">
                      <span>{cfg.icon}</span>
                      <span className="font-bold uppercase" style={{ color: cfg.color }}>
                        {cfg.label}
                      </span>
                    </div>
                    <span className="text-[10px] text-white/40">Weight: {activePt.node?.weight ?? 1}</span>
                  </div>
                  <p className="font-semibold text-white break-all text-xs">{activePt.node?.label || activePt.node?.id}</p>
                  {activePt.node?.detail && typeof activePt.node.detail === 'object' && (
                    <div className="text-[10px] text-white/60 bg-black/40 p-2 rounded border border-white/5 space-y-0.5 max-h-32 overflow-y-auto">
                      {Object.entries(activePt.node.detail).map(([k, v]) => (
                        <div key={k} className="flex justify-between gap-2">
                          <span className="text-white/40">{k}:</span>
                          <span className="text-white/80 truncate max-w-[120px]">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="text-[10px] text-white/30 pt-1">
                    Connected to {edges.filter((e) => e.source === activePt.id || e.target === activePt.id).length} links
                  </div>
                </div>
              );
            })()}
          </div>
        )}

        {/* Watermark Hint */}
        <div className="absolute top-2 left-3 pointer-events-none text-white/20 font-mono text-[10px] space-y-0.5">
          <p>• Scroll to Zoom (up to 20x)</p>
          <p>• Click & Drag Canvas to Pan</p>
          <p>• Drag any Node to Declutter</p>
        </div>
      </div>

      {/* Bottom Filter Legend */}
      <div className="p-2.5 bg-[#111116] border-t border-white/8 flex flex-wrap items-center justify-center gap-2 text-xs font-mono z-10">
        <span className="text-white/30 text-[11px] mr-1">Filter Kinds:</span>
        {Object.entries(KIND_CONFIG).map(([kind, cfg]) => {
          const active = activeKinds[kind];
          return (
            <button
              key={kind}
              onClick={() => toggleKind(kind)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border transition-all ${
                active
                  ? 'border-white/20 bg-white/5 text-white/90 shadow-sm'
                  : 'border-transparent text-white/20 opacity-40 hover:opacity-70'
              }`}
            >
              <span className="inline-block w-2.5 h-2.5 rounded-full" style={{ background: cfg.color }} />
              <span>{cfg.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export default GraphView;
