/**
 * Relay trace map — High-performance dark mode Leaflet map
 * with animated glowing route polyline, pulse markers, and defensive coordinate validation.
 */

import React, { Component, ErrorInfo, ReactNode, useEffect, useState } from 'react';
import { CircleMarker, MapContainer, Polyline, TileLayer, Tooltip, Popup, useMap } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import { Empty } from './ui';
import { flag } from '../lib/format';
import type { MapLayout, MapMarker } from '../lib/types';

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
}

class MapErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.warn('Map rendering error caught safely:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback || (
          <Empty
            title="Map unavailable"
            hint="Coordinates could not be rendered on the cartographic canvas for this case."
          />
        )
      );
    }
    return this.props.children;
  }
}

function FitBounds({ markers }: { markers: MapMarker[] }) {
  const map = useMap();
  useEffect(() => {
    if (!markers || !markers.length) return;
    try {
      if (markers.length === 1) {
        map.setView([markers[0].lat, markers[0].lon], 4);
      } else {
        const bounds = markers.map((m) => [m.lat, m.lon] as [number, number]);
        map.fitBounds(bounds, { padding: [40, 40], maxZoom: 7 });
      }
    } catch (e) {
      console.warn('FitBounds caught non-fatal error:', e);
    }
  }, [map, markers]);
  return null;
}

function markerColor(marker: MapMarker): string {
  if (marker.kind === 'origin') return '#ef4444'; // Red for origin
  if (marker.anomalous || marker.reason) return '#f97316'; // Orange for anomaly
  if (marker.kind === 'final') return '#10b981'; // Green for delivery destination
  return '#3b82f6'; // Blue for transit
}

export function RelayMapInner({ layout, height = 440 }: { layout?: MapLayout; height?: number }) {
  const [selectedMarker, setSelectedMarker] = useState<MapMarker | null>(null);

  if (!layout || !layout.drawable || !layout.markers || !layout.markers.length) {
    return (
      <Empty
        title="No locatable hops"
        hint={layout?.note || 'The trace has no relay with a resolvable IP location to plot.'}
      />
    );
  }

  // Strict check: lat and lon MUST be real non-null numbers
  const validMarkers = layout.markers.filter(
    (m) =>
      m != null &&
      typeof m.lat === 'number' &&
      typeof m.lon === 'number' &&
      !isNaN(m.lat) &&
      !isNaN(m.lon) &&
      m.lat !== null &&
      m.lon !== null
  );

  if (!validMarkers.length) {
    return (
      <Empty
        title="No locatable coordinates"
        hint={
          layout?.note ||
          'This trace contains private (RFC 1918) or documentation (RFC 5737) IP ranges with no public geographic coordinates.'
        }
      />
    );
  }

  const center = [validMarkers[0].lat, validMarkers[0].lon] as [number, number];
  const route = validMarkers.map((m) => [m.lat, m.lon] as [number, number]);

  return (
    <div className="w-full flex flex-col gap-3 select-none">
      {/* Map Container */}
      <div
        className="w-full overflow-hidden rounded-xl border border-white/8 relative bg-[#0d0d12]"
        style={{ height }}
      >
        <MapContainer
          center={center}
          zoom={3}
          scrollWheelZoom={true}
          className="h-full w-full"
          style={{ background: '#0a0a0f' }}
        >
          {/* Official Esri World Dark Gray Canvas Base (No API key required) */}
          <TileLayer
            attribution='&copy; <a href="https://www.esri.com/">Esri</a> &middot; OpenStreetMap'
            url="https://services.arcgisonline.com/arcgis/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
            maxZoom={16}
          />
          {/* Esri World Dark Gray Reference Layer (City names, places, roads & borders) */}
          <TileLayer
            url="https://services.arcgisonline.com/arcgis/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}"
            maxZoom={16}
          />
          <FitBounds markers={validMarkers} />

          {/* Glowing Animated Route Polyline */}
          {route.length > 1 && (
            <>
              <Polyline
                positions={route}
                pathOptions={{
                  color: '#3b82f6',
                  weight: 3,
                  opacity: 0.85,
                  dashArray: '8 6',
                }}
              />
              <Polyline
                positions={route}
                pathOptions={{
                  color: '#ef4444',
                  weight: 6,
                  opacity: 0.2,
                }}
              />
            </>
          )}

          {/* Markers */}
          {validMarkers.map((marker) => {
            const isOrigin = marker.kind === 'origin';
            const color = markerColor(marker);
            const r = isOrigin ? 10 : marker.anomalous ? 8 : 6;

            return (
              <React.Fragment key={`${marker.index}-${marker.ip}`}>
                {/* Glow ring for origin / anomalies */}
                {(isOrigin || marker.anomalous) && (
                  <CircleMarker
                    center={[marker.lat, marker.lon]}
                    radius={r + 6}
                    pathOptions={{
                      color,
                      weight: 1.5,
                      fillColor: color,
                      fillOpacity: 0.2,
                    }}
                  />
                )}

                <CircleMarker
                  center={[marker.lat, marker.lon]}
                  radius={r}
                  pathOptions={{
                    color: '#ffffff',
                    weight: 2,
                    fillColor: color,
                    fillOpacity: 1,
                  }}
                  eventHandlers={{
                    click: () => setSelectedMarker(marker),
                  }}
                >
                  <Tooltip direction="top" offset={[0, -8]} opacity={0.95}>
                    <div className="font-mono text-xs font-semibold">
                      Hop #{marker.index}: {marker.place || marker.ip}
                    </div>
                  </Tooltip>

                  <Popup className="dark-popup">
                    <div className="bg-[#121217] text-white p-3 rounded-lg font-mono text-xs space-y-1 min-w-[200px]">
                      <div className="flex items-center justify-between border-b border-white/10 pb-1 mb-1">
                        <span className="font-bold text-brand uppercase">
                          HOP #{marker.index} ({marker.kind})
                        </span>
                        <span>{flag(marker.country_code)}</span>
                      </div>
                      <p><span className="text-white/40">IP:</span> {marker.ip}</p>
                      <p><span className="text-white/40">Location:</span> {marker.place || 'Unknown'}</p>
                      {marker.asn && <p><span className="text-white/40">ASN:</span> {marker.asn}</p>}
                      {marker.isp && <p><span className="text-white/40">ISP:</span> {marker.isp}</p>}
                      {marker.anomalous && (
                        <div className="mt-1 p-1 bg-red-500/20 text-red-400 rounded text-[10px]">
                          ⚠ {marker.reason || 'Anomalous hop detected'}
                        </div>
                      )}
                    </div>
                  </Popup>
                </CircleMarker>
              </React.Fragment>
            );
          })}
        </MapContainer>

        {/* Map Legend Overlay in corner */}
        <div className="absolute top-3 right-3 bg-[#111116]/90 backdrop-blur-md p-2.5 rounded-lg border border-white/10 shadow-lg text-[11px] font-mono text-white/80 space-y-1 pointer-events-none z-[1000]">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#ef4444]" />
            <span>Origin Server (First Hop)</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#f97316]" />
            <span>Anomalous / Proxy Hop</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#3b82f6]" />
            <span>Transit Relay</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#10b981]" />
            <span>Final Delivery MX</span>
          </div>
        </div>
      </div>

      {/* Hop Pills Bar */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs font-mono">
        {validMarkers.map((m, i) => (
          <span
            key={i}
            className="inline-flex items-center gap-1.5 bg-[#14141a] px-2.5 py-1 rounded-md border border-white/8"
          >
            <span>{flag(m.country_code)}</span>
            <span className="text-white/90 font-medium">#{m.index} {m.place || m.ip}</span>
            {m.kind === 'origin' && (
              <span className="px-1.5 py-0.2 bg-red-500/20 text-red-400 rounded text-[10px] uppercase font-bold">
                Origin
              </span>
            )}
            {m.anomalous && (
              <span className="px-1.5 py-0.2 bg-orange-500/20 text-orange-400 rounded text-[10px] uppercase font-bold">
                Anomaly
              </span>
            )}
          </span>
        ))}
        {layout.unlocated && layout.unlocated.length > 0 && (
          <span className="text-white/40 text-[11px]">
            +{layout.unlocated.length} private/internal hop(s)
          </span>
        )}
      </div>
    </div>
  );
}

export function RelayMap(props: { layout?: MapLayout; height?: number }) {
  return (
    <MapErrorBoundary>
      <RelayMapInner {...props} />
    </MapErrorBoundary>
  );
}

export default RelayMap;
