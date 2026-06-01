// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * RegionEditor, draw/edit a polygon (zone / privacy mask / intrusion area) or a
 * line (line-crossing tripwire) over a live camera snapshot. Coordinates are the
 * Hikvision-normalized 0-10000 space (origin top-left), so a region drawn here
 * maps 1:1 to the NVR's smart-config endpoints regardless of resolution.
 *
 * Interaction: click empty space to add a point (polygon up to maxPoints; line =
 * exactly 2), drag a point to move it, click a point to select, Delete/the
 * toolbar to remove the selected point or clear all.
 */
import { useCallback, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Trash2, Undo2, Eraser } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

export interface RegionPoint {
  x: number;
  y: number;
}

const COORD_MAX = 10000;

interface RegionEditorProps {
  /** Snapshot URL used as the drawing backdrop. */
  imageUrl: string;
  mode: 'polygon' | 'line';
  points: RegionPoint[];
  onChange: (points: RegionPoint[]) => void;
  /** Max points (line is forced to 2). Polygon default 12. */
  maxPoints?: number;
  color?: string;
  className?: string;
}

export function RegionEditor({
  imageUrl,
  mode,
  points,
  onChange,
  maxPoints,
  color = '#22d3ee',
  className,
}: RegionEditorProps) {
  const { t } = useTranslation('cameras');
  const svgRef = useRef<SVGSVGElement>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const draggingRef = useRef<number | null>(null);
  const cap = mode === 'line' ? 2 : maxPoints ?? 12;

  // Pointer (client px) → normalized 0-10000, clamped.
  const toCoord = useCallback((clientX: number, clientY: number): RegionPoint => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const r = svg.getBoundingClientRect();
    const x = Math.round(((clientX - r.left) / Math.max(1, r.width)) * COORD_MAX);
    const y = Math.round(((clientY - r.top) / Math.max(1, r.height)) * COORD_MAX);
    return { x: Math.max(0, Math.min(COORD_MAX, x)), y: Math.max(0, Math.min(COORD_MAX, y)) };
  }, []);

  const handleSvgPointerDown = useCallback(
    (e: React.PointerEvent) => {
      // Ignore if a point handle initiated the drag (handled separately).
      if (draggingRef.current !== null) return;
      if (points.length >= cap) return;
      const p = toCoord(e.clientX, e.clientY);
      onChange([...points, p]);
      setSelected(points.length);
    },
    [points, cap, toCoord, onChange],
  );

  const handlePointerMove = useCallback(
    (e: React.PointerEvent) => {
      const idx = draggingRef.current;
      if (idx === null) return;
      e.preventDefault();
      const p = toCoord(e.clientX, e.clientY);
      const next = points.slice();
      next[idx] = p;
      onChange(next);
    },
    [points, toCoord, onChange],
  );

  const endDrag = useCallback(() => {
    draggingRef.current = null;
  }, []);

  const removeSelected = useCallback(() => {
    if (selected === null) return;
    onChange(points.filter((_, i) => i !== selected));
    setSelected(null);
  }, [selected, points, onChange]);

  const undo = useCallback(() => {
    onChange(points.slice(0, -1));
    setSelected(null);
  }, [points, onChange]);

  const closed = mode === 'polygon' && points.length >= 3;
  const ptsStr = points.map((p) => `${p.x},${p.y}`).join(' ');

  return (
    <div className={cn('space-y-2', className)}>
      <div className="relative w-full overflow-hidden rounded-md bg-black" style={{ aspectRatio: '16 / 9' }}>
        <img src={imageUrl} alt={t('RegionEditor.snapshotAlt')} className="absolute inset-0 h-full w-full object-contain" draggable={false} />
        <svg
          ref={svgRef}
          viewBox={`0 0 ${COORD_MAX} ${COORD_MAX}`}
          preserveAspectRatio="none"
          className="absolute inset-0 h-full w-full cursor-crosshair touch-none"
          onPointerDown={handleSvgPointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={endDrag}
          onPointerLeave={endDrag}
        >
          {points.length >= 2 &&
            (closed ? (
              <polygon points={ptsStr} fill={`${color}33`} stroke={color} strokeWidth={40} />
            ) : (
              <polyline points={ptsStr} fill="none" stroke={color} strokeWidth={40} />
            ))}
          {points.map((p, i) => (
            <circle
              key={i}
              cx={p.x}
              cy={p.y}
              r={selected === i ? 150 : 110}
              fill={selected === i ? color : '#fff'}
              stroke={color}
              strokeWidth={40}
              style={{ cursor: 'grab' }}
              onPointerDown={(e) => {
                e.stopPropagation();
                draggingRef.current = i;
                setSelected(i);
              }}
            />
          ))}
        </svg>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">
          {mode === 'line'
            ? t('RegionEditor.lineHint', { count: points.length })
            : t('RegionEditor.polygonHint', { count: points.length, max: cap })}
        </span>
        <div className="flex items-center gap-1">
          <Button type="button" size="sm" variant="ghost" disabled={selected === null} onClick={removeSelected}>
            <Trash2 className="h-3.5 w-3.5 mr-1" /> {t('RegionEditor.removePoint')}
          </Button>
          <Button type="button" size="sm" variant="ghost" disabled={!points.length} onClick={undo}>
            <Undo2 className="h-3.5 w-3.5 mr-1" /> {t('RegionEditor.undo')}
          </Button>
          <Button type="button" size="sm" variant="ghost" disabled={!points.length} onClick={() => { onChange([]); setSelected(null); }}>
            <Eraser className="h-3.5 w-3.5 mr-1" /> {t('RegionEditor.clear')}
          </Button>
        </div>
      </div>
    </div>
  );
}

export default RegionEditor;
