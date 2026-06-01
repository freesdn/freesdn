// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Camera Canvas Overlay Library
 *
 * SVG-based visual overlay components for camera detection configuration:
 *  - CameraCanvasOverlay: base snapshot + SVG container
 *  - RectangleOverlay: privacy mask regions (draggable/resizable rectangles)
 *  - LineOverlay: line crossing rules (two-point lines with direction arrows)
 *  - PolygonOverlay: intrusion detection zones (multi-point polygon)
 *  - GridOverlay: motion detection grid (22×18 togglable cells)
 *
 * All coordinates use the Hikvision ISAPI normalised 0-1000 range.
 */

import React, { useState, useCallback, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { camerasApi } from '@/lib/api';
import { cn } from '@/lib/utils';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Point {
  x: number;
  y: number;
}

// Hikvision normalised coordinate space
const NORM = 1000;

// Colour palette for up to 8 regions/rules
const PALETTE = [
  '#3b82f6', // blue
  '#ef4444', // red
  '#22c55e', // green
  '#f59e0b', // amber
  '#8b5cf6', // violet
  '#ec4899', // pink
  '#06b6d4', // cyan
  '#f97316', // orange
];

function getColor(index: number): string {
  return PALETTE[index % PALETTE.length];
}

// ---------------------------------------------------------------------------
// Helper: convert normalised → SVG pixels and back
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CameraCanvasOverlay, base wrapper
// ---------------------------------------------------------------------------

interface CameraCanvasOverlayProps {
  cameraId: string;
  /** SVG children rendered in normalised-space viewport (0-1000 × 0-1000) */
  children?: React.ReactNode;
  className?: string;
  /** Width of the rendered overlay canvas */
  width?: number;
  /** Aspect ratio for the canvas (default 16:9) */
  aspectRatio?: number;
}

export function CameraCanvasOverlay({
  cameraId,
  children,
  className,
  width = 640,
  aspectRatio = 16 / 9,
}: CameraCanvasOverlayProps) {
  const { t } = useTranslation('common');
  const height = Math.round(width / aspectRatio);
  const [snapshotUrl, setSnapshotUrl] = useState('');

  // Fetch a short-lived stream token for the snapshot URL
  useEffect(() => {
    let cancelled = false;
    camerasApi.getSnapshotUrlAsync(cameraId).then((url) => {
      if (!cancelled) setSnapshotUrl(url);
    }).catch(() => {
      // Stream token fetch failed · leave snapshot empty (error state)
      if (!cancelled) setSnapshotUrl('');
    });
    return () => { cancelled = true; };
  }, [cameraId]);

  return (
    <div
      className={cn('relative inline-block bg-muted rounded overflow-hidden select-none', className)}
      style={{ width, height }}
    >
      {/* Camera snapshot background */}
      <img
        src={snapshotUrl}
        alt={t('CameraCanvasOverlay.snapshotAlt')}
        className="absolute inset-0 w-full h-full object-cover"
        draggable={false}
      />

      {/* SVG overlay */}
      <svg
        viewBox={`0 0 ${NORM} ${NORM}`}
        className="absolute inset-0 w-full h-full"
        preserveAspectRatio="none"
        style={{ pointerEvents: 'none' }}
      >
        {children}
      </svg>
    </div>
  );
}

// ---------------------------------------------------------------------------
// RectangleOverlay, for privacy masks
// ---------------------------------------------------------------------------

interface RectangleOverlayProps {
  /** Array of rectangles, each with 4 corner points (order: TL, TR, BR, BL) */
  regions: { id: number; enabled: boolean; coordinates: Point[] }[];
  /** Called when coordinates change via drag */
  onChange?: (index: number, newCoords: Point[]) => void;
  /** Whether editing (dragging) is enabled */
  editable?: boolean;
}

export function RectangleOverlay({ regions, editable = false }: RectangleOverlayProps) {
  const { t } = useTranslation('common');
  return (
    <g style={{ pointerEvents: editable ? 'all' : 'none' }}>
      {regions.map((region, idx) => {
        if (region.coordinates.length < 2) return null;
        const color = getColor(idx);
        // Derive bounding box from coordinates
        const xs = region.coordinates.map((p) => p.x);
        const ys = region.coordinates.map((p) => p.y);
        const x = Math.min(...xs);
        const y = Math.min(...ys);
        const w = Math.max(...xs) - x;
        const h = Math.max(...ys) - y;

        return (
          <g key={region.id}>
            <rect
              x={x}
              y={y}
              width={w}
              height={h}
              fill={region.enabled ? color : '#666'}
              fillOpacity={0.25}
              stroke={region.enabled ? color : '#666'}
              strokeWidth={3}
              strokeDasharray={region.enabled ? 'none' : '8 4'}
            />
            <text
              x={x + 8}
              y={y + 30}
              fill="white"
              fontSize={24}
              fontWeight="bold"
              style={{ textShadow: '1px 1px 2px rgba(0,0,0,0.8)' }}
            >
              {t('CameraCanvasOverlay.label.region', { id: region.id })}
            </text>
          </g>
        );
      })}
    </g>
  );
}

// ---------------------------------------------------------------------------
// LineOverlay, for line crossing rules
// ---------------------------------------------------------------------------

interface LineOverlayProps {
  rules: { id: number; enabled: boolean; sensitivity: number; direction: string; coordinates: Point[] }[];
  editable?: boolean;
  onChange?: (index: number, newCoords: Point[]) => void;
}

export function LineOverlay({ rules, editable = false }: LineOverlayProps) {
  const { t } = useTranslation('common');
  return (
    <g style={{ pointerEvents: editable ? 'all' : 'none' }}>
      {rules.map((rule, idx) => {
        if (rule.coordinates.length < 2) return null;
        const color = getColor(idx);
        const [p1, p2] = rule.coordinates;

        // Direction arrow (perpendicular mid-point)
        const mx = (p1.x + p2.x) / 2;
        const my = (p1.y + p2.y) / 2;
        const dx = p2.x - p1.x;
        const dy = p2.y - p1.y;
        const len = Math.sqrt(dx * dx + dy * dy) || 1;
        const nx = -dy / len;
        const ny = dx / len;
        const arrowLen = 40;

        return (
          <g key={rule.id}>
            {/* Main line */}
            <line
              x1={p1.x}
              y1={p1.y}
              x2={p2.x}
              y2={p2.y}
              stroke={rule.enabled ? color : '#888'}
              strokeWidth={4}
              strokeLinecap="round"
              opacity={rule.enabled ? 1 : 0.5}
            />
            {/* Endpoints */}
            <circle cx={p1.x} cy={p1.y} r={8} fill={color} stroke="white" strokeWidth={2} />
            <circle cx={p2.x} cy={p2.y} r={8} fill={color} stroke="white" strokeWidth={2} />

            {/* Direction arrows */}
            {(rule.direction === 'left-to-right' || rule.direction === 'both') && (
              <line
                x1={mx}
                y1={my}
                x2={mx + nx * arrowLen}
                y2={my + ny * arrowLen}
                stroke={color}
                strokeWidth={3}
                markerEnd="url(#arrowhead)"
              />
            )}
            {(rule.direction === 'right-to-left' || rule.direction === 'both') && (
              <line
                x1={mx}
                y1={my}
                x2={mx - nx * arrowLen}
                y2={my - ny * arrowLen}
                stroke={color}
                strokeWidth={3}
                markerEnd="url(#arrowhead)"
              />
            )}

            {/* Label */}
            <text
              x={p1.x}
              y={p1.y - 14}
              fill="white"
              fontSize={20}
              fontWeight="bold"
              textAnchor="middle"
              style={{ textShadow: '1px 1px 2px rgba(0,0,0,0.8)' }}
            >
              {t('CameraCanvasOverlay.label.line', { id: rule.id })}
            </text>
          </g>
        );
      })}

      {/* Arrowhead marker definition */}
      <defs>
        <marker
          id="arrowhead"
          markerWidth="10"
          markerHeight="7"
          refX="10"
          refY="3.5"
          orient="auto"
        >
          <polygon points="0 0, 10 3.5, 0 7" fill="currentColor" />
        </marker>
      </defs>
    </g>
  );
}

// ---------------------------------------------------------------------------
// PolygonOverlay, for intrusion detection zones
// ---------------------------------------------------------------------------

interface PolygonOverlayProps {
  zones: { id: number; enabled: boolean; coordinates: Point[] }[];
  editable?: boolean;
  onChange?: (index: number, newCoords: Point[]) => void;
}

export function PolygonOverlay({ zones, editable = false }: PolygonOverlayProps) {
  const { t } = useTranslation('common');
  return (
    <g style={{ pointerEvents: editable ? 'all' : 'none' }}>
      {zones.map((zone, idx) => {
        if (zone.coordinates.length < 3) return null;
        const color = getColor(idx);
        const pts = zone.coordinates.map((p) => `${p.x},${p.y}`).join(' ');
        const centroid = {
          x: zone.coordinates.reduce((s, p) => s + p.x, 0) / zone.coordinates.length,
          y: zone.coordinates.reduce((s, p) => s + p.y, 0) / zone.coordinates.length,
        };

        return (
          <g key={zone.id}>
            {/* Filled polygon */}
            <polygon
              points={pts}
              fill={zone.enabled ? color : '#666'}
              fillOpacity={0.2}
              stroke={zone.enabled ? color : '#666'}
              strokeWidth={3}
              strokeLinejoin="round"
              strokeDasharray={zone.enabled ? 'none' : '8 4'}
            />
            {/* Vertex dots */}
            {zone.coordinates.map((p, pi) => (
              <circle
                key={pi}
                cx={p.x}
                cy={p.y}
                r={6}
                fill={color}
                stroke="white"
                strokeWidth={2}
              />
            ))}
            {/* Label in center */}
            <text
              x={centroid.x}
              y={centroid.y}
              fill="white"
              fontSize={22}
              fontWeight="bold"
              textAnchor="middle"
              dominantBaseline="central"
              style={{ textShadow: '1px 1px 3px rgba(0,0,0,0.9)' }}
            >
              {t('CameraCanvasOverlay.label.zone', { id: zone.id })}
            </text>
          </g>
        );
      })}
    </g>
  );
}

// ---------------------------------------------------------------------------
// GridOverlay, for motion detection (22×18 cell grid)
// ---------------------------------------------------------------------------

interface GridOverlayProps {
  /**
   * Motion grid map encoded as a hex string.
   * Each bit = one cell in the 22×18 grid.
   */
  gridMap: string;
  /** Called when the grid map changes */
  onChange?: (newGridMap: string) => void;
  editable?: boolean;
  /** Whether to show the grid at all */
  visible?: boolean;
}

const GRID_COLS = 22;
const GRID_ROWS = 18;
const CELL_W = NORM / GRID_COLS;
const CELL_H = NORM / GRID_ROWS;

/**
 * Parse an ISAPI hex grid string into a 2D boolean array.
 * Hikvision uses rows of hex characters, separated by colons or as one block.
 */
function parseGridMap(hex: string): boolean[][] {
  const grid: boolean[][] = [];
  // Remove any non-hex separators and normalise
  const cleaned = hex.replace(/[^0-9a-fA-F]/g, '');
  // Each row of 22 cells needs 22 bits = ceil(22/4) = 6 hex chars
  const hexPerRow = Math.ceil(GRID_COLS / 4);
  for (let row = 0; row < GRID_ROWS; row++) {
    const rowHex = cleaned.slice(row * hexPerRow, (row + 1) * hexPerRow) || '0'.repeat(hexPerRow);
    const rowBits: boolean[] = [];
    const num = parseInt(rowHex, 16);
    for (let col = 0; col < GRID_COLS; col++) {
      // MSB first
      const bit = (num >> (GRID_COLS - 1 - col)) & 1;
      rowBits.push(!!bit);
    }
    grid.push(rowBits);
  }
  return grid;
}

function gridToHex(grid: boolean[][]): string {
  const hexPerRow = Math.ceil(GRID_COLS / 4);
  const parts: string[] = [];
  for (let row = 0; row < GRID_ROWS; row++) {
    let num = 0;
    for (let col = 0; col < GRID_COLS; col++) {
      if (grid[row]?.[col]) {
        num |= 1 << (GRID_COLS - 1 - col);
      }
    }
    parts.push(num.toString(16).padStart(hexPerRow, '0'));
  }
  return parts.join('');
}

export function GridOverlay({
  gridMap,
  onChange,
  editable = false,
  visible = true,
}: GridOverlayProps) {
  const grid = useMemo(() => parseGridMap(gridMap), [gridMap]);
  const [painting, setPainting] = useState(false);
  const [paintValue, setPaintValue] = useState(true);

  // Clear painting state when mouse is released anywhere (not just on cells)
  useEffect(() => {
    const handler = () => setPainting(false);
    window.addEventListener('mouseup', handler);
    return () => window.removeEventListener('mouseup', handler);
  }, []);

  const toggleCell = useCallback(
    (row: number, col: number, value?: boolean) => {
      if (!onChange || !editable) return;
      const newGrid = grid.map((r) => [...r]);
      newGrid[row][col] = value ?? !newGrid[row][col];
      onChange(gridToHex(newGrid));
    },
    [grid, onChange, editable],
  );

  if (!visible) return null;

  return (
    <g style={{ pointerEvents: editable ? 'all' : 'none' }}>
      {grid.map((row, ri) =>
        row.map((active, ci) => (
          <rect
            key={`${ri}-${ci}`}
            x={ci * CELL_W}
            y={ri * CELL_H}
            width={CELL_W}
            height={CELL_H}
            fill={active ? '#3b82f6' : 'transparent'}
            fillOpacity={active ? 0.35 : 0}
            stroke="#ffffff40"
            strokeWidth={0.5}
            style={{ cursor: editable ? 'pointer' : 'default' }}
            onMouseDown={(e) => {
              e.preventDefault();
              setPainting(true);
              const next = !active;
              setPaintValue(next);
              toggleCell(ri, ci, next);
            }}
            onMouseEnter={() => {
              if (painting) toggleCell(ri, ci, paintValue);
            }}
            onMouseUp={() => setPainting(false)}
          />
        )),
      )}
      {/* Cancel paint on mouse leave */}
      <rect
        x={0}
        y={0}
        width={NORM}
        height={NORM}
        fill="transparent"
        style={{ pointerEvents: 'none' }}
        onMouseUp={() => setPainting(false)}
      />
    </g>
  );
}

