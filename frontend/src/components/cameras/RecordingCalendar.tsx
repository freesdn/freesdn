// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * RecordingCalendar, month-grid date picker for playback, with a dot on every
 * day that has footage (à la Hikvision's recording-day calendar). Footage days
 * are derived from the live NVR timeline for the visible month (getCameraTimeline),
 * so it reflects real recordings, not the empty DB table.
 *
 * Self-contained popover (button + click-outside panel), the project has no
 * Popover/Calendar primitive and react-day-picker isn't installed; date-fns is.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  addMonths,
  eachDayOfInterval,
  endOfMonth,
  endOfWeek,
  format,
  isSameDay,
  isSameMonth,
  startOfMonth,
  startOfWeek,
} from 'date-fns';
import { Calendar as CalendarIcon, ChevronLeft, ChevronRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { camerasApi } from '@/lib/api';
import { cn } from '@/lib/utils';

interface RecordingCalendarProps {
  /** Camera whose footage days are dotted (the representative camera in a grid). */
  cameraId?: string;
  /** Currently-selected playback instant. */
  value: Date;
  /** Fires with the picked day (current time-of-day preserved). */
  onPick: (date: Date) => void;
}

const WEEKDAYS = ['S', 'M', 'T', 'W', 'T', 'F', 'S'];

export function RecordingCalendar({ cameraId, value, onPick }: RecordingCalendarProps) {
  const [open, setOpen] = useState(false);
  const [viewMonth, setViewMonth] = useState(() => startOfMonth(value));
  const ref = useRef<HTMLDivElement>(null);

  // Re-centre on the selected day each time the popover opens.
  useEffect(() => {
    if (open) setViewMonth(startOfMonth(value));
  }, [open, value]);

  // Close on outside-click / Escape.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const monthStart = startOfMonth(viewMonth);
  const monthEnd = endOfMonth(viewMonth);

  const { data } = useQuery({
    queryKey: ['recording-days', cameraId, format(viewMonth, 'yyyy-MM')],
    queryFn: async () => {
      const end = new Date(Math.min(Date.now(), monthEnd.getTime()));
      const res = await camerasApi.getCameraTimeline(cameraId as string, monthStart.toISOString(), end.toISOString());
      return res.data;
    },
    enabled: open && !!cameraId,
    staleTime: 5 * 60_000,
  });

  // Local-day strings touched by any recording segment.
  const footageDays = useMemo(() => {
    const set = new Set<string>();
    const segs: Array<{ start: string; end: string }> | undefined = data?.segments;
    if (Array.isArray(segs)) {
      for (const s of segs) {
        const a = new Date(s.start);
        const b = new Date(s.end);
        if (isNaN(a.getTime()) || isNaN(b.getTime())) continue;
        for (
          let d = new Date(a.getFullYear(), a.getMonth(), a.getDate());
          d.getTime() <= b.getTime();
          d.setDate(d.getDate() + 1)
        ) {
          set.add(format(d, 'yyyy-MM-dd'));
        }
      }
    }
    return set;
  }, [data]);

  const days = useMemo(
    () => eachDayOfInterval({ start: startOfWeek(monthStart), end: endOfWeek(monthEnd) }),
    [monthStart, monthEnd],
  );

  return (
    <div className="relative" ref={ref}>
      <Button variant="outline" size="sm" className="h-8 gap-1.5 text-xs" onClick={() => setOpen((o) => !o)}>
        <CalendarIcon className="h-3.5 w-3.5" />
        {format(value, 'MMM d, yyyy')}
      </Button>
      {open && (
        <div className="absolute left-0 z-50 mt-1 w-64 rounded-md border bg-popover p-3 shadow-md">
          <div className="mb-2 flex items-center justify-between">
            <button type="button" className="rounded p-1 hover:bg-muted" onClick={() => setViewMonth((m) => addMonths(m, -1))}>
              <ChevronLeft className="h-4 w-4" />
            </button>
            <span className="text-sm font-medium">{format(viewMonth, 'MMMM yyyy')}</span>
            <button type="button" className="rounded p-1 hover:bg-muted" onClick={() => setViewMonth((m) => addMonths(m, 1))}>
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
          <div className="mb-1 grid grid-cols-7 gap-0.5 text-center text-[10px] text-muted-foreground">
            {WEEKDAYS.map((w, i) => (
              <div key={i}>{w}</div>
            ))}
          </div>
          <div className="grid grid-cols-7 gap-0.5">
            {days.map((d) => {
              const inMonth = isSameMonth(d, viewMonth);
              const selected = isSameDay(d, value);
              const hasFootage = footageDays.has(format(d, 'yyyy-MM-dd'));
              const future = d.getTime() > Date.now();
              return (
                <button
                  key={d.toISOString()}
                  type="button"
                  disabled={future}
                  onClick={() => {
                    const picked = new Date(d);
                    picked.setHours(value.getHours(), value.getMinutes(), value.getSeconds(), 0);
                    onPick(picked);
                    setOpen(false);
                  }}
                  className={cn(
                    'relative flex h-7 items-center justify-center rounded text-xs',
                    !inMonth && 'text-muted-foreground/40',
                    future && 'cursor-not-allowed opacity-30',
                    selected ? 'bg-primary text-primary-foreground' : 'hover:bg-muted',
                  )}
                >
                  {d.getDate()}
                  {hasFootage && !selected && (
                    <span className="absolute bottom-0.5 left-1/2 h-1 w-1 -translate-x-1/2 rounded-full bg-emerald-500" />
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export default RecordingCalendar;
