// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Usage Chart Component
 * 
 * Time-series chart for traffic, usage, and metrics
 */

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface DataPoint {
  timestamp: string;
  [key: string]: string | number;
}

interface SeriesConfig {
  key: string;
  label: string;
  color: string;
  gradientId?: string;
}

interface UsageChartProps {
  data: DataPoint[];
  series: SeriesConfig[];
  title?: string;
  timeRanges?: { label: string; value: string }[];
  selectedRange?: string;
  onRangeChange?: (range: string) => void;
  height?: number;
  className?: string;
}

const defaultTimeRanges = [
  { label: '1H', value: '1h' },
  { label: '6H', value: '6h' },
  { label: '24H', value: '24h' },
  { label: '7D', value: '7d' },
  { label: '30D', value: '30d' },
];

export function UsageChart({
  data,
  series,
  title,
  timeRanges = defaultTimeRanges,
  selectedRange = '24h',
  onRangeChange,
  height = 300,
  className,
}: UsageChartProps) {
  const [activeRange, setActiveRange] = useState(selectedRange);

  const handleRangeChange = (range: string) => {
    setActiveRange(range);
    onRangeChange?.(range);
  };

  return (
    <div className={cn('space-y-4', className)}>
      {/* Header with title and time range selector */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        {title && (
          <h3 className="text-sm font-medium text-muted-foreground">{title}</h3>
        )}
        <div className="flex gap-1 rounded-lg bg-muted p-1 overflow-x-auto scrollbar-hide -mx-1 px-1 sm:mx-0 sm:px-1">
          {timeRanges.map((range) => (
            <Button
              key={range.value}
              variant="ghost"
              size="sm"
              className={cn(
                'h-7 px-2.5 text-xs',
                activeRange === range.value && 'bg-background shadow-sm'
              )}
              onClick={() => handleRangeChange(range.value)}
            >
              {range.label}
            </Button>
          ))}
        </div>
      </div>

      {/* Chart */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3 }}
        style={{ height }}
      >
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={data}
            margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
          >
            <defs>
              {series.map((s) => (
                <linearGradient
                  key={`gradient-${s.key}`}
                  id={s.gradientId || `gradient-${s.key}`}
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop offset="0%" stopColor={s.color} stopOpacity={0.3} />
                  <stop offset="100%" stopColor={s.color} stopOpacity={0} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              vertical={false}
              stroke="hsl(var(--border))"
            />
            <XAxis
              dataKey="timestamp"
              axisLine={false}
              tickLine={false}
              tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
              tickMargin={8}
            />
            <YAxis
              axisLine={false}
              tickLine={false}
              tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
              tickMargin={8}
            />
            <Tooltip
              content={({ active, payload, label }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="rounded-lg border bg-popover px-3 py-2 shadow-md">
                      <p className="text-xs font-medium text-muted-foreground mb-1">
                        {label}
                      </p>
                      {payload.map((entry, index) => (
                        <p
                          key={index}
                          className="text-sm font-medium"
                          style={{ color: entry.color }}
                        >
                          {entry.name}: {entry.value}
                        </p>
                      ))}
                    </div>
                  );
                }
                return null;
              }}
            />
            <Legend
              verticalAlign="top"
              height={36}
              content={({ payload }) => (
                <div className="flex justify-center gap-4 mb-2">
                  {payload?.map((entry, index) => (
                    <div key={index} className="flex items-center gap-1.5">
                      <span
                        className="h-2 w-2 rounded-full"
                        style={{ backgroundColor: entry.color }}
                      />
                      <span className="text-xs text-muted-foreground">
                        {entry.value}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            />
            {series.map((s) => (
              <Area
                key={s.key}
                type="monotone"
                dataKey={s.key}
                name={s.label}
                stroke={s.color}
                strokeWidth={2}
                fill={`url(#${s.gradientId || `gradient-${s.key}`})`}
                animationDuration={500}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </motion.div>
    </div>
  );
}
