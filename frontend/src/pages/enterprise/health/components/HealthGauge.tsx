// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { cn } from '@/lib/utils';

export function HealthGauge({ score, size = 'lg' }: { score: number | null | undefined; size?: 'sm' | 'md' | 'lg' }) {
  const measured = score != null && Number.isFinite(score);
  const value = measured ? Math.max(0, Math.min(100, score)) : 0;
  const radius = size === 'lg' ? 80 : size === 'md' ? 56 : 36;
  const stroke = size === 'lg' ? 10 : size === 'md' ? 8 : 6;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;

  const color =
    !measured ? 'text-muted-foreground' :
    value >= 90 ? 'text-green-500' :
    value >= 70 ? 'text-amber-500' :
    value >= 50 ? 'text-orange-500' :
    'text-red-500';

  const dim = (radius + stroke) * 2;
  const fontSize = size === 'lg' ? 'text-4xl' : size === 'md' ? 'text-2xl' : 'text-lg';

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={dim} height={dim} className="-rotate-90">
        <circle
          cx={radius + stroke}
          cy={radius + stroke}
          r={radius}
          fill="none"
          strokeWidth={stroke}
          className="stroke-muted"
        />
        <circle
          cx={radius + stroke}
          cy={radius + stroke}
          r={radius}
          fill="none"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={cn('transition-all duration-1000', color.replace('text-', 'stroke-'))}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={cn('font-bold', fontSize, color)}>{measured ? Math.round(value) : 'N/A'}</span>
        <span className="text-xs text-muted-foreground">/ 100</span>
      </div>
    </div>
  );
}
