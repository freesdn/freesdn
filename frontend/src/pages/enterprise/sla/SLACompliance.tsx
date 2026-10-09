// SPDX-License-Identifier: AGPL-3.0-only
import { Progress } from '@/components/ui/progress';

function isMeasured(value: number | null | undefined): value is number {
  return value != null && Number.isFinite(value) && value >= 0 && value <= 100;
}

export function complianceVariant(value: number | null | undefined) {
  if (!isMeasured(value)) return 'default';
  return value >= 95 ? 'success' : value >= 80 ? 'warning' : 'destructive';
}

export function formatCompliance(value: number | null | undefined, unavailable: string) {
  return isMeasured(value) ? `${value.toFixed(1)}%` : unavailable;
}

export function ComplianceGauge({ value, unavailable }: {
  value: number | null;
  unavailable: string;
}) {
  if (!isMeasured(value)) {
    return <span className="font-mono text-muted-foreground">{unavailable}</span>;
  }
  const variant = complianceVariant(value);
  const color = variant === 'success' ? 'text-success'
    : variant === 'warning' ? 'text-warning' : 'text-destructive';
  return (
    <div className="flex items-center gap-2">
      <Progress value={value} className="h-2 flex-1" />
      <span className={`font-mono font-bold ${color}`}>{formatCompliance(value, unavailable)}</span>
    </div>
  );
}
