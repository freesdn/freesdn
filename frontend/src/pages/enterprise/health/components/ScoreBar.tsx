// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { cn } from '@/lib/utils';
import { useTranslation } from 'react-i18next';

export function ScoreBar({ label, score, icon: Icon }: { label: string; score: number | null; icon: React.ElementType }) {
  const { t } = useTranslation('enterprise');
  if (score === null || score === undefined) {
    return (
      <div className="flex items-center gap-3">
        <Icon className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm text-muted-foreground w-24">{label}</span>
        <span className="text-xs text-muted-foreground">{t('ScoreBar.notAvailable')}</span>
      </div>
    );
  }
  const color =
    score >= 90 ? 'bg-green-500' :
    score >= 70 ? 'bg-amber-500' :
    score >= 50 ? 'bg-orange-500' :
    'bg-red-500';

  return (
    <div className="flex items-center gap-3">
      <Icon className="h-4 w-4 text-muted-foreground flex-shrink-0" />
      <span className="text-sm text-muted-foreground w-24 flex-shrink-0">{label}</span>
      <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', color)} style={{ width: `${score}%` }} />
      </div>
      <span className="text-sm font-medium w-8 text-right">{score}</span>
    </div>
  );
}
