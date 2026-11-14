// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Access Control Page
 *
 * Says exactly what the capability record (`access_control` in
 * backend/app/core/capability_maturity.py) says, and nothing more:
 * Experimental; door and credential records work through the API; physical
 * door control is refused with HTTP 501 because no door-controller adapter
 * exists; the module ships disabled. This page has no management screens, so
 * it says so instead of advertising features (real-time door control,
 * biometrics, anti-passback) that no code path implements.
 * `AccessControlPage.test.tsx` fails if the record moves on without this page.
 */

import { useTranslation } from 'react-i18next';
import { CheckCircle2, DoorClosed, Info, XCircle, type LucideIcon } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { CapabilityMaturityBadge } from '@/components/ui/capability-maturity-badge';
import { PageHeader } from '@/components/layout';

function StatusItem({
  icon: Icon,
  tone,
  title,
  children,
}: {
  icon: LucideIcon;
  tone: 'success' | 'destructive' | 'muted';
  title: string;
  children: React.ReactNode;
}) {
  const iconClass =
    tone === 'success' ? 'text-success' : tone === 'destructive' ? 'text-destructive' : 'text-muted-foreground';
  return (
    <div className="flex items-start gap-3">
      <Icon className={`mt-0.5 h-5 w-5 shrink-0 ${iconClass}`} aria-hidden="true" />
      <div className="min-w-0 space-y-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        <div className="text-sm text-muted-foreground">{children}</div>
      </div>
    </div>
  );
}

export default function AccessControlPage() {
  const { t } = useTranslation('access');

  return (
    <div className="space-y-6">
      <PageHeader
        icon={DoorClosed}
        title={t('AccessControlPage.title')}
        titleBadge={<CapabilityMaturityBadge capabilityId="access_control" />}
        description={t('AccessControlPage.description')}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('AccessControlPage.status.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <StatusItem icon={CheckCircle2} tone="success" title={t('AccessControlPage.status.records.title')}>
            <p>{t('AccessControlPage.status.records.body')}</p>
            <p className="mt-1">
              {t('AccessControlPage.status.records.where')}{' '}
              <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground">/api/v1/access</code>
            </p>
          </StatusItem>
          <StatusItem icon={XCircle} tone="destructive" title={t('AccessControlPage.status.doorControl.title')}>
            <p>{t('AccessControlPage.status.doorControl.body')}</p>
          </StatusItem>
          <StatusItem icon={Info} tone="muted" title={t('AccessControlPage.status.module.title')}>
            <p>{t('AccessControlPage.status.module.body')}</p>
          </StatusItem>
        </CardContent>
      </Card>
    </div>
  );
}
