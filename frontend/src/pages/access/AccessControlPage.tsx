// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Access Control Management Page
 *
 * Physical access control · coming in a future release.
 */

import { useTranslation } from 'react-i18next';
import { Lock, DoorOpen, CreditCard, History } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { PageHeader } from '@/components/layout';

const PLANNED_FEATURES = [
  { icon: DoorOpen, titleKey: 'features.doorManagement.title', descKey: 'features.doorManagement.desc' },
  { icon: CreditCard, titleKey: 'features.cardholders.title', descKey: 'features.cardholders.desc' },
  { icon: History, titleKey: 'features.eventHistory.title', descKey: 'features.eventHistory.desc' },
  { icon: Lock, titleKey: 'features.accessPolicies.title', descKey: 'features.accessPolicies.desc' },
];

export default function AccessControlPage() {
  const { t } = useTranslation('access');

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('AccessControlPage.title')}
        description={t('AccessControlPage.description')}
      />

      <div className="flex flex-col items-center justify-center py-16 text-center">
        <div className="rounded-full bg-muted p-4 mb-4">
          <Lock className="h-8 w-8 text-muted-foreground" />
        </div>
        <h2 className="text-xl font-semibold mb-2">{t('AccessControlPage.comingSoon')}</h2>
        <p className="text-muted-foreground max-w-md mb-10">
          {t('AccessControlPage.comingSoonDescription')}
        </p>

        <div className="grid gap-4 sm:grid-cols-2 max-w-2xl w-full">
          {PLANNED_FEATURES.map((f) => (
            <Card key={f.titleKey} className="text-left">
              <CardContent noOffset className="flex items-start gap-3">
                <f.icon className="h-5 w-5 text-muted-foreground shrink-0 mt-0.5" />
                <div>
                  <p className="font-medium text-sm">{t(`AccessControlPage.${f.titleKey}`)}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{t(`AccessControlPage.${f.descKey}`)}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
