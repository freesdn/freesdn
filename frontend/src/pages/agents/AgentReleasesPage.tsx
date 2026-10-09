// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Private replacement page. Collapsing a section never unmounts its retained
 * intent. Server authorization and captured workflow context remain required. */
import { useTranslation } from 'react-i18next';
import { Package } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { ReleaseCataloguePanel } from '@/components/agents/ReleaseCataloguePanel';
import { ReleasePublicationWorkflow } from '@/components/agents/ReleasePublicationWorkflow';
import { ReleaseDeletionWorkflow } from '@/components/agents/ReleaseDeletionWorkflow';
import { ReleasePromotionWorkflow } from '@/components/agents/ReleasePromotionWorkflow';

export function AgentReleasesPage() {
  const { t } = useTranslation('agents');
  return <div className="space-y-6">
    <PageHeader title={t('AgentReleasesWorkspace.title')} description={t('AgentReleasesWorkspace.description')} icon={Package} />
    <p>{t('AgentReleasesWorkspace.retention')}</p>
    <ReleaseCataloguePanel />
    <details data-release-workflow="publication" className="rounded border p-4">
      <summary className="cursor-pointer font-semibold">{t('AgentReleasesWorkspace.publication')}</summary>
      <div className="mt-4"><ReleasePublicationWorkflow /></div>
    </details>
    <details data-release-workflow="promotion" className="rounded border p-4">
      <summary className="cursor-pointer font-semibold">{t('AgentReleasesWorkspace.promotion')}</summary>
      <div className="mt-4"><ReleasePromotionWorkflow /></div>
    </details>
    <details data-release-workflow="deletion" className="rounded border p-4">
      <summary className="cursor-pointer font-semibold">{t('AgentReleasesWorkspace.deletion')}</summary>
      <div className="mt-4"><ReleaseDeletionWorkflow /></div>
    </details>
  </div>;
}
