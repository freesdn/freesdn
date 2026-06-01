// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { ExternalLink } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { api } from '@/lib/api';

interface PlatformInfo {
  platform?: { app_version?: string };
}

const DOCS_URL = 'https://docs.freesdn.org';
const REPO_URL = 'https://github.com/freesdn/freesdn';

// Per-vendor trademark attribution. These are proper nouns (brand + legal owner)
// and are intentionally NOT translated; only the surrounding prose is i18n'd.
const TRADEMARK_ATTRIBUTIONS: ReadonlyArray<{ mark: string; owner: string }> = [
  { mark: 'TP-Link, Omada', owner: 'TP-Link Systems Inc.' },
  { mark: 'Ubiquiti, UniFi, UniFi Protect', owner: 'Ubiquiti Inc.' },
  { mark: 'Cisco, Meraki', owner: 'Cisco Systems, Inc.' },
  { mark: 'MikroTik, RouterOS', owner: 'Mikrotikls SIA' },
  { mark: 'OpenWrt', owner: 'the OpenWrt project / Software Freedom Conservancy' },
  { mark: 'OPNsense', owner: 'Deciso B.V.' },
  { mark: 'pfSense', owner: 'Netgate (Rubicon Communications, LLC)' },
  { mark: 'Proxmox', owner: 'Proxmox Server Solutions GmbH' },
  { mark: 'FreePBX', owner: 'Sangoma Technologies Corporation' },
  { mark: 'Grandstream', owner: 'Grandstream Networks, Inc.' },
  { mark: 'Hikvision', owner: 'Hangzhou Hikvision Digital Technology Co., Ltd.' },
  { mark: 'TrueNAS', owner: 'iXsystems, Inc.' },
  { mark: 'ONVIF', owner: 'the ONVIF organization' },
];

/**
 * About FreeSDN, rendered as the Settings > About tab (/settings/about).
 * Surfaces version + license and a detailed third-party trademark /
 * non-affiliation notice with per-vendor attribution.
 */
export function AboutSettingsTab() {
  const { t } = useTranslation('about');

  // Shares the System-tab query key so the cached app_version is reused.
  const { data } = useQuery<PlatformInfo>({
    queryKey: ['infra-health'],
    queryFn: () => api.get('/enterprise/health/infrastructure').then((r) => r.data),
    retry: 1,
    staleTime: 60_000,
  });
  const version = data?.platform?.app_version ?? '26.06.1';

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>{t('AboutPage.platform.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between gap-4">
            <span className="text-sm text-muted-foreground">{t('AboutPage.platform.version')}</span>
            <Badge variant="secondary">{version}</Badge>
          </div>
          <div className="flex items-center justify-between gap-4">
            <span className="text-sm text-muted-foreground">{t('AboutPage.platform.license')}</span>
            <span className="text-sm font-medium">AGPL-3.0-only</span>
          </div>
          <div className="flex items-center justify-between gap-4">
            <span className="text-sm text-muted-foreground">
              {t('AboutPage.platform.documentation')}
            </span>
            <a
              href={DOCS_URL}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1 text-sm text-primary hover:underline"
            >
              docs.freesdn.org
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
          <div className="flex items-center justify-between gap-4">
            <span className="text-sm text-muted-foreground">
              {t('AboutPage.platform.sourceCode')}
            </span>
            <a
              href={REPO_URL}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1 text-sm text-primary hover:underline"
            >
              github.com/freesdn/freesdn
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('AboutPage.trademarks.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <p className="text-sm leading-relaxed text-muted-foreground">
            {t('AboutPage.trademarks.intro')}
          </p>
          <p className="text-sm leading-relaxed text-muted-foreground">
            {t('AboutPage.trademarks.independence')}
          </p>

          <div>
            <h4 className="mb-2 text-sm font-semibold text-foreground">
              {t('AboutPage.trademarks.attributionTitle')}
            </h4>
            <dl className="divide-y rounded-lg border">
              {TRADEMARK_ATTRIBUTIONS.map((row) => (
                <div
                  key={row.mark}
                  className="flex flex-col gap-0.5 px-4 py-2.5 sm:flex-row sm:items-baseline sm:justify-between sm:gap-4"
                >
                  <dt className="text-sm font-medium text-foreground">{row.mark}</dt>
                  <dd className="text-sm text-muted-foreground sm:text-right">{row.owner}</dd>
                </div>
              ))}
            </dl>
          </div>

          <p className="text-xs leading-relaxed text-muted-foreground">
            {t('AboutPage.trademarks.closing')}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
