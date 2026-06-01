// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Download,
  Monitor,
  Terminal,
  Apple,
  Copy,
  Check,
  Package,
  Shield,
  Wifi,
  HardDrive,
  ChevronDown,
  ChevronUp,
  Info,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { StatusBadge } from '@/components/ui/status-indicator';
import { InlineErrorBanner } from '@/components/ui/empty-state';
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert';
import {
  agentDownloadsApi,
  type PlatformInstallInfo,
} from '@/lib/api';
import { safeExternalUrl } from '@/lib/utils';

// Detect user OS
function detectOS(): string {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('win')) return 'windows';
  if (ua.includes('mac')) return 'macos';
  if (ua.includes('linux')) return 'linux';
  return 'windows';
}

// Format file size
function formatSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
}

// Platform icon mapping
function PlatformIcon({ platform, className }: { platform: string; className?: string }) {
  switch (platform) {
    case 'windows':
      return <Monitor className={className} />;
    case 'linux':
      return <Terminal className={className} />;
    case 'macos':
      return <Apple className={className} />;
    default:
      return <HardDrive className={className} />;
  }
}

// Copy button component
function CopyButton({ text }: { text: string }) {
  const { t } = useTranslation('agents');
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="p-1 rounded hover:bg-foreground/10 transition-colors"
      aria-label={copied ? t('DownloadsPage.copy.copied') : t('DownloadsPage.copy.copy')}
      title={t('DownloadsPage.copy.copy')}
    >
      {copied ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5 text-muted-foreground" />}
    </button>
  );
}

// Install instructions component
function InstallInstructions({ commands }: { commands: string[] }) {
  return (
    <div className="relative group">
      <pre className="bg-zinc-950 text-zinc-300 rounded-lg p-4 text-sm overflow-x-auto font-mono leading-relaxed">
        {commands.map((cmd, i) => (
          <div key={i} className={cmd.startsWith('#') ? 'text-zinc-500' : ''}>
            {cmd.startsWith('#') ? cmd : <><span className="text-green-400">$</span> {cmd}</>}
          </div>
        ))}
      </pre>
      <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <CopyButton text={commands.filter(c => !c.startsWith('#')).join('\n')} />
      </div>
    </div>
  );
}

// Platform download card
function PlatformCard({
  info,
  isDetected,
}: {
  info: PlatformInstallInfo;
  isDetected: boolean;
}) {
  const { t } = useTranslation('agents');
  const [expanded, setExpanded] = useState(isDetected);
  const hasDaemon = info.daemon !== null;
  const hasDesktop = info.desktop !== null;
  const hasAny = hasDaemon || hasDesktop;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
    >
      <Card className={`relative overflow-hidden ${isDetected ? 'ring-2 ring-primary' : ''}`}>
        {isDetected && (
          <div className="absolute top-0 left-0 right-0 h-1 bg-primary" />
        )}
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`p-2.5 rounded-lg ${isDetected ? 'bg-primary/10' : 'bg-muted'}`}>
                <PlatformIcon platform={info.platform} className={`w-5 h-5 ${isDetected ? 'text-primary' : 'text-muted-foreground'}`} />
              </div>
              <div>
                <CardTitle className="text-lg flex items-center gap-2">
                  {info.display_name}
                  {isDetected && (
                    <StatusBadge variant="success" hideIcon size="sm">{t('DownloadsPage.yourOs')}</StatusBadge>
                  )}
                </CardTitle>
                <CardDescription>
                  {hasDaemon && hasDesktop
                    ? t('DownloadsPage.availability.both')
                    : hasDaemon
                    ? t('DownloadsPage.availability.daemon')
                    : hasDesktop
                    ? t('DownloadsPage.availability.desktop')
                    : t('DownloadsPage.availability.none')}
                </CardDescription>
              </div>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {/* Download buttons */}
          <div className="flex flex-wrap gap-3">
            {hasDaemon && info.daemon && safeExternalUrl(info.daemon.download_url) && (
              <a href={safeExternalUrl(info.daemon.download_url)!} download>
                <Button size="lg" className="gap-2">
                  <Download className="w-4 h-4" />
                  {t('DownloadsPage.buttons.daemonAgent')}
                  <Badge variant="secondary" className="ml-1 text-xs">
                    v{info.daemon.version}
                  </Badge>
                </Button>
              </a>
            )}
            {hasDesktop && info.desktop && safeExternalUrl(info.desktop.download_url) && (
              <a href={safeExternalUrl(info.desktop.download_url)!} download>
                <Button variant="outline" size="lg" className="gap-2">
                  <Download className="w-4 h-4" />
                  {t('DownloadsPage.buttons.desktopApp')}
                  <Badge variant="secondary" className="ml-1 text-xs">
                    v{info.desktop.version}
                  </Badge>
                </Button>
              </a>
            )}
            {!hasAny && (
              <Button variant="outline" size="lg" disabled className="gap-2">
                <Package className="w-4 h-4" />
                {t('DownloadsPage.buttons.comingSoon')}
              </Button>
            )}
          </div>

          {/* File info */}
          {hasDaemon && info.daemon && (
            <div className="flex items-center gap-4 text-xs text-muted-foreground">
              <span>{formatSize(info.daemon.file_size)}</span>
              <span className="font-mono truncate max-w-[200px]" title={info.daemon.checksum_sha256}>
                SHA-256: {info.daemon.checksum_sha256.slice(0, 16)}...
              </span>
            </div>
          )}

          {/* Install instructions (expandable) */}
          {info.install_commands.length > 0 && (
            <div>
              <button
                onClick={() => setExpanded(!expanded)}
                className="flex items-center gap-1.5 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
              >
                {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                {t('DownloadsPage.installInstructions')}
              </button>
              {expanded && (
                <div className="mt-3">
                  <InstallInstructions commands={info.install_commands} />
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}

// Main Downloads Page
export function DownloadsPage() {
  const { t } = useTranslation('agents');
  const detectedOS = detectOS();

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['agent-downloads-page'],
    queryFn: async () => {
      const resp = await agentDownloadsApi.getPageData();
      return resp.data;
    },
  });

  // Sort platforms: detected OS first (spread to avoid mutating React Query cache)
  const sortedPlatforms = [...(data?.platforms ?? [])].sort((a, b) => {
    if (a.platform === detectedOS) return -1;
    if (b.platform === detectedOS) return 1;
    return 0;
  });

  // If no releases exist yet, show all platforms with empty state
  const allPlatforms: PlatformInstallInfo[] = sortedPlatforms.length > 0
    ? sortedPlatforms
    : [
        {
          platform: 'windows',
          display_name: 'Windows',
          icon: 'windows',
          daemon: null,
          desktop: null,
          install_commands: [
            '# Download and run the MSI installer, then:',
            'freesdn-agent register --server https://your-freesdn.com --name "Office Agent"',
            '# Approve the agent in FreeSDN UI \u2192 Agents',
            'freesdn-agent daemon',
          ],
        },
        {
          platform: 'linux',
          display_name: 'Linux (Debian/Ubuntu)',
          icon: 'linux',
          daemon: null,
          desktop: null,
          install_commands: [
            'sudo dpkg -i freesdn-agent_*.deb',
            'sudo freesdn-agent register --server https://your-freesdn.com --name "DC Agent"',
            '# Approve in FreeSDN UI \u2192 Agents',
            'sudo systemctl enable --now freesdn-agent',
          ],
        },
        {
          platform: 'macos',
          display_name: 'macOS',
          icon: 'apple',
          daemon: null,
          desktop: null,
          install_commands: [
            'sudo installer -pkg freesdn-agent-*.pkg -target /',
            'sudo freesdn-agent register --server https://your-freesdn.com --name "Mac Agent"',
            '# Approve in FreeSDN UI \u2192 Agents',
            'sudo launchctl load -w /Library/LaunchDaemons/com.freesdn.agent.plist',
          ],
        },
      ].sort((a, b) => (a.platform === detectedOS ? -1 : b.platform === detectedOS ? 1 : 0));

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Download}
        title={t('DownloadsPage.header.title')}
        description={t('DownloadsPage.header.description')}
        onRefresh={() => refetch()}
        refreshing={isFetching}
      />

      {isError && (
        <InlineErrorBanner onRetry={() => refetch()}>
          {t('DownloadsPage.error.loadFailed')}
        </InlineErrorBanner>
      )}

      {/* Info banner */}
      <Alert>
        <Info className="h-4 w-4" />
        <AlertTitle>{t('DownloadsPage.infoBanner.title')}</AlertTitle>
        <AlertDescription>
          <strong>{t('DownloadsPage.buttons.daemonAgent')}</strong> · {t('DownloadsPage.infoBanner.daemonDesc')}
          <br />
          <strong>{t('DownloadsPage.buttons.desktopApp')}</strong> · {t('DownloadsPage.infoBanner.desktopDesc')}
        </AlertDescription>
      </Alert>

      {/* Feature highlights */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          {
            icon: Wifi,
            iconClass: 'bg-info/10 text-info',
            title: t('DownloadsPage.features.protocols.title'),
            desc: t('DownloadsPage.features.protocols.desc'),
          },
          {
            icon: Shield,
            iconClass: 'bg-success/10 text-success',
            title: t('DownloadsPage.features.secure.title'),
            desc: t('DownloadsPage.features.secure.desc'),
          },
          {
            icon: Terminal,
            iconClass: 'bg-purple-500/10 text-purple-600 dark:text-purple-400',
            title: t('DownloadsPage.features.multiSite.title'),
            desc: t('DownloadsPage.features.multiSite.desc'),
          },
        ].map(({ icon: Icon, iconClass, title, desc }) => (
          <Card key={title}>
            <CardContent noOffset>
              <div className="flex items-center gap-3 mb-2">
                <div className={`flex h-9 w-9 items-center justify-center rounded-lg ${iconClass}`}>
                  <Icon className="w-4 h-4" />
                </div>
                <h3 className="font-semibold">{title}</h3>
              </div>
              <p className="text-sm text-muted-foreground">{desc}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Platform downloads */}
      {isLoading ? (
        <div className="grid grid-cols-1 gap-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-48 w-full rounded-xl" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {allPlatforms.map((info) => (
            <PlatformCard
              key={info.platform}
              info={info}
              isDetected={info.platform === detectedOS}
            />
          ))}
        </div>
      )}

      {/* Quick start flow */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">{t('DownloadsPage.quickStart.title')}</CardTitle>
          <CardDescription>{t('DownloadsPage.quickStart.subtitle')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {[
              {
                step: 1,
                title: t('DownloadsPage.quickStart.steps.download.title'),
                desc: t('DownloadsPage.quickStart.steps.download.desc'),
              },
              {
                step: 2,
                title: t('DownloadsPage.quickStart.steps.register.title'),
                desc: t('DownloadsPage.quickStart.steps.register.desc'),
              },
              {
                step: 3,
                title: t('DownloadsPage.quickStart.steps.approve.title'),
                desc: t('DownloadsPage.quickStart.steps.approve.desc'),
              },
              {
                step: 4,
                title: t('DownloadsPage.quickStart.steps.connect.title'),
                desc: t('DownloadsPage.quickStart.steps.connect.desc'),
              },
            ].map(({ step, title, desc }) => (
              <div key={step} className="flex gap-3">
                <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center text-sm font-bold text-primary">
                  {step}
                </div>
                <div>
                  <h4 className="font-semibold text-sm">{title}</h4>
                  <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Version info */}
      {data && (
        <div className="text-xs text-muted-foreground text-center">
          {data.latest_version && <>{t('DownloadsPage.versionInfo.latest', { version: data.latest_version })} &middot; </>}
          {t('DownloadsPage.versionInfo.server', { version: data.server_version })}
        </div>
      )}
    </div>
  );
}

export default DownloadsPage;
