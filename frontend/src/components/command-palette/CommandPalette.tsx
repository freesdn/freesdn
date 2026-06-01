// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Command Palette (⌘K)
 *
 * Auto-generated from the same nav-data the Sidebar uses, so every page in the
 * sidebar is reachable here. Recent routes appear at the top when the search
 * input is empty; theme + sign-out + a small set of real action commands round
 * it out. No more hardcoded broken routes.
 */

import * as React from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useLocation } from 'react-router-dom';
import { useToast } from '@/hooks/use-toast';
import { controllersApi } from '@/lib/api/controllers';
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from '@/components/ui/command';
import {
  Search,
  RefreshCw,
  Moon,
  Sun,
  Laptop,
  LogOut,
  HelpCircle,
  FileText,
  Keyboard,
  Clock,
  type LucideIcon,
} from 'lucide-react';
import { useUIStore } from '@/stores';
import {
  useUIPaletteStore,
  useRecentRoutes,
} from '@/stores/sidebarStore';
import { useAuthStore } from '@/stores/authStore';
import { useModuleStore } from '@/stores/moduleStore';
import { useSiteStore } from '@/stores/siteStore';
import { buildSections, flattenItems, type NavItem } from '@/lib/nav-data';

interface PaletteCommand {
  id: string;
  label: string;
  icon: LucideIcon;
  shortcut?: string;
  action: () => void | Promise<void>;
  /** Extra search keywords */
  keywords?: string[];
  /** Group heading for grouping */
  group: string;
}

interface CommandPaletteProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const [internalOpen, setInternalOpen] = React.useState(false);
  const [search, setSearch] = React.useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();
  const { t } = useTranslation('common');

  const isOpen = open ?? internalOpen;
  const setIsOpen = onOpenChange ?? setInternalOpen;

  const setTheme = useUIStore((s) => s.setTheme);
  const { logout } = useAuthStore();
  const { isModuleEnabled } = useModuleStore();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const isInSite = selectedSiteId !== null;
  const recentRoutes = useRecentRoutes();

  // Global keyboard shortcut (⌘K / Ctrl+K)
  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setIsOpen(!isOpen);
      }
    };

    document.addEventListener('keydown', down);
    return () => document.removeEventListener('keydown', down);
  }, [isOpen, setIsOpen]);

  const runCommand = React.useCallback(
    (command: () => void | Promise<void>) => {
      setIsOpen(false);
      setSearch('');
      void command();
    },
    [setIsOpen],
  );

  const syncAllControllers = React.useCallback(async () => {
    try {
      const response = await controllersApi.getAll();
      const controllers = Array.isArray(response.data)
        ? response.data.filter(
            (controller): controller is { id: string } =>
              typeof controller === 'object' &&
              controller !== null &&
              'id' in controller &&
              typeof controller.id === 'string',
          )
        : [];

      if (controllers.length === 0) {
        toast({
          title: t('CommandPalette.sync.none.title'),
          description: t('CommandPalette.sync.none.description'),
        });
        navigate('/controllers');
        return;
      }

      const results = await Promise.allSettled(
        controllers.map((controller) => controllersApi.sync(controller.id)),
      );
      const succeeded = results.filter((r) => r.status === 'fulfilled').length;
      const failed = results.length - succeeded;

      if (failed === 0) {
        toast({
          title: t('CommandPalette.sync.started.title'),
          description: t('CommandPalette.sync.started.description', { count: succeeded }),
        });
      } else if (succeeded === 0) {
        toast({
          title: t('CommandPalette.sync.failed.title'),
          description: t('CommandPalette.sync.failed.description'),
          variant: 'destructive',
        });
      } else {
        toast({
          title: t('CommandPalette.sync.partial.title'),
          description: t('CommandPalette.sync.partial.description', {
            succeeded,
            failed,
          }),
          variant: 'destructive',
        });
      }

      navigate('/controllers');
    } catch (error) {
      toast({
        title: t('CommandPalette.sync.failed.title'),
        description:
          error instanceof Error ? error.message : t('CommandPalette.sync.error'),
        variant: 'destructive',
      });
    }
  }, [navigate, toast, t]);

  // ── Auto-generate navigation commands from nav-data ──
  const navigationCommands: PaletteCommand[] = React.useMemo(() => {
    const sections = buildSections(0, t);
    const items = flattenItems(sections);

    return items
      .filter((item: NavItem) => {
        // Apply module gating
        if (item.moduleId && !isModuleEnabled(item.moduleId)) return false;
        // Apply site visibility filtering
        if (item.siteVisibility === 'global' && isInSite) return false;
        if (item.siteVisibility === 'site' && !isInSite) return false;
        return true;
      })
      .map((item: NavItem) => ({
        id: `nav-${item.href}`,
        label: item.name,
        icon: item.icon,
        keywords: item.keywords,
        group: item.sectionTitle ?? 'Navigation',
        action: () => navigate(item.href),
      }));
  }, [navigate, isModuleEnabled, isInSite, t]);

  // ── Action commands (real handlers only) ──
  const actionCommands: PaletteCommand[] = React.useMemo(
    () => [
      {
        id: 'action-discovery',
        label: t('CommandPalette.actions.discovery'),
        icon: Search,
        action: () => navigate('/discovery'),
        keywords: ['scan', 'find', 'detect'],
        group: 'Actions',
      },
      {
        id: 'action-sync',
        label: t('CommandPalette.actions.syncAll'),
        icon: RefreshCw,
        shortcut: '⌘ R',
        action: syncAllControllers,
        keywords: ['refresh', 'update'],
        group: 'Actions',
      },
    ],
    [navigate, syncAllControllers, t],
  );

  // ── Theme commands (use UIStore, not localStorage hack) ──
  const themeCommands: PaletteCommand[] = React.useMemo(
    () => [
      {
        id: 'theme-light',
        label: t('CommandPalette.theme.light'),
        icon: Sun,
        action: () => setTheme('light'),
        keywords: ['mode', 'bright', 'day'],
        group: 'Theme',
      },
      {
        id: 'theme-dark',
        label: t('CommandPalette.theme.dark'),
        icon: Moon,
        action: () => setTheme('dark'),
        keywords: ['mode', 'night'],
        group: 'Theme',
      },
      {
        id: 'theme-system',
        label: t('CommandPalette.theme.system'),
        icon: Laptop,
        action: () => setTheme('system'),
        keywords: ['auto', 'os'],
        group: 'Theme',
      },
    ],
    [setTheme, t],
  );

  // ── Help commands ──
  const helpCommands: PaletteCommand[] = React.useMemo(
    () => [
      {
        id: 'help-docs',
        label: t('CommandPalette.help.docs'),
        icon: FileText,
        action: () => {
          window.open('/docs', '_blank', 'noopener,noreferrer');
        },
        keywords: ['guide', 'manual'],
        group: 'Help',
      },
      {
        id: 'help-shortcuts',
        label: t('CommandPalette.help.shortcuts'),
        icon: Keyboard,
        shortcut: '?',
        action: () => useUIPaletteStore.getState().openShortcuts(),
        keywords: ['hotkeys', 'bindings'],
        group: 'Help',
      },
      {
        id: 'help-support',
        label: t('CommandPalette.help.support'),
        icon: HelpCircle,
        action: () => {
          window.open('https://freesdn.org/support', '_blank', 'noopener,noreferrer');
        },
        keywords: ['contact', 'help'],
        group: 'Help',
      },
      {
        id: 'help-logout',
        label: t('CommandPalette.help.logout'),
        icon: LogOut,
        action: async () => {
          await logout();
          navigate('/login');
        },
        keywords: ['logout', 'exit'],
        group: 'Help',
      },
    ],
    [logout, navigate, t],
  );

  // ── Recent commands (only when search is empty) ──
  const recentCommands: PaletteCommand[] = React.useMemo(() => {
    if (search.trim()) return [];
    return recentRoutes
      .filter((r) => r.path !== location.pathname)
      .slice(0, 5)
      .map((r) => ({
        id: `recent-${r.path}`,
        label: r.label,
        icon: Clock,
        action: () => navigate(r.path),
        group: 'Recent',
        keywords: ['recent', 'recently visited'],
      }));
  }, [recentRoutes, location.pathname, search, navigate]);

  // ── Group navigation commands by section title ──
  const groupedNav = React.useMemo(() => {
    const groups = new Map<string, PaletteCommand[]>();
    for (const cmd of navigationCommands) {
      const list = groups.get(cmd.group) ?? [];
      list.push(cmd);
      groups.set(cmd.group, list);
    }
    return Array.from(groups.entries());
  }, [navigationCommands]);

  const renderCommand = (cmd: PaletteCommand) => {
    const Icon = cmd.icon;
    return (
      <CommandItem
        key={cmd.id}
        value={`${cmd.label} ${cmd.keywords?.join(' ') ?? ''}`}
        onSelect={() => runCommand(cmd.action)}
      >
        <Icon className="mr-2 h-4 w-4" />
        <span>{cmd.label}</span>
        {cmd.shortcut && <CommandShortcut>{cmd.shortcut}</CommandShortcut>}
      </CommandItem>
    );
  };

  return (
    <CommandDialog open={isOpen} onOpenChange={setIsOpen}>
      <CommandInput
        placeholder={t('CommandPalette.searchPlaceholder')}
        value={search}
        onValueChange={setSearch}
      />
      <CommandList>
        <CommandEmpty>{t('CommandPalette.noResults')}</CommandEmpty>

        {/* Recent (empty-search only) */}
        {recentCommands.length > 0 && (
          <>
            <CommandGroup heading={t('CommandPalette.groups.recent')}>
              {recentCommands.map(renderCommand)}
            </CommandGroup>
            <CommandSeparator />
          </>
        )}

        {/* Navigation grouped by section */}
        {groupedNav.map(([heading, cmds], idx) => (
          <React.Fragment key={heading}>
            <CommandGroup heading={heading}>
              {cmds.map(renderCommand)}
            </CommandGroup>
            {idx < groupedNav.length - 1 && <CommandSeparator />}
          </React.Fragment>
        ))}

        <CommandSeparator />

        <CommandGroup heading={t('CommandPalette.groups.actions')}>
          {actionCommands.map(renderCommand)}
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading={t('CommandPalette.groups.theme')}>
          {themeCommands.map(renderCommand)}
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading={t('CommandPalette.groups.help')}>
          {helpCommands.map(renderCommand)}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}

export default CommandPalette;
