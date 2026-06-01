// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Bell,
  User,
  Wifi,
  WifiOff,
  Settings,
  LogOut,
  Key,
  Shield,
  Mail,
  Trash2,
  AlertCircle,
  Info,
  X,
  RefreshCw,
  Loader2,
  AlertTriangle,
  Search,
  Menu,
} from 'lucide-react';
import { useUIStore } from '../../stores';
import { useUIPaletteStore } from '../../stores/sidebarStore';
import { isMacPlatform } from '../../hooks/useGlobalShortcuts';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TooltipProvider,
} from '../ui/tooltip';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { ThemeToggle } from '../ui/theme-toggle';
import { LanguageSwitcher } from '../ui/language-switcher';
import { useAuthStore } from '../../stores/authStore';
import { api, notificationApi } from '../../lib/api';
import { SiteSelector } from './SiteSelector';

// NOTE: The backend returns these field names, ``body`` (not ``message``),
// ``read`` (not ``is_read``), no ``icon``. The shared
// ``InAppNotification`` type in ``lib/api/types.ts`` was historically
// wrong (modeled on an early frontend-only schema). We use a local
// interface here so TopBar matches what the BE actually sends. When
// the shared type is fixed in a follow-up, this can be removed.
interface BellNotification {
  id: string;
  title: string;
  body: string;
  category: string;
  severity: string;
  action_url?: string | null;
  read: boolean;
  created_at: string;
}

interface TopBarProps {
  connectionStatus: 'online' | 'offline' | 'connecting';
}

interface TopBarProps {
  connectionStatus: 'online' | 'offline' | 'connecting';
}

// Severity to icon mapping (semantic tokens)
const getSeverityIcon = (severity: string) => {
  switch (severity) {
    case 'critical':
    case 'high':
      return <AlertCircle className="h-4 w-4 text-destructive" />;
    case 'medium':
      return <AlertTriangle className="h-4 w-4 text-warning" />;
    case 'low':
      return <Info className="h-4 w-4 text-info" />;
    default:
      return <Info className="h-4 w-4 text-muted-foreground" />;
  }
};

// Severity to dot color (semantic tokens)
const getSeverityBadgeColor = (severity: string) => {
  switch (severity) {
    case 'critical':
      return 'bg-destructive';
    case 'high':
      return 'bg-destructive/80';
    case 'medium':
      return 'bg-warning';
    case 'low':
      return 'bg-info';
    default:
      return 'bg-muted-foreground';
  }
};

export function TopBar({ connectionStatus }: TopBarProps) {
  const { t } = useTranslation('common');
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user, logout } = useAuthStore();
  const toggleSidebarMobile = useUIStore((s) => s.toggleSidebarMobile);
  const openCommandPalette = useUIPaletteStore((s) => s.toggleCommandPalette);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfileDialog, setShowProfileDialog] = useState(false);
  const [showChangeEmailDialog, setShowChangeEmailDialog] = useState(false);
  const [showChangePasswordDialog, setShowChangePasswordDialog] = useState(false);
  const [showDeleteAccountDialog, setShowDeleteAccountDialog] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  
  // Form states
  const [newEmail, setNewEmail] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [deleteConfirmation, setDeleteConfirmation] = useState('');

  // Active vs Archive (dismissed) toggle. Backend interprets
  // ``include_dismissed`` as the Archive filter.
  const [showArchive, setShowArchive] = useState(false);
  // Offset-pagination, bumped by "Load more". Reset to 0 whenever the
  // tab changes so we don't paginate past the wrong dataset.
  const [pageOffset, setPageOffset] = useState(0);
  const pageSize = 20;

  // Fetch in-app notifications
  const { data: notificationsData } = useQuery({
    queryKey: ['in-app-notifications', showArchive, pageOffset],
    queryFn: async () => {
      const response = await notificationApi.getInAppNotifications(
        false,
        pageSize,
        pageOffset,
        showArchive,
      );
      return response.data;
    },
    refetchInterval: 30000, // Refetch every 30 seconds
    enabled: !!user,
  });

  // Fetch unread count
  const { data: unreadCountData } = useQuery({
    queryKey: ['notification-unread-count'],
    queryFn: async () => {
      const response = await notificationApi.getUnreadCount();
      return response.data;
    },
    refetchInterval: 10000, // Refetch every 10 seconds
    enabled: !!user,
  });

  // Cast to local BE-correct schema (see ``BellNotification`` comment).
  const notifications = useMemo<BellNotification[]>(
    () => (notificationsData?.items ?? []) as unknown as BellNotification[],
    [notificationsData?.items],
  );
  // Prefer the envelope's unread_count (returned by the same query) so
  // we stay in sync after mark-all-read without waiting for the
  // separate badge query to refetch. Fall back to the dedicated badge
  // query when the envelope is still loading.
  const unreadCount =
    notificationsData?.unread_count ?? unreadCountData?.total ?? 0;
  const totalForTab = notificationsData?.total ?? 0;
  const hasMore = pageOffset + notifications.length < totalForTab;

  // Mark notifications as read/dismissed
  const markMutation = useMutation({
    mutationFn: async ({ ids, action }: { ids: string[]; action: 'read' | 'dismiss' }) => {
      const response = await notificationApi.markNotifications(ids, action);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['in-app-notifications'] });
      queryClient.invalidateQueries({ queryKey: ['notification-unread-count'] });
    },
  });

  // Mark all as read
  const markAllReadMutation = useMutation({
    mutationFn: async () => {
      const response = await notificationApi.markAllAsRead();
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['in-app-notifications'] });
      queryClient.invalidateQueries({ queryKey: ['notification-unread-count'] });
    },
  });

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const markAsRead = useCallback((id: string) => {
    markMutation.mutate({ ids: [id], action: 'read' });
  }, [markMutation]);

  const markAllAsRead = useCallback(() => {
    markAllReadMutation.mutate();
  }, [markAllReadMutation]);

  const dismissNotification = useCallback((id: string) => {
    markMutation.mutate({ ids: [id], action: 'dismiss' });
  }, [markMutation]);

  const clearAllNotifications = useCallback(() => {
    const allIds = notifications.map(n => n.id);
    if (allIds.length > 0) {
      markMutation.mutate({ ids: allIds, action: 'dismiss' });
    }
    setShowNotifications(false);
  }, [notifications, markMutation]);

  const handleChangeEmail = async () => {
    if (!newEmail) {
      setError(t('TopBar.errors.enterNewEmail'));
      return;
    }
    
    setIsLoading(true);
    setError(null);
    
    try {
      await api.patch(`/users/${user?.id}`, { email: newEmail });
      setSuccess(t('TopBar.success.emailUpdated'));
      setNewEmail('');
      setTimeout(() => {
        setShowChangeEmailDialog(false);
        setSuccess(null);
      }, 2000);
    } catch (err: unknown) {
      const axiosErr = err as import('axios').AxiosError<{ detail?: string }>;
      setError(axiosErr.response?.data?.detail || t('TopBar.errors.updateEmailFailed'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleChangePassword = async () => {
    if (!currentPassword || !newPassword || !confirmPassword) {
      setError(t('TopBar.errors.fillAllFields'));
      return;
    }

    if (newPassword !== confirmPassword) {
      setError(t('TopBar.errors.passwordsDoNotMatch'));
      return;
    }

    if (newPassword.length < 8) {
      setError(t('TopBar.errors.passwordTooShort'));
      return;
    }
    
    setIsLoading(true);
    setError(null);
    
    try {
      await api.post('/auth/password', {
        current_password: currentPassword,
        new_password: newPassword,
      });
      setSuccess(t('TopBar.success.passwordChanged'));
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => {
        setShowChangePasswordDialog(false);
        setSuccess(null);
      }, 2000);
    } catch (err: unknown) {
      const axiosErr = err as import('axios').AxiosError<{ detail?: string }>;
      setError(axiosErr.response?.data?.detail || t('TopBar.errors.changePasswordFailed'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteAccount = async () => {
    if (deleteConfirmation !== 'DELETE') {
      setError(t('TopBar.errors.typeDeleteToConfirm'));
      return;
    }
    
    setIsLoading(true);
    setError(null);
    
    try {
      await api.delete(`/users/${user?.id}`);
      await logout();
      navigate('/login');
    } catch (err: unknown) {
      const axiosErr = err as import('axios').AxiosError<{ detail?: string }>;
      setError(axiosErr.response?.data?.detail || t('TopBar.errors.deleteAccountFailed'));
      setIsLoading(false);
    }
  };

  const getNotificationIcon = (notification: BellNotification) => {
    // NOTE: BE schema has no ``icon`` field; we infer the icon purely
    // from severity. The previous code branched on ``notification.icon``
    // which was always undefined.
    return getSeverityIcon(notification.severity);
  };

  const formatTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
    if (seconds < 60) return t('TopBar.time.justNow');
    if (seconds < 3600) return t('TopBar.time.minutesAgo', { n: Math.floor(seconds / 60) });
    if (seconds < 86400) return t('TopBar.time.hoursAgo', { n: Math.floor(seconds / 3600) });
    return t('TopBar.time.daysAgo', { n: Math.floor(seconds / 86400) });
  };

  const resetDialogState = () => {
    setError(null);
    setSuccess(null);
    setNewEmail('');
    setCurrentPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setDeleteConfirmation('');
  };

  return (
    <header className="h-16 border-b border-border bg-background/95 backdrop-blur-sm sticky top-0 z-30">
      <div className="flex h-full items-center justify-between gap-2 sm:gap-4 px-3 sm:px-6">
        {/* Left: Mobile hamburger + Site selector */}
        <div className="flex items-center gap-2">
          <button
            onClick={toggleSidebarMobile}
            className="lg:hidden inline-flex h-11 w-11 items-center justify-center rounded-lg text-muted-foreground hover:text-foreground hover:bg-secondary transition-all"
            aria-label={t('TopBar.aria.openMenu')}
          >
            <Menu className="h-5 w-5" />
          </button>
          <SiteSelector />
        </div>

        {/* Center: Global search trigger (⌘K / Ctrl+K) */}
        <div className="flex-1 max-w-md hidden md:block">
          <button
            type="button"
            onClick={openCommandPalette}
            className="w-full h-9 px-3 inline-flex items-center gap-2 rounded-md border border-border bg-muted/50 text-sm text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
            aria-label={t('TopBar.aria.openCommandPalette')}
          >
            <Search className="h-3.5 w-3.5 flex-shrink-0" />
            <span className="flex-1 text-left truncate">{t('TopBar.search.placeholder')}</span>
            <kbd className="inline-flex items-center gap-0.5 h-5 px-1.5 rounded border border-border bg-background font-mono text-[10px] font-medium shrink-0">
              {isMacPlatform ? '⌘ K' : 'Ctrl K'}
            </kbd>
          </button>
        </div>

        {/* Right side actions */}
        <div className="flex items-center gap-1 sm:gap-3">
          {/* Connection Status · hidden on the smallest screens to free up gutter */}
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  className={`hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-colors ${
                    connectionStatus === 'online'
                      ? 'bg-success/10 border-success/30 text-success'
                      : connectionStatus === 'connecting'
                      ? 'bg-warning/10 border-warning/30 text-warning'
                      : 'bg-destructive/10 border-destructive/30 text-destructive'
                  }`}
                  onClick={() => {
                    if (connectionStatus === 'offline') {
                      window.location.reload();
                    }
                  }}
                  aria-label={t('TopBar.connection.statusAria', {
                    status: t(`TopBar.connection.${connectionStatus}`),
                  })}
                >
                  {connectionStatus === 'online' ? (
                    <Wifi className="h-4 w-4" />
                  ) : connectionStatus === 'connecting' ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <WifiOff className="h-4 w-4" />
                  )}
                  <span className="text-xs font-medium">
                    {connectionStatus === 'online' && t('TopBar.connection.connected')}
                    {connectionStatus === 'offline' && t('TopBar.connection.disconnected')}
                    {connectionStatus === 'connecting' && t('TopBar.connection.connectingLabel')}
                  </span>
                  {connectionStatus === 'offline' && (
                    <RefreshCw className="h-3 w-3 ml-1" />
                  )}
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom">
                {connectionStatus === 'online'
                  ? t('TopBar.connection.tooltipOnline')
                  : connectionStatus === 'connecting'
                  ? t('TopBar.connection.tooltipConnecting')
                  : t('TopBar.connection.tooltipOffline')}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>

          {/* Language Switcher */}
          <LanguageSwitcher />

          {/* Theme Toggle */}
          <ThemeToggle variant="icon" />

          {/* Camera Event Alerts · consolidated into main notification bell */}

          {/* Notifications */}
          <DropdownMenu open={showNotifications} onOpenChange={setShowNotifications}>
            <DropdownMenuTrigger asChild>
              <button
                className="relative p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-secondary transition-all"
                aria-label={unreadCount > 0 ? t('TopBar.notifications.ariaWithCount', { n: unreadCount }) : t('TopBar.notifications.title')}
              >
                <Bell className="h-5 w-5" />
                {unreadCount > 0 && (
                  <span className="absolute top-1 right-1 flex h-4 w-4 items-center justify-center rounded-full bg-destructive text-[9px] font-semibold text-destructive-foreground">
                    {unreadCount > 9 ? '9+' : unreadCount}
                  </span>
                )}
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80">
              <div className="flex items-center justify-between px-3 py-2 border-b">
                <span className="font-semibold">{t('TopBar.notifications.title')}</span>
                {notifications.length > 0 && !showArchive && (
                  <div className="flex items-center gap-2">
                    <button
                      onClick={markAllAsRead}
                      className="text-xs text-muted-foreground hover:text-foreground"
                    >
                      {t('TopBar.notifications.markAllRead')}
                    </button>
                    <button
                      onClick={clearAllNotifications}
                      className="text-xs text-muted-foreground hover:text-destructive"
                    >
                      {t('TopBar.notifications.clearAll')}
                    </button>
                  </div>
                )}
              </div>
              {/* Active / Archive tab toggle. Switching tabs resets the
                  paging cursor so we don't show past the end of the
                  dataset. */}
              <div className="flex border-b text-xs">
                <button
                  type="button"
                  className={`flex-1 px-3 py-2 transition-colors ${
                    !showArchive
                      ? 'border-b-2 border-primary text-foreground font-medium'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                  onClick={() => {
                    setShowArchive(false);
                    setPageOffset(0);
                  }}
                  aria-pressed={!showArchive}
                >
                  {t('TopBar.notifications.tabActive')}
                </button>
                <button
                  type="button"
                  className={`flex-1 px-3 py-2 transition-colors ${
                    showArchive
                      ? 'border-b-2 border-primary text-foreground font-medium'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                  onClick={() => {
                    setShowArchive(true);
                    setPageOffset(0);
                  }}
                  aria-pressed={showArchive}
                >
                  {t('TopBar.notifications.tabArchive')}
                </button>
              </div>
              <div className="max-h-80 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="py-8 text-center text-muted-foreground">
                    <Bell className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">
                      {showArchive ? t('TopBar.notifications.emptyArchive') : t('TopBar.notifications.empty')}
                    </p>
                  </div>
                ) : (
                  notifications.map((notification: BellNotification) => (
                    <div
                      key={notification.id}
                      className={`px-3 py-3 border-b last:border-b-0 hover:bg-muted/50 transition-colors cursor-pointer ${
                        !notification.read ? 'bg-primary/5' : ''
                      }`}
                      onClick={() => {
                        if (!notification.read) {
                          markAsRead(notification.id);
                        }
                        if (notification.action_url) {
                          navigate(notification.action_url);
                          setShowNotifications(false);
                        }
                      }}
                    >
                      <div className="flex items-start gap-3">
                        <div className="mt-0.5">
                          {getNotificationIcon(notification)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <p className="text-sm font-medium truncate">
                                {notification.title}
                              </p>
                              <span className={`w-1.5 h-1.5 rounded-full ${getSeverityBadgeColor(notification.severity)}`} />
                            </div>
                            {/* Archive items are already dismissed, hide
                                the X to avoid a no-op click. */}
                            {!showArchive && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  dismissNotification(notification.id);
                                }}
                                className="text-muted-foreground hover:text-foreground"
                                aria-label={t('TopBar.notifications.dismissAria')}
                              >
                                <X className="h-3 w-3" />
                              </button>
                            )}
                          </div>
                          <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                            {notification.body}
                          </p>
                          <div className="flex items-center gap-2 mt-1">
                            <p className="text-[10px] text-muted-foreground">
                              {formatTimeAgo(notification.created_at)}
                            </p>
                            {notification.category && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground capitalize">
                                {notification.category.replace('_', ' ')}
                              </span>
                            )}
                          </div>
                        </div>
                        {!notification.read && (
                          <div className="w-2 h-2 rounded-full bg-primary mt-1.5" />
                        )}
                      </div>
                    </div>
                  ))
                )}
                {/* Offset-pagination terminus. Cursor pagination would be
                    nicer (no skew on inserts) but offset/limit is fine for
                    the bell drawer's typical depth. */}
                {hasMore && (
                  <button
                    type="button"
                    onClick={() => setPageOffset(pageOffset + pageSize)}
                    className="w-full py-2 text-xs text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors border-t"
                  >
                    {t('TopBar.notifications.loadMore')}
                  </button>
                )}
              </div>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* User Menu */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                className="flex items-center gap-2 p-1.5 rounded-lg hover:bg-secondary transition-all"
                aria-label={t('TopBar.userMenu.ariaLabel')}
              >
                <div className="h-8 w-8 rounded-full bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center">
                  <span className="text-xs font-semibold text-primary-foreground">
                    {user?.first_name?.[0]?.toUpperCase() || user?.email?.[0]?.toUpperCase() || 'U'}
                  </span>
                </div>
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuLabel>
                <div className="flex flex-col space-y-1">
                  <p className="text-sm font-medium">
                    {user?.first_name} {user?.last_name}
                  </p>
                  <p className="text-xs text-muted-foreground truncate">
                    {user?.email}
                  </p>
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => { resetDialogState(); setShowProfileDialog(true); }}>
                <User className="mr-2 h-4 w-4" />
                <span>{t('TopBar.userMenu.profile')}</span>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => { resetDialogState(); setShowChangePasswordDialog(true); }}>
                <Key className="mr-2 h-4 w-4" />
                <span>{t('TopBar.userMenu.changePassword')}</span>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => navigate('/settings')}>
                <Settings className="mr-2 h-4 w-4" />
                <span>{t('TopBar.userMenu.settings')}</span>
              </DropdownMenuItem>
              {user?.is_superuser && (
                <DropdownMenuItem onClick={() => navigate('/security')}>
                  <Shield className="mr-2 h-4 w-4" />
                  <span>{t('TopBar.userMenu.security')}</span>
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem 
                onClick={handleLogout}
                className="text-destructive focus:text-destructive"
              >
                <LogOut className="mr-2 h-4 w-4" />
                <span>{t('TopBar.userMenu.logout')}</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Profile Dialog */}
      <Dialog open={showProfileDialog} onOpenChange={(open) => { setShowProfileDialog(open); if (!open) resetDialogState(); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('TopBar.profileDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('TopBar.profileDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="flex items-center justify-center">
              <div className="h-20 w-20 rounded-full bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center">
                <span className="text-2xl font-bold text-primary-foreground">
                  {user?.first_name?.[0]?.toUpperCase()}{user?.last_name?.[0]?.toUpperCase()}
                </span>
              </div>
            </div>
            <div className="space-y-2">
              <Label>{t('TopBar.profileDialog.fullName')}</Label>
              <Input value={`${user?.first_name || ''} ${user?.last_name || ''}`} disabled />
            </div>
            <div className="space-y-2">
              <Label>{t('TopBar.profileDialog.email')}</Label>
              <div className="flex gap-2">
                <Input value={user?.email || ''} disabled className="flex-1" />
                <Button variant="outline" size="sm" onClick={() => { setShowProfileDialog(false); setShowChangeEmailDialog(true); }}>
                  {t('TopBar.profileDialog.change')}
                </Button>
              </div>
            </div>
            <div className="space-y-2">
              <Label>{t('TopBar.profileDialog.role')}</Label>
              <Input
                value={user?.is_superuser ? t('TopBar.roles.superAdmin') : user?.is_org_admin ? t('TopBar.roles.orgAdmin') : t('TopBar.roles.user')}
                disabled
              />
            </div>
            <div className="space-y-2">
              <Label>{t('TopBar.profileDialog.mfaStatus')}</Label>
              <div className="flex items-center gap-2">
                <Input
                  value={user?.mfa_enabled ? t('TopBar.profileDialog.enabled') : t('TopBar.profileDialog.disabled')}
                  disabled
                  className="flex-1"
                />
                <Button variant="outline" size="sm" onClick={() => navigate('/settings/security')}>
                  {user?.mfa_enabled ? t('TopBar.profileDialog.manage') : t('TopBar.profileDialog.enable')}
                </Button>
              </div>
            </div>
          </div>
          <DialogFooter className="flex-col sm:flex-row gap-2">
            <Button
              variant="destructive"
              onClick={() => { setShowProfileDialog(false); setShowDeleteAccountDialog(true); }}
              className="w-full sm:w-auto"
            >
              <Trash2 className="mr-2 h-4 w-4" />
              {t('TopBar.profileDialog.deleteAccount')}
            </Button>
            <Button variant="outline" onClick={() => setShowProfileDialog(false)} className="w-full sm:w-auto">
              {t('TopBar.actions.close')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Change Email Dialog */}
      <Dialog open={showChangeEmailDialog} onOpenChange={(open) => { setShowChangeEmailDialog(open); if (!open) resetDialogState(); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('TopBar.emailDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('TopBar.emailDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            {error && (
              <div className="bg-destructive/10 text-destructive px-3 py-2 rounded-md text-sm">
                {error}
              </div>
            )}
            {success && (
              <div className="bg-success/10 text-success px-3 py-2 rounded-md text-sm">
                {success}
              </div>
            )}
            <div className="space-y-2">
              <Label>{t('TopBar.emailDialog.currentEmail')}</Label>
              <Input value={user?.email || ''} disabled />
            </div>
            <div className="space-y-2">
              <Label htmlFor="newEmail">{t('TopBar.emailDialog.newEmail')}</Label>
              <Input
                id="newEmail"
                type="email"
                placeholder={t('TopBar.emailDialog.newEmailPlaceholder')}
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowChangeEmailDialog(false)}>
              {t('TopBar.actions.cancel')}
            </Button>
            <Button onClick={handleChangeEmail} disabled={isLoading}>
              {isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Mail className="mr-2 h-4 w-4" />}
              {t('TopBar.emailDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Change Password Dialog */}
      <Dialog open={showChangePasswordDialog} onOpenChange={(open) => { setShowChangePasswordDialog(open); if (!open) resetDialogState(); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('TopBar.passwordDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('TopBar.passwordDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            {error && (
              <div className="bg-destructive/10 text-destructive px-3 py-2 rounded-md text-sm">
                {error}
              </div>
            )}
            {success && (
              <div className="bg-success/10 text-success px-3 py-2 rounded-md text-sm">
                {success}
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="currentPassword">{t('TopBar.passwordDialog.currentPassword')}</Label>
              <Input 
                id="currentPassword"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="newPassword">{t('TopBar.passwordDialog.newPassword')}</Label>
              <Input 
                id="newPassword"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="confirmPassword">{t('TopBar.passwordDialog.confirmPassword')}</Label>
              <Input 
                id="confirmPassword"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowChangePasswordDialog(false)}>
              {t('TopBar.actions.cancel')}
            </Button>
            <Button onClick={handleChangePassword} disabled={isLoading}>
              {isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Key className="mr-2 h-4 w-4" />}
              {t('TopBar.passwordDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Account Dialog */}
      <Dialog open={showDeleteAccountDialog} onOpenChange={(open) => { setShowDeleteAccountDialog(open); if (!open) resetDialogState(); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-destructive">{t('TopBar.deleteDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('TopBar.deleteDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            {error && (
              <div className="bg-destructive/10 text-destructive px-3 py-2 rounded-md text-sm">
                {error}
              </div>
            )}
            <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4">
              <h4 className="font-medium text-destructive mb-2">{t('TopBar.deleteDialog.warningHeading')}</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>{t('TopBar.deleteDialog.warningData')}</li>
                <li>{t('TopBar.deleteDialog.warningKeys')}</li>
                <li>{t('TopBar.deleteDialog.warningIrreversible')}</li>
              </ul>
            </div>
            <div className="space-y-2">
              <Label htmlFor="deleteConfirm">
                {t('TopBar.deleteDialog.confirmPrefix')} <span className="font-mono font-bold">DELETE</span> {t('TopBar.deleteDialog.confirmSuffix')}
              </Label>
              <Input
                id="deleteConfirm"
                value={deleteConfirmation}
                onChange={(e) => setDeleteConfirmation(e.target.value)}
                placeholder="DELETE"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeleteAccountDialog(false)}>
              {t('TopBar.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={handleDeleteAccount}
              disabled={isLoading || deleteConfirmation !== 'DELETE'}
            >
              {isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
              {t('TopBar.deleteDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </header>
  );
}
