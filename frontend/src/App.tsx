// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { Routes, Route, Navigate } from 'react-router-dom';
import { lazy, Suspense, useEffect } from 'react';
import { useAuthStore, useInitAuth } from '@/stores/authStore';
import { useNotificationsStore, useWebSocketStore, useUIStore } from '@/stores';
import { useUIPaletteStore } from '@/stores/sidebarStore';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useGlobalShortcuts } from '@/hooks/useGlobalShortcuts';
import { Toaster } from '@/components/ui/toast';
import { ThemeProvider } from '@/components/providers/ThemeProvider';
import { CommandPalette } from '@/components/command-palette';
import { ShortcutsCheatsheet } from '@/components/ui/shortcuts-cheatsheet';
import { DemoModeBanner } from '@/demo/DemoModeBanner';
import { systemApi } from '@/lib/api';

// Layout
import { MainLayout } from '@/components/layout';

// Auth
import { LoginPage, RegisterPage, ForgotPasswordPage, ProtectedRoute, UnauthorizedPage } from '@/components/auth';
import SSOCallbackPage from '@/pages/auth/SSOCallbackPage';
import ResetPasswordPage from '@/pages/auth/ResetPasswordPage';
import ChangePasswordPage from '@/pages/auth/ChangePasswordPage';

// Pages - Core (DashboardPage stays static · it's the landing route)
import DashboardPage from '@/pages/dashboard/DashboardPage';
import { SetupPage } from '@/pages/setup';

// Pages - Core (lazy-loaded · not needed on initial render)
const DevicesPage = lazy(() => import('@/pages/devices/DevicesPage'));
const DeviceDetailPage = lazy(() => import('@/pages/devices/DeviceDetailPage'));
const ControllersPage = lazy(() => import('@/pages/controllers/ControllersPage'));
const ControllerDetailPage = lazy(() => import('@/pages/controllers/ControllerDetailPage'));
const StoragePage = lazy(() => import('@/pages/storage/StoragePage'));
const FabricPage = lazy(() => import('@/pages/fabric/FabricPage'));
const SitesPage = lazy(() => import('@/pages/sites/SitesPage'));
const SiteDetailPage = lazy(() => import('@/pages/sites/SiteDetailPage'));
const DiscoveryPage = lazy(() => import('@/pages/discovery/DiscoveryPage'));
const UsersPage = lazy(() => import('@/pages/users/UsersPage'));
const SettingsPage = lazy(() => import('@/pages/settings/SettingsPage'));
// SSOSettingsPage is now embedded within SettingsPage (no standalone route)
const ModuleDetailPage = lazy(() => import('@/pages/settings/ModuleDetailPage'));
const PluginsPage = lazy(() => import('@/pages/settings/PluginsPage'));
const OrganizationsPage = lazy(() => import('@/pages/organizations/OrganizationsPage'));
const OrganizationDetailPage = lazy(() => import('@/pages/organizations/OrganizationDetailPage'));

// Pages - Network (static imports removed · now lazy-loaded via module manifests)
// Module pages are handled by <ModuleRoutes /> below

// Pages - Monitoring (lazy-loaded)
const AlertsPage = lazy(() => import('@/pages/alerts').then(m => ({ default: m.AlertsPage })));
const LogsPage = lazy(() => import('@/pages/logs').then(m => ({ default: m.LogsPage })));
const AnalyticsPage = lazy(() => import('@/pages/analytics').then(m => ({ default: m.AnalyticsPage })));
const CrossSiteComparisonPage = lazy(() => import('@/pages/analytics/CrossSiteComparisonPage'));

// Pages - Configuration (lazy-loaded)
const AutomationPage = lazy(() => import('@/pages/automation').then(m => ({ default: m.AutomationPage })));
const WebhooksPage = lazy(() => import('@/pages/webhooks').then(m => ({ default: m.WebhooksPage })));
const IntegrationsPage = lazy(() => import('@/pages/integrations').then(m => ({ default: m.IntegrationsPage })));
const FirmwarePage = lazy(() => import('@/pages/firmware').then(m => ({ default: m.FirmwarePage })));
const DriversPage = lazy(() => import('@/pages/drivers').then(m => ({ default: m.DriversPage })));

// Pages - Enterprise (lazy-loaded)
const HealthDashboardPage = lazy(() => import('@/pages/enterprise/health').then(m => ({ default: m.HealthDashboardPage })));
const ConfigTemplatesPage = lazy(() => import('@/pages/enterprise/templates').then(m => ({ default: m.ConfigTemplatesPage })));
const SiteGroupsPage = lazy(() => import('@/pages/enterprise/site-groups').then(m => ({ default: m.SiteGroupsPage })));
const LifecyclePage = lazy(() => import('@/pages/enterprise/lifecycle').then(m => ({ default: m.LifecyclePage })));
const BulkOperationsPage = lazy(() => import('@/pages/enterprise/bulk-ops').then(m => ({ default: m.BulkOperationsPage })));
const ReconciliationPage = lazy(() => import('@/pages/enterprise/reconciliation').then(m => ({ default: m.ReconciliationPage })));
const IncidentsPage = lazy(() => import('@/pages/enterprise/incidents').then(m => ({ default: m.IncidentsPage })));
const SLAPage = lazy(() => import('@/pages/enterprise/sla').then(m => ({ default: m.SLAPage })));
const TopologyPage = lazy(() => import('@/pages/enterprise/topology').then(m => ({ default: m.TopologyPage })));
const AlertRulesPage = lazy(() => import('@/pages/enterprise/alert-rules').then(m => ({ default: m.AlertRulesPage })));
const NotificationProvidersPage = lazy(() => import('@/pages/enterprise/notification-providers').then(m => ({ default: m.NotificationProvidersPage })));

// Pages - Security (lazy-loaded)
const SecurityPage = lazy(() => import('@/pages/security').then(m => ({ default: m.SecurityPage })));
const CredentialsPage = lazy(() => import('@/pages/credentials').then(m => ({ default: m.CredentialsPage })));
const AgentsPage = lazy(() => import('@/pages/agents').then(m => ({ default: m.AgentsPage })));
const DownloadsPage = lazy(() => import('@/pages/agents/DownloadsPage').then(m => ({ default: m.DownloadsPage })));
const AgentReleasesPage = lazy(() => import('@/pages/agents/AgentReleasesPage').then(m => ({ default: m.AgentReleasesPage })));
const AgentDetailPage = lazy(() => import('@/pages/agents/AgentDetailPage').then(m => ({ default: m.AgentDetailPage })));
const RolesPage = lazy(() => import('@/pages/roles').then(m => ({ default: m.RolesPage })));

// Pages - Marketplace (lazy-loaded)
const MarketplacePage = lazy(() => import('@/pages/marketplace/MarketplacePage'));
const PluginDetailPage = lazy(() => import('@/pages/marketplace/PluginDetailPage'));

// Pages - Camera standalone (no MainLayout · immersive/pop-out)
const CameraWallPopout = lazy(() => import('@/pages/cameras/CameraWallPopout'));
const CameraDisplayWall = lazy(() => import('@/pages/cameras/CameraDisplayWall'));
// MultiPlaybackPage now loaded via cameras module manifest
const GatewayFirmwarePage = lazy(() => import('@/pages/gateway-firmware/GatewayFirmwarePage'));
const GatewayVPNPage = lazy(() => import('@/pages/gateway-vpn/GatewayVPNPage'));
const GatewayBulkPage = lazy(() => import('@/pages/gateway-bulk/GatewayBulkPage'));
const GatewaySystemPage = lazy(() => import('@/pages/gateway-system/GatewaySystemPage'));
const GatewayRoutingPage = lazy(() => import('@/pages/gateway-routing/GatewayRoutingPage'));
const GatewayFirewallPage = lazy(() => import('@/pages/gateway-firewall/GatewayFirewallPage'));
const GatewayHotspotPage = lazy(() => import('@/pages/gateway-hotspot/GatewayHotspotPage'));
const GatewayProfilesPage = lazy(() => import('@/pages/gateway-profiles/GatewayProfilesPage'));
const GatewaySwitchAdvancedPage = lazy(() => import('@/pages/gateway-switch-advanced/GatewaySwitchAdvancedPage'));
const GatewayDiagnosticsPage = lazy(() => import('@/pages/gateway-diagnostics/GatewayDiagnosticsPage'));
const GatewayInsightsPage = lazy(() => import('@/pages/gateway-insights/GatewayInsightsPage'));
const PendingChangesPage = lazy(() => import('@/pages/pending-changes/PendingChangesPage'));

// Hooks
import { useModulesInit } from '@/hooks/useModules';

// Module system (lazy-loaded module routes)
import { renderModuleRoutes } from '@/modules/ModuleRoutes';

function App() {
  const { addNotification } = useNotificationsStore();
  const setConnectionStatus = useWebSocketStore((state) => state.setConnectionStatus);
  const { isAuthenticated, _isHydrated, _isAuthInitialized } = useAuthStore();
  const { initAuth } = useInitAuth();
  const setReadOnlyMode = useUIStore((state) => state.setReadOnlyMode);
  const {
    commandPaletteOpen,
    setCommandPaletteOpen,
    toggleCommandPalette,
    shortcutsOpen,
    setShortcutsOpen,
    openShortcuts,
  } = useUIPaletteStore();

  // Global keyboard shortcuts: ⌘K palette, ? cheatsheet, g-prefix nav.
  useGlobalShortcuts({
    enabled: isAuthenticated,
    onOpenCommandPalette: toggleCommandPalette,
    onOpenShortcutsCheatsheet: openShortcuts,
  });
  
  // Initialize auth on app load · only after zustand persist hydration completes
  useEffect(() => {
    if (_isHydrated) {
      initAuth();
    }
  }, [_isHydrated, initAuth]);
  
  // Initialize module system (loads manifests, org enablement, navigation)
  useModulesInit();

  // Seed adapter read-only mode from the backend once the session is
  // verified. The endpoint is admin-only and auth-gated, so we only fetch
  // after auth init confirms an authenticated session. A failure (e.g.
  // non-admin / 403) leaves the store at its safe default (false) without
  // surfacing a banner.
  useEffect(() => {
    if (!(_isAuthInitialized && isAuthenticated)) return;
    let cancelled = false;
    systemApi
      .getAdapterReadOnly()
      .then((res) => {
        if (!cancelled) setReadOnlyMode(res.data.read_only);
      })
      .catch(() => {
        /* leave default (read-write) on error */
      });
    return () => {
      cancelled = true;
    };
  }, [_isAuthInitialized, isAuthenticated, setReadOnlyMode]);
  
  // Only connect WebSocket once initAuth has verified the session is valid.
  // Status changes go directly to the zustand store via onStatusChange
  // callback · no React state in App, so reconnection cycles don't
  // re-render the entire component tree.
  useWebSocket({
    enabled: _isAuthInitialized && isAuthenticated,
    onStatusChange: setConnectionStatus,
    onMessage: (message) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const data = message.data as Record<string, any> | undefined;
      switch (message.type) {
        case 'device_status_change':
          addNotification({
            type: data?.status === 'online' ? 'success' : 'warning',
            title: `Device ${data?.status}`,
            message: `${data?.name} is now ${data?.status}`,
          });
          break;
        case 'discovery_complete':
          addNotification({
            type: 'info',
            title: 'Discovery Complete',
            message: `Found ${data?.device_count} devices`,
          });
          break;
      }
    },
  });

  return (
    <ThemeProvider>
      <Toaster>
        <DemoModeBanner />
        <Suspense fallback={<div className="flex items-center justify-center h-screen"><div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" /></div>}>
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
          <Route path="/change-password" element={<ChangePasswordPage />} />
          <Route path="/auth/sso/callback" element={<SSOCallbackPage />} />
          <Route path="/setup" element={<SetupPage />} />
          <Route path="/unauthorized" element={<UnauthorizedPage />} />

        {/* Protected Dashboard Routes */}
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <MainLayout>
                <DashboardPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <MainLayout>
                <DashboardPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/sites"
          element={
            <ProtectedRoute>
              <MainLayout>
                <SitesPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/sites/:siteId"
          element={
            <ProtectedRoute>
              <MainLayout>
                <SiteDetailPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/sites/:siteId/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <SiteDetailPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/controllers"
          element={
            <ProtectedRoute>
              <MainLayout>
                <ControllersPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/controllers/:id/:tab?"
          element={
            <ProtectedRoute>
              <MainLayout>
                <ControllerDetailPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/storage"
          element={
            <ProtectedRoute>
              <MainLayout>
                <StoragePage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/fabric"
          element={
            <ProtectedRoute>
              <MainLayout>
                <FabricPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route path="/devices/new" element={<Navigate to="/discovery" replace />} />
        <Route
          path="/devices"
          element={
            <ProtectedRoute>
              <MainLayout>
                <DevicesPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Devices List tab · explicit route so it wins over /devices/:deviceId */}
        <Route
          path="/devices/list"
          element={
            <ProtectedRoute>
              <MainLayout>
                <DevicesPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/devices/:deviceId"
          element={
            <ProtectedRoute>
              <MainLayout>
                <DeviceDetailPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/devices/:deviceId/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <DeviceDetailPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        
        {/* ─── Module Routes (lazy-loaded, module-guarded) ─── */}
        {renderModuleRoutes()}

        <Route
          path="/organizations"
          element={
            <ProtectedRoute requiredPermissions={['organization:read']}>
              <MainLayout>
                <OrganizationsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/organizations/:orgId"
          element={
            <ProtectedRoute requiredPermissions={['organization:read']}>
              <MainLayout>
                <OrganizationDetailPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/organizations/:orgId/:tab"
          element={
            <ProtectedRoute requiredPermissions={['organization:read']}>
              <MainLayout>
                <OrganizationDetailPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/discovery"
          element={
            <ProtectedRoute>
              <MainLayout>
                <DiscoveryPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/discovery/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <DiscoveryPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/users"
          element={
            <ProtectedRoute requiredPermissions={['user:read']}>
              <MainLayout>
                <UsersPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings"
          element={
            <ProtectedRoute requiredPermissions={['settings:read']}>
              <MainLayout>
                <SettingsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings/:tab"
          element={
            <ProtectedRoute requiredPermissions={['settings:read']}>
              <MainLayout>
                <SettingsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings/modules/:moduleId"
          element={
            <ProtectedRoute requiredPermissions={['settings:read']}>
              <MainLayout>
                <ModuleDetailPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings/modules/:moduleId/:tab"
          element={
            <ProtectedRoute requiredPermissions={['settings:read']}>
              <MainLayout>
                <ModuleDetailPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* SSO settings now handled by /settings/:tab via SettingsPage */}

        {/* Plugins · top-level platform page */}
        <Route
          path="/plugins"
          element={
            <ProtectedRoute requiredPermissions={['settings:admin']}>
              <MainLayout>
                <PluginsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />

        {/* Monitoring */}
        <Route
          path="/analytics"
          element={
            <ProtectedRoute>
              <MainLayout>
                <AnalyticsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/analytics/sites-comparison"
          element={
            <ProtectedRoute>
              <MainLayout>
                <CrossSiteComparisonPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/analytics/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <AnalyticsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/logs"
          element={
            <ProtectedRoute>
              <MainLayout>
                <LogsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/logs/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <LogsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/alerts"
          element={
            <ProtectedRoute>
              <MainLayout>
                <AlertsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/alerts/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <AlertsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        
        {/* Configuration */}
        <Route
          path="/automation"
          element={
            <ProtectedRoute>
              <MainLayout>
                <AutomationPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/automation/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <AutomationPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/webhooks"
          element={
            <ProtectedRoute>
              <MainLayout>
                <WebhooksPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/integrations"
          element={
            <ProtectedRoute>
              <MainLayout>
                <IntegrationsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/firmware"
          element={
            <ProtectedRoute>
              <MainLayout>
                <FirmwarePage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/firmware/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <FirmwarePage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/drivers"
          element={
            <ProtectedRoute>
              <MainLayout>
                <DriversPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        
        {/* Enterprise */}
        <Route
          path="/health"
          element={
            <ProtectedRoute>
              <MainLayout>
                <HealthDashboardPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/health/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <HealthDashboardPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/templates"
          element={
            <ProtectedRoute>
              <MainLayout>
                <ConfigTemplatesPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/groups"
          element={
            <ProtectedRoute>
              <MainLayout>
                <SiteGroupsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/groups/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <SiteGroupsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/lifecycle"
          element={
            <ProtectedRoute>
              <MainLayout>
                <LifecyclePage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/bulk-operations"
          element={
            <ProtectedRoute requiredPermissions={['device:update']}>
              <MainLayout>
                <BulkOperationsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/reconciliation"
          element={
            <ProtectedRoute>
              <MainLayout>
                <ReconciliationPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/incidents"
          element={
            <ProtectedRoute>
              <MainLayout>
                <IncidentsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/incidents/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <IncidentsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/sla"
          element={
            <ProtectedRoute>
              <MainLayout>
                <SLAPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/sla/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <SLAPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/topology"
          element={
            <ProtectedRoute>
              <MainLayout>
                <TopologyPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/alert-rules"
          element={
            <ProtectedRoute>
              <MainLayout>
                <AlertRulesPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/alert-rules/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <AlertRulesPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/notification-providers"
          element={
            <ProtectedRoute>
              <MainLayout>
                <NotificationProvidersPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/notification-providers/:tab"
          element={
            <ProtectedRoute>
              <MainLayout>
                <NotificationProvidersPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        
        {/* Security */}
        <Route
          path="/security"
          element={
            <ProtectedRoute requiredPermissions={['audit:read']}>
              <MainLayout>
                <SecurityPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/security/:tab"
          element={
            <ProtectedRoute requiredPermissions={['audit:read']}>
              <MainLayout>
                <SecurityPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/credentials"
          element={
            <ProtectedRoute requiredPermissions={['settings:read']}>
              <MainLayout>
                <CredentialsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/agents"
          element={
            <ProtectedRoute>
              <MainLayout>
                <AgentsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/agents/downloads"
          element={
            <ProtectedRoute>
              <MainLayout>
                <DownloadsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/agents/releases"
          element={
            <ProtectedRoute requiredPermissions={['agent:admin']}>
              <MainLayout>
                <AgentReleasesPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/agents/:id"
          element={
            <ProtectedRoute>
              <MainLayout>
                <AgentDetailPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/roles"
          element={
            <ProtectedRoute requiredPermissions={['role:read']}>
              <MainLayout>
                <RolesPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/roles/:tab"
          element={
            <ProtectedRoute requiredPermissions={['role:read']}>
              <MainLayout>
                <RolesPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />

        {/* Marketplace */}
        <Route
          path="/marketplace"
          element={
            <ProtectedRoute requiredPermissions={['settings:admin']}>
              <MainLayout>
                <MarketplacePage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/marketplace/:slug"
          element={
            <ProtectedRoute requiredPermissions={['settings:admin']}>
              <MainLayout>
                <PluginDetailPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />

        {/* Camera pop-out wall (no MainLayout · bare window for security monitors) */}
        <Route
          path="/cameras/wall/popout"
          element={
            <ProtectedRoute>
              <CameraWallPopout />
            </ProtectedRoute>
          }
        />
        {/* Camera display wall · immersive kiosk mode (no MainLayout) */}
        <Route
          path="/cameras/display"
          element={
            <ProtectedRoute>
              <CameraDisplayWall />
            </ProtectedRoute>
          }
        />
        {/* Multi-camera playback route now in cameras module manifest */}

        {/* Gateway VPN, controller-side VPN configuration */}
        <Route
          path="/gateway/vpn"
          element={
            <ProtectedRoute>
              <MainLayout>
                <GatewayVPNPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Gateway firmware, controller-side firmware lifecycle */}
        <Route
          path="/gateway/firmware"
          element={
            <ProtectedRoute>
              <MainLayout>
                <GatewayFirmwarePage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Gateway bulk ops + cloning + templates */}
        <Route
          path="/gateway/bulk"
          element={
            <ProtectedRoute>
              <MainLayout>
                <GatewayBulkPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Gateway system, controller backups, SMTP, SSL, admins, etc. */}
        <Route
          path="/gateway/system"
          element={
            <ProtectedRoute>
              <MainLayout>
                <GatewaySystemPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Gateway advanced routing, VRRP, IPv6 static, BGP */}
        <Route
          path="/gateway/routing"
          element={
            <ProtectedRoute>
              <MainLayout>
                <GatewayRoutingPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Gateway firewall depth, DMZ, UPnP, attack defense, ALG, IDS/IPS */}
        <Route
          path="/gateway/firewall"
          element={
            <ProtectedRoute>
              <MainLayout>
                <GatewayFirewallPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Gateway hotspot, operators, SMS gateway, free-auth */}
        <Route
          path="/gateway/hotspot"
          element={
            <ProtectedRoute>
              <MainLayout>
                <GatewayHotspotPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Gateway profiles, reusable object catalog */}
        <Route
          path="/gateway/profiles"
          element={
            <ProtectedRoute>
              <MainLayout>
                <GatewayProfilesPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Gateway switch-advanced, per-switch sFlow, mirror, MSTP */}
        <Route
          path="/gateway/switch-advanced"
          element={
            <ProtectedRoute>
              <MainLayout>
                <GatewaySwitchAdvancedPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Gateway diagnostics, speed test, session stats */}
        <Route
          path="/gateway/diagnostics"
          element={
            <ProtectedRoute>
              <MainLayout>
                <GatewayDiagnosticsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Gateway insights, top-talkers, anomalies, AI suggestions, mesh */}
        <Route
          path="/gateway/insights"
          element={
            <ProtectedRoute>
              <MainLayout>
                <GatewayInsightsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        {/* Pending changes, staged writes across every gateway-* feature */}
        <Route
          path="/gateway/pending"
          element={
            <ProtectedRoute>
              <MainLayout>
                <PendingChangesPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />

        {/* Catch all */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      </Suspense>

      {/* Global Command Palette (⌘K / Ctrl+K) · controlled via useUIPaletteStore */}
      {isAuthenticated && (
        <CommandPalette open={commandPaletteOpen} onOpenChange={setCommandPaletteOpen} />
      )}

      {/* Keyboard Shortcuts Cheatsheet (?) */}
      {isAuthenticated && (
        <ShortcutsCheatsheet open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
      )}
      </Toaster>
    </ThemeProvider>
  );
}

export default App;
