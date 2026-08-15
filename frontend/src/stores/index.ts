// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';

// Device Store
interface Device {
  id: string;
  name: string;
  device_type: string;
  vendor: string;
  model: string;
  ip: string;
  status: string;
}

interface DevicesState {
  selectedDevice: Device | null;
  selectedDevices: string[];
  filterStatus: 'all' | 'online' | 'offline';
  filterType: string;
  filterVendor: string;
  
  setSelectedDevice: (device: Device | null) => void;
  toggleDeviceSelection: (deviceId: string) => void;
  setSelectedDevices: (deviceIds: string[]) => void;
  clearSelection: () => void;
  setFilterStatus: (status: 'all' | 'online' | 'offline') => void;
  setFilterType: (type: string) => void;
  setFilterVendor: (vendor: string) => void;
}

export const useDevicesStore = create<DevicesState>()(
  devtools(
    immer((set) => ({
      selectedDevice: null,
      selectedDevices: [],
      filterStatus: 'all',
      filterType: '',
      filterVendor: '',
      
      setSelectedDevice: (device) => set((state) => {
        state.selectedDevice = device;
      }),
      
      toggleDeviceSelection: (deviceId) => set((state) => {
        const index = state.selectedDevices.indexOf(deviceId);
        if (index === -1) {
          state.selectedDevices.push(deviceId);
        } else {
          state.selectedDevices.splice(index, 1);
        }
      }),
      
      setSelectedDevices: (deviceIds) => set((state) => {
        state.selectedDevices = deviceIds;
      }),
      
      clearSelection: () => set((state) => {
        state.selectedDevices = [];
      }),
      
      setFilterStatus: (status) => set((state) => {
        state.filterStatus = status;
      }),
      
      setFilterType: (type) => set((state) => {
        state.filterType = type;
      }),
      
      setFilterVendor: (vendor) => set((state) => {
        state.filterVendor = vendor;
      }),
    })),
    { name: 'devices-store' }
  )
);

// ────────────────────────────────────────────────────────────────
// Accent Color Presets
// Each preset defines HSL values for primary, ring, sidebar-accent,
// and chart-1 in both light and dark modes. These are injected onto
// :root / .dark by ThemeProvider so every tailwind utility that
// references `primary`, `ring`, `sidebar-accent`, etc. updates globally.
// ────────────────────────────────────────────────────────────────

export interface AccentPreset {
  id: string;
  label: string;
  /** Tailwind-compatible swatch class for the settings UI preview */
  swatch: string;
  /** HSL values WITHOUT the `hsl()` wrapper, e.g. "217 91% 55%" */
  light: { primary: string; primaryForeground: string; ring: string; sidebarAccent: string; chart1: string };
  dark:  { primary: string; primaryForeground: string; ring: string; sidebarAccent: string; chart1: string };
}

export const ACCENT_PRESETS: AccentPreset[] = [
  {
    id: 'blue',
    label: 'Enterprise Blue',
    swatch: 'bg-blue-500',
    light: { primary: '217 91% 45%', primaryForeground: '0 0% 100%', ring: '217 91% 45%', sidebarAccent: '217 91% 45%', chart1: '217 91% 45%' },
    dark:  { primary: '217 91% 55%', primaryForeground: '222 47% 8%', ring: '217 91% 55%', sidebarAccent: '217 91% 55%', chart1: '217 91% 55%' },
  },
  {
    id: 'indigo',
    label: 'Indigo',
    swatch: 'bg-indigo-500',
    light: { primary: '239 84% 56%', primaryForeground: '0 0% 100%', ring: '239 84% 56%', sidebarAccent: '239 84% 56%', chart1: '239 84% 56%' },
    dark:  { primary: '239 84% 67%', primaryForeground: '0 0% 100%', ring: '239 84% 67%', sidebarAccent: '239 84% 67%', chart1: '239 84% 67%' },
  },
  {
    id: 'violet',
    label: 'Violet',
    swatch: 'bg-violet-500',
    light: { primary: '258 90% 56%', primaryForeground: '0 0% 100%', ring: '258 90% 56%', sidebarAccent: '258 90% 56%', chart1: '258 90% 56%' },
    dark:  { primary: '258 90% 66%', primaryForeground: '0 0% 100%', ring: '258 90% 66%', sidebarAccent: '258 90% 66%', chart1: '258 90% 66%' },
  },
  {
    id: 'emerald',
    label: 'Emerald',
    swatch: 'bg-emerald-500',
    light: { primary: '160 84% 36%', primaryForeground: '0 0% 100%', ring: '160 84% 36%', sidebarAccent: '160 84% 36%', chart1: '160 84% 36%' },
    dark:  { primary: '160 84% 45%', primaryForeground: '0 0% 100%', ring: '160 84% 45%', sidebarAccent: '160 84% 45%', chart1: '160 84% 45%' },
  },
  {
    id: 'teal',
    label: 'Teal',
    swatch: 'bg-teal-500',
    light: { primary: '173 80% 36%', primaryForeground: '0 0% 100%', ring: '173 80% 36%', sidebarAccent: '173 80% 36%', chart1: '173 80% 36%' },
    dark:  { primary: '173 80% 45%', primaryForeground: '0 0% 100%', ring: '173 80% 45%', sidebarAccent: '173 80% 45%', chart1: '173 80% 45%' },
  },
  {
    id: 'amber',
    label: 'Amber',
    swatch: 'bg-amber-500',
    light: { primary: '38 92% 44%', primaryForeground: '0 0% 100%', ring: '38 92% 44%', sidebarAccent: '38 92% 44%', chart1: '38 92% 44%' },
    dark:  { primary: '38 92% 50%', primaryForeground: '0 0% 8%',  ring: '38 92% 50%', sidebarAccent: '38 92% 50%', chart1: '38 92% 50%' },
  },
  {
    id: 'rose',
    label: 'Rose',
    swatch: 'bg-rose-500',
    light: { primary: '350 89% 52%', primaryForeground: '0 0% 100%', ring: '350 89% 52%', sidebarAccent: '350 89% 52%', chart1: '350 89% 52%' },
    dark:  { primary: '350 89% 60%', primaryForeground: '0 0% 100%', ring: '350 89% 60%', sidebarAccent: '350 89% 60%', chart1: '350 89% 60%' },
  },
  {
    id: 'orange',
    label: 'Orange',
    swatch: 'bg-orange-500',
    light: { primary: '25 95% 50%', primaryForeground: '0 0% 100%', ring: '25 95% 50%', sidebarAccent: '25 95% 50%', chart1: '25 95% 50%' },
    dark:  { primary: '25 95% 55%', primaryForeground: '0 0% 100%', ring: '25 95% 55%', sidebarAccent: '25 95% 55%', chart1: '25 95% 55%' },
  },
  {
    id: 'cyan',
    label: 'Cyan',
    swatch: 'bg-cyan-500',
    light: { primary: '188 95% 38%', primaryForeground: '0 0% 100%', ring: '188 95% 38%', sidebarAccent: '188 95% 38%', chart1: '188 95% 38%' },
    dark:  { primary: '188 95% 48%', primaryForeground: '0 0% 100%', ring: '188 95% 48%', sidebarAccent: '188 95% 48%', chart1: '188 95% 48%' },
  },
  {
    id: 'slate',
    label: 'Slate',
    swatch: 'bg-slate-500',
    light: { primary: '215 16% 47%', primaryForeground: '0 0% 100%', ring: '215 16% 47%', sidebarAccent: '215 16% 47%', chart1: '215 16% 47%' },
    dark:  { primary: '215 16% 57%', primaryForeground: '0 0% 100%', ring: '215 16% 57%', sidebarAccent: '215 16% 57%', chart1: '215 16% 57%' },
  },
];

// UI Store
interface UIState {
  sidebarCollapsed: boolean;
  /** Mobile sidebar drawer open state · ephemeral, NOT persisted. */
  sidebarMobileOpen: boolean;
  theme: 'dark' | 'light' | 'system';
  accentColor: string;        // preset id · 'blue' | 'indigo' | ... | 'custom'
  animationsEnabled: boolean;
  dashboardEditMode: boolean;
  /**
   * Adapter read-only mode · server-authoritative, NOT persisted. Seeded
   * from GET /system/settings/adapter-read-only on app mount and updated
   * after the Settings toggle PUTs a new value. true = device writes are
   * refused (monitor-only); false = read-write (manage).
   */
  readOnlyMode: boolean;

  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setSidebarMobileOpen: (open: boolean) => void;
  toggleSidebarMobile: () => void;
  setTheme: (theme: 'dark' | 'light' | 'system') => void;
  setAccentColor: (accentId: string) => void;
  setAnimationsEnabled: (enabled: boolean) => void;
  setDashboardEditMode: (editMode: boolean) => void;
  setReadOnlyMode: (readOnly: boolean) => void;
}

export const useUIStore = create<UIState>()(
  devtools(
    persist(
      immer((set) => ({
        sidebarCollapsed: false,
        sidebarMobileOpen: false,
        theme: 'dark',
        accentColor: 'blue',
        animationsEnabled: true,
        dashboardEditMode: false,
        readOnlyMode: false,

        toggleSidebar: () => set((state) => {
          state.sidebarCollapsed = !state.sidebarCollapsed;
        }),

        setSidebarCollapsed: (collapsed) => set((state) => {
          state.sidebarCollapsed = collapsed;
        }),

        setSidebarMobileOpen: (open) => set((state) => {
          state.sidebarMobileOpen = open;
        }),

        toggleSidebarMobile: () => set((state) => {
          state.sidebarMobileOpen = !state.sidebarMobileOpen;
        }),

        setTheme: (theme) => set((state) => {
          state.theme = theme;
        }),

        setAccentColor: (accentId) => set((state) => {
          state.accentColor = accentId;
        }),

        setAnimationsEnabled: (enabled) => set((state) => {
          state.animationsEnabled = enabled;
        }),

        setDashboardEditMode: (editMode) => set((state) => {
          state.dashboardEditMode = editMode;
        }),

        setReadOnlyMode: (readOnly) => set((state) => {
          state.readOnlyMode = readOnly;
        }),
      })),
      {
        name: 'freesdn-ui-settings',
        // Exclude ephemeral mobile drawer state AND server-authoritative
        // read-only mode from persistence. readOnlyMode is seeded from the
        // backend on every mount, persisting it would flash a stale value.
        partialize: (state) => {
          const { sidebarMobileOpen: _omitDrawer, readOnlyMode: _omitRO, ...rest } = state;
          void _omitDrawer;
          void _omitRO;
          return rest as Omit<UIState, 'sidebarMobileOpen' | 'readOnlyMode'>;
        },
      }
    ),
    { name: 'ui-store' }
  )
);

// WebSocket Store - Global connection status
type ConnectionStatus = 'connecting' | 'online' | 'offline';

interface WebSocketState {
  connectionStatus: ConnectionStatus;
  setConnectionStatus: (status: ConnectionStatus) => void;
}

export const useWebSocketStore = create<WebSocketState>()(
  devtools(
    immer((set) => ({
      connectionStatus: 'connecting',
      
      setConnectionStatus: (status) => set((state) => {
        state.connectionStatus = status;
      }),
    })),
    { name: 'websocket-store' }
  )
);

// Notifications Store
interface Notification {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message?: string;
  timestamp: Date;
  read: boolean;
}

interface NotificationsState {
  notifications: Notification[];
  unreadCount: number;
  
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp' | 'read'>) => void;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  removeNotification: (id: string) => void;
  clearAll: () => void;
}

export const useNotificationsStore = create<NotificationsState>()(
  devtools(
    immer((set, _get) => ({
      notifications: [],
      unreadCount: 0,
      
      addNotification: (notification) => set((state) => {
        const newNotification: Notification = {
          ...notification,
          id: crypto.randomUUID(),
          timestamp: new Date(),
          read: false,
        };
        state.notifications.unshift(newNotification);
        state.unreadCount = state.notifications.filter((n: Notification) => !n.read).length;
        
        // Keep only last 100 notifications
        if (state.notifications.length > 100) {
          state.notifications = state.notifications.slice(0, 100);
        }
      }),
      
      markAsRead: (id) => set((state) => {
        const notification = state.notifications.find((n: Notification) => n.id === id);
        if (notification) {
          notification.read = true;
          state.unreadCount = state.notifications.filter((n: Notification) => !n.read).length;
        }
      }),
      
      markAllAsRead: () => set((state) => {
        state.notifications.forEach((n: Notification) => n.read = true);
        state.unreadCount = 0;
      }),
      
      removeNotification: (id) => set((state) => {
        state.notifications = state.notifications.filter((n: Notification) => n.id !== id);
        state.unreadCount = state.notifications.filter((n: Notification) => !n.read).length;
      }),
      
      clearAll: () => set((state) => {
        state.notifications = [];
        state.unreadCount = 0;
      }),
    })),
    { name: 'notifications-store' }
  )
);
