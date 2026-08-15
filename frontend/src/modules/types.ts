// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Frontend Module Manifest Types
 * 
 * Type definitions for the client-side module system.
 * Each module declares its routes, navigation items, and widgets
 * through a typed manifest, enabling:
 *   - Lazy-loaded code splitting per module
 *   - Dynamic sidebar navigation
 *   - Module-scoped route guards
 *   - Dashboard widget registration
 */
import type { ComponentType, LazyExoticComponent } from 'react';
import type { LucideIcon } from 'lucide-react';

// ────────────────────────────────────────────────────────────
// Route definition
// ────────────────────────────────────────────────────────────

export interface ModuleRouteDefinition {
  /** URL path (e.g. "/cameras", "/network/vlans") */
  path: string;
  /** Lazy-loaded page component */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  component: LazyExoticComponent<ComponentType<any>>;
  /** Route title (used in breadcrumbs, page <title>) */
  title?: string;
  /** Nested child routes (if applicable) */
  children?: ModuleRouteDefinition[];
}

// ────────────────────────────────────────────────────────────
// Navigation item definition
// ────────────────────────────────────────────────────────────

export type NavSection = 'network' | 'configuration' | 'monitoring' | 'security';

export interface ModuleNavDefinition {
  /** Display name */
  name: string;
  /** URL path */
  path: string;
  /** Lucide icon component */
  icon: LucideIcon;
  /** Which sidebar section this item belongs to */
  section: NavSection;
  /** Sort order within section (lower = higher) */
  order?: number;
  /** Badge count (e.g. unread alerts) */
  badge?: number;
}

// ────────────────────────────────────────────────────────────
// Widget definition (for dashboard tiles)
// ────────────────────────────────────────────────────────────

export interface ModuleWidgetDefinition {
  /** Unique widget ID */
  id: string;
  /** Display title */
  title: string;
  /** Widget component (lazy-loaded) */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  component: LazyExoticComponent<ComponentType<any>>;
  /** Default grid size */
  defaultSize?: { cols: number; rows: number };
  /** Minimum role required to see this widget */
  minRole?: string;
}

// ────────────────────────────────────────────────────────────
// Extension point types
// ────────────────────────────────────────────────────────────

/** Entity types that can receive context actions */
export type EntityType = 'device' | 'site' | 'controller' | 'camera' | 'user';

/** Target pages that accept injected detail sections */
export type DetailSlot =
  | 'device-detail'
  | 'site-detail'
  | 'controller-detail'
  | 'camera-detail';

/**
 * A settings tab contributed by a module.
 * Rendered as an additional tab in the SettingsPage.
 */
export interface ModuleSettingsTab {
  id: string;
  label: string;
  icon: LucideIcon;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  component: LazyExoticComponent<ComponentType<any>>;
  order?: number;
  permission?: string;
}

/**
 * A context action injected into entity detail page action menus.
 * When clicked, opens the provided component as a dialog.
 */
export interface ModuleContextAction {
  id: string;
  label: string;
  icon: LucideIcon;
  entityType: EntityType;
  /** Dialog/panel component · receives { entityId, onClose } props */
  component: LazyExoticComponent<ComponentType<{ entityId: string; onClose: () => void }>>;
  permission?: string;
  /** Conditionally show based on entity data */
  condition?: (entity: Record<string, unknown>) => boolean;
}

/**
 * An extra section/card injected into entity detail pages.
 */
export interface ModuleDetailSection {
  id: string;
  title: string;
  targetPage: DetailSlot;
  component: LazyExoticComponent<ComponentType<{ entityId: string }>>;
  order?: number;
  permission?: string;
}

// ────────────────────────────────────────────────────────────
// Module manifest
// ────────────────────────────────────────────────────────────

export interface FrontendModuleManifest {
  /** Module identifier · must match backend module ID */
  id: string;
  /** Human-readable name */
  name: string;
  /** Module description */
  description?: string;
  /** Module icon */
  icon: LucideIcon;
  /** Module accent color */
  color?: string;
  /** All routes this module provides */
  routes: ModuleRouteDefinition[];
  /** Navigation items for the sidebar */
  navItems: ModuleNavDefinition[];
  /** Dashboard widgets (optional) */
  widgets?: ModuleWidgetDefinition[];

  // ── Extension points ──────────────────────────────────────

  /** Additional settings page tabs provided by this module */
  settingsTabs?: ModuleSettingsTab[];

  /** Context actions injected into entity detail page action menus */
  contextActions?: ModuleContextAction[];

  /** Extra sections/cards injected into entity detail pages */
  detailSections?: ModuleDetailSection[];
}
