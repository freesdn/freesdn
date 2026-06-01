// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * AI Assistant Module - Frontend Manifest
 */
import { lazy } from 'react';
import { Brain } from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

export const aiModule: FrontendModuleManifest = {
  id: 'ai',
  name: 'AI Assistant',
  description: 'AI-powered network assistant with multi-provider LLM support',
  icon: Brain,
  color: '#8B5CF6',
  routes: [
    {
      path: '/ai',
      component: lazy(() => import('@/pages/ai/AIAssistantPage')),
      title: 'AI Assistant',
    },
    // AI settings are now embedded in /settings/:tab via SettingsPage
  ],
  navItems: [
    { name: 'AI Assistant', path: '/ai', icon: Brain, section: 'configuration', order: 90 },
  ],
};
