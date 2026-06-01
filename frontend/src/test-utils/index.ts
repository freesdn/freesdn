// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Barrel re-export for test utilities.
 *
 * Tests can `import { renderWithProviders, makeUser } from '@/test-utils'`
 * regardless of which sub-module a helper lives in.
 */
export {
  renderWithProviders,
  makeTestQueryClient,
  createTestQueryClient,
  type RenderWithProvidersOptions,
  type RenderWithProvidersResult,
} from './render';
export {
  makeUser,
  makeOrg,
  makeSite,
  makeDevice,
  resetFactoryIds,
  type OrgFactory,
  type SiteFactory,
  type DeviceFactory,
} from './factories';
