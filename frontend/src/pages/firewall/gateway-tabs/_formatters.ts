// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Shared helpers used across GatewayDetailPage tabs.
 *
 * Lives next to the tab files so the tabs can be extracted into siblings
 * without depending on the parent GatewayDetailPage file. The leading underscore
 * keeps it sorted at the top of the directory listing and signals "internal".
 */

export const vendorLabels: Record<string, string> = {
  opnsense: 'OPNsense',
  pfsense: 'pfSense',
  mikrotik: 'MikroTik',
  openwrt: 'OpenWRT',
};
