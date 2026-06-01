// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Barrel re-export for MikroTik tab shared helpers.
 *
 * These helpers let individual tabs
 * import a stable, consistent set of validation inputs + type
 * narrowing primitives without each tab redefining its own copy.
 *
 * TODO(i18n): all human-readable copy in the 9 MikroTik tabs is still
 * hard-coded English. Wiring `useTranslation` across hundreds of
 * strings remains future work.
 */
export {
  IpInput,
  CidrInput,
  MacInput,
  VlanInput,
  PortInput,
  IP_PATTERN,
  CIDR_PATTERN,
  MAC_PATTERN,
  VLAN_MIN,
  VLAN_MAX,
  PORT_MIN,
  PORT_MAX,
  isValidIp,
  isValidCidr,
  isValidMac,
  isValidVlan,
  isValidPort,
  normalizeMac,
} from './inputs';

export { getRouterId, getRouterStr, getRouterBool } from './types';
