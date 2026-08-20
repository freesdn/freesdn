// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Barrel file · re-exports every API client and type so that
 *   import { devicesApi, SwitchSummary } from '@/lib/api'
 * continues to work unchanged.
 */

// Core axios instance & helpers
export { api, apiClient, API_URL, getCookie, getWebSocketUrl, getApiErrorMessage } from './client';

// All TypeScript types / interfaces
export * from './types';

// Domain API clients
export { devicesApi, actionsApi, deviceControlApi } from './devices';
export {
  controllersApi,
  type TestConnectionResult,
  type ControllerMetadata,
  type StorageInventory,
  type StoragePool,
  type StorageDisk,
  type StorageDataset,
  type StorageAlert,
  type StorageService,
} from './controllers';
export { sitesApi, sitesApiV2 } from './sites';
export { usersApi } from './users';
export { camerasApi, nvrApi, cameraAccessApi, cameraDiscoveryApi, evidenceApi, cameraReportsApi, type EvidenceArchive, type CameraReport } from './cameras';
export { discoveryApi } from './discovery';
export { analyticsApi } from './analytics';
export { systemApi, backupApi, storageLocationsApi, configApi, notificationApi, modulesApi } from './system';
export { accessPointsApi, switchesApi, poeApi, networkApi } from './network';
export { credentialsApi, securityAuditApi } from './security';
export { automationApi, webhooksApi, integrationsApi, firmwareApi } from './config';
export { agentsApi, agentDownloadsApi } from './agents';
export { voipApi } from './voip';
export { vpnApi } from './vpn';
export type { OverlayDiscoveredDevice, OverlayDiscoveryResult } from './vpn';
export { firewallApi } from './firewall';
export { gatewayApi, gatewayOrchApi } from './gateway';
export { mikrotikApi } from './mikrotik';
export type {
  MikroTikListResponse,
  MikroTikSingletonResponse,
  MikroTikChangeRequest,
  MikroTikPendingChange,
  MikroTikOperation,
  MikroTikIdentity,
  MikroTikResource,
  MikroTikRouterboard,
  MikroTikClock,
  MikroTikSystemHealth,
  MikroTikSystemInfoResponse,
  MikroTikEthernetInterface,
  MikroTikBridgeInterface,
  MikroTikGenericInterface,
  MikroTikIPAddress,
  MikroTikIPPool,
  MikroTikRoute,
  MikroTikDHCPServer,
  MikroTikDHCPLease,
  MikroTikDHCPNetwork,
  MikroTikFirewallFilterRule,
  MikroTikFirewallNATRule,
  MikroTikDNSSettings,
  MikroTikDNSStaticEntry,
  MikroTikDNSCacheEntry,
  MikroTikL2TPServer,
  MikroTikPPTPServer,
  MikroTikPPPSecret,
  MikroTikCertificate,
  MikroTikHotspotServer,
  MikroTikHotspotUserProfile,
  MikroTikHotspotActive,
  MikroTikSimpleQueue,
  MikroTikQueueTree,

  MikroTikFirmwareStatus,
  MikroTikFirmwareStatusResponse,
  MikroTikPackage,
  MikroTikBackupFile,
  MikroTikBackupContent,
  MikroTikNeighbor,
  MikroTikNeighborDiscoverySettings,
  MikroTikLldpInterface,
  MikroTikTopologyNode,
  MikroTikTopologyEdge,
  MikroTikTopologyResponse,
  MikroTikSnmpTrapTarget,
  MikroTikSnmpV3User,
} from './mikrotik';
export { enterpriseApi, correlationApi, slaApi, topologyApi, alertRulesApi } from './enterprise';
export { hypervisorApi, type RemoteMigrateRequest, type CreateSdnZoneRequest, type CreateSdnVnetRequest } from './hypervisor';
export {
  listChangesForGateway,
  applyChange as applyPendingChange,
  discardChange as discardPendingChange,
  stagePbxChange,
  describeApplyError,
  type GatewayVendor,
  type ListChangesParams,
  type ApplyErrorInfo,
  type PendingChangeResponse,
  type ChangeStatus as PendingChangeStatus,
  type ApplyPendingChangeRequest,
  type StagePbxChangeParams,
  type FreePBXDomain,
} from './pendingChanges';
