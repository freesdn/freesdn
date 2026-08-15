// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * React hook for device capability-based feature gating.
 * 
 * Usage:
 *   const { capabilities, canPoeControl, isLoading } = useDeviceCapabilities(deviceId);
 *   
 *   // Conditionally render based on capabilities
 *   {canPoeControl && <PoEControls deviceId={deviceId} />}
 *   
 *   // Check specific capability
 *   {capabilities?.effective_caps['port.vlan_config']?.can_write && <VlanEditor />}
 *   
 *   // Show reason why feature is disabled
 *   {!canPoeControl && capabilities?.profile_restrictions['port.poe_control'] && (
 *     <Tooltip content={capabilities.profile_restrictions['port.poe_control']}>
 *       <Badge variant="secondary">PoE Not Supported</Badge>
 *     </Tooltip>
 *   )}
 */

import { useQuery } from '@tanstack/react-query';
import { deviceControlApi, DeviceCapabilitiesResponse, CapabilityDetail } from '@/lib/api';

interface UseDeviceCapabilitiesResult {
  /** Full capabilities response */
  capabilities: DeviceCapabilitiesResponse | undefined;
  
  /** Loading state */
  isLoading: boolean;
  
  /** Error state */
  error: Error | null;
  
  /** Refetch capabilities */
  refetch: () => void;
  
  // Convenience booleans for common checks
  canPoeControl: boolean;
  canPoeStatus: boolean;
  canPortControl: boolean;
  canPortStatus: boolean;
  canPortConfig: boolean;
  canVlanConfig: boolean;
  canSsidControl: boolean;
  canClientList: boolean;
  canFirmwareUpdate: boolean;
  canBackup: boolean;
  canReboot: boolean;
  
  // Helper functions
  /** Check if a specific capability is supported */
  hasCapability: (capabilityKey: string) => boolean;
  
  /** Check if a specific capability supports writes */
  canWrite: (capabilityKey: string) => boolean;
  
  /** Get the reason why a capability is disabled */
  getDisabledReason: (capabilityKey: string) => string | undefined;
  
  /** Get detailed info for a capability */
  getCapabilityDetail: (capabilityKey: string) => CapabilityDetail | undefined;
}

export function useDeviceCapabilities(
  deviceId: string | undefined | null
): UseDeviceCapabilitiesResult {
  const {
    data: capabilities,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['deviceCapabilities', deviceId],
    queryFn: async () => {
      if (!deviceId) throw new Error('Device ID required');
      const response = await deviceControlApi.getCapabilities(deviceId);
      return response.data;
    },
    enabled: !!deviceId,
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
    retry: 1,
  });

  // Helper functions
  const hasCapability = (capabilityKey: string): boolean => {
    if (!capabilities?.effective_caps) return false;
    const cap = capabilities.effective_caps[capabilityKey];
    return cap?.supported ?? false;
  };

  const canWrite = (capabilityKey: string): boolean => {
    if (!capabilities?.effective_caps) return false;
    const cap = capabilities.effective_caps[capabilityKey];
    return cap?.supported && cap?.can_write;
  };

  const getDisabledReason = (capabilityKey: string): string | undefined => {
    if (!capabilities) return undefined;
    // First check profile restrictions (with guard for undefined)
    if (capabilities.profile_restrictions?.[capabilityKey]) {
      return capabilities.profile_restrictions[capabilityKey];
    }
    // Then check effective caps (with guard for undefined)
    const cap = capabilities.effective_caps?.[capabilityKey];
    return cap?.reason_disabled;
  };

  const getCapabilityDetail = (capabilityKey: string): CapabilityDetail | undefined => {
    return capabilities?.effective_caps?.[capabilityKey];
  };

  return {
    capabilities,
    isLoading,
    error: error as Error | null,
    refetch,
    
    // Convenience booleans (from API response)
    canPoeControl: capabilities?.can_poe_control ?? false,
    canPoeStatus: capabilities?.can_poe_status ?? false,
    canPortControl: capabilities?.can_port_control ?? false,
    canPortStatus: capabilities?.can_port_status ?? false,
    canPortConfig: capabilities?.can_port_config ?? false,
    canVlanConfig: capabilities?.can_vlan_config ?? false,
    canSsidControl: capabilities?.can_ssid_control ?? false,
    canClientList: capabilities?.can_client_list ?? false,
    canFirmwareUpdate: capabilities?.can_firmware_update ?? false,
    canBackup: capabilities?.can_backup ?? false,
    canReboot: capabilities?.can_reboot ?? false,
    
    // Helper functions
    hasCapability,
    canWrite,
    getDisabledReason,
    getCapabilityDetail,
  };
}

/**
 * Hook for checking multiple device capabilities at once.
 * Useful for pages that display multiple devices.
 */
export function useMultipleDeviceCapabilities(
  deviceIds: string[]
): Map<string, UseDeviceCapabilitiesResult> {
  const results = new Map<string, UseDeviceCapabilitiesResult>();
  
  // This would need to be implemented with proper parallel queries
  // For now, return empty map - consumers should use individual hooks
  deviceIds.forEach(_id => {
    // Note: This is a simplified implementation
    // In production, use useQueries for parallel fetching
  });
  
  return results;
}

export default useDeviceCapabilities;
