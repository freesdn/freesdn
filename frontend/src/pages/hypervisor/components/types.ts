// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Shared Types
 */
import type { QueryClient } from '@tanstack/react-query';
import type { HypervisorNode, HypervisorVM } from '@/lib/api';

export interface HypervisorTabProps {
  controllerId: string;
  nodes: HypervisorNode[];
  queryClient: QueryClient;
}

export interface VMTableProps extends HypervisorTabProps {
  items: HypervisorVM[];
  loading: boolean;
  error: boolean;
  refetch: () => void;
  label: string;
  onVmAction: (params: { node: string; vmType: string; vmid: number; action: string }) => void;
  onDelete: (params: { node: string; vmType: string; vmid: number }) => void;
  onClone: (vm: HypervisorVM) => void;
  onMigrate: (vm: HypervisorVM) => void;
  onResize: (vm: HypervisorVM) => void;
  onBackup: (vm: HypervisorVM) => void;
  onSnapshot: (vm: HypervisorVM) => void;
  onSnapList: (vm: HypervisorVM) => void;
  onConsole: (vm: HypervisorVM) => void;
  onEditConfig: (vm: HypervisorVM) => void;
  /** Bulk selection state */
  selectedVMs: Set<string>;
  onToggleSelect: (key: string) => void;
  onToggleSelectAll: () => void;
}

/** Unique key for a VM in bulk selection */
export function vmKey(vm: { node: string; vm_type: string; vmid: number }): string {
  return `${vm.node}:${vm.vm_type}:${vm.vmid}`;
}

export interface BulkTarget {
  node: string;
  vm_type: string;
  vmid: number;
}
