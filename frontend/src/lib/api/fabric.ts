// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
//
// Fabric, the universal app-interconnect. Catalog (sources + operations) and
// operator-authored Connections (event -> step chain). Mirrors the backend
// GET /fabric/catalog + the /fabric/connections CRUD + /test + /runs surface.
import { api } from './client';

export type OperationTier = 'native' | 'plugin';

export interface FabricOperation {
  id: string;
  title: string;
  description: string;
  input_schema: Record<string, unknown>;
  produces: string[];
  accepts: string[];
  permission: string | null;
  write: boolean;
  feature: string | null;
  tier: OperationTier;
  provider_id: string;
}

export interface FabricEvent {
  event_type: string;
  title: string;
  description: string;
  payload_schema: Record<string, unknown>;
  produces: string[];
  tier: OperationTier;
  provider_id: string;
}

export interface FabricAiTool {
  name: string;
  description: string;
  permission: string | null;
  tier: string;
}

export interface FabricCatalog {
  operations: FabricOperation[];
  events: FabricEvent[];
  ai_tools: FabricAiTool[];
  counts: Record<string, number>;
}

export interface FabricStep {
  operation_id: string;
  params?: Record<string, unknown>;
  continue_on_error?: boolean;
}

export interface FabricConnection {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  source_event: string;
  conditions: Record<string, unknown> | null;
  steps: FabricStep[];
  cooldown_seconds: number;
  last_run_at: string | null;
  run_count: number;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface FabricConnectionCreate {
  name: string;
  source_event: string;
  steps: FabricStep[];
  description?: string | null;
  conditions?: Record<string, unknown> | null;
  enabled?: boolean;
  cooldown_seconds?: number;
}

export interface FabricRun {
  id: string;
  connection_id: string;
  source_event_type: string;
  trigger_payload: Record<string, unknown>;
  success: boolean;
  steps: Array<Record<string, unknown>>;
  error: string | null;
  duration_ms: number;
  created_at: string | null;
}

// A catalog operation annotated for a specific source event by the negotiator's
// matchmaking: `match` is "artifact" (the event produces a media-type this op
// consumes) or "data" (no input artifact needed); `allowed` is whether the
// current user may author a step with it (mirrors the create/update gate).
export interface FabricSuggestedTarget extends FabricOperation {
  match: 'artifact' | 'data';
  allowed: boolean;
}

export interface FabricSuggestion {
  source_event: string;
  event: FabricEvent | null;
  targets: FabricSuggestedTarget[];
  counts: { total: number; allowed: number };
}

export const fabricApi = {
  getCatalog: () => api.get<FabricCatalog>('/fabric/catalog'),

  listConnections: (enabled?: boolean) =>
    api.get<{ connections: FabricConnection[]; total: number }>('/fabric/connections', {
      params: enabled === undefined ? {} : { enabled },
    }),
  getConnection: (id: string) => api.get<FabricConnection>(`/fabric/connections/${id}`),
  createConnection: (data: FabricConnectionCreate) =>
    api.post<FabricConnection>('/fabric/connections', data),
  updateConnection: (id: string, data: Partial<FabricConnectionCreate>) =>
    api.patch<FabricConnection>(`/fabric/connections/${id}`, data),
  deleteConnection: (id: string) => api.delete(`/fabric/connections/${id}`),

  // Operator-initiated single firing (stages writes; same gates as a live fire).
  testConnection: (id: string, payload: Record<string, unknown> = {}) =>
    api.post(`/fabric/connections/${id}/test`, { payload }),

  listRuns: (id: string, limit = 50) =>
    api.get<{ runs: FabricRun[]; total: number }>(`/fabric/connections/${id}/runs`, {
      params: { limit },
    }),

  // Negotiator matchmaking: operations compatible with a source event, each
  // annotated with match-kind + whether the caller may author it.
  suggestTargets: (sourceEvent: string) =>
    api.get<FabricSuggestion>('/fabric/connections/suggest', {
      params: { source_event: sourceEvent },
    }),
};
