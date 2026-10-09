// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
export type GatewayAggregateKind = 'vpn' | 'device-summary' | 'tailscale' | 'haproxy' | 'proxy' | 'crowdsec' | 'monit' | 'telegraf' | 'netflow';

const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const scalar = (value: unknown) => value == null || typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value));
function reject(): never { throw new Error('Gateway status is unavailable'); }

function booleans(body: Record<string, unknown>, ...keys: string[]) {
  if (keys.some(key => typeof body[key] !== 'boolean')) reject();
}

function rows(body: Record<string, unknown>, key: string, count?: string) {
  const values = body[key];
  if (!Array.isArray(values) || values.some(row => !record(row) || Object.values(row).some(value => !scalar(value)))) reject();
  if (count && (typeof body[count] !== 'number' || body[count] !== values.length)) reject();
}

function jsonValue(value: unknown, depth = 0): boolean {
  if (depth > 32) return false;
  if (scalar(value)) return true;
  if (Array.isArray(value)) return value.every(item => jsonValue(item, depth + 1));
  return record(value) && Object.values(value).every(item => jsonValue(item, depth + 1));
}

/** Validate the selected gateway and normalized envelope without changing Axios data. */
export function validatedAggregate<T extends { data: unknown }>(response: T, gatewayId: string, kind: GatewayAggregateKind): T {
  const envelope = response.data;
  if (!record(envelope) || envelope.gateway_id !== gatewayId) reject();
  const key = kind === 'vpn' ? 'tunnels' : kind === 'device-summary' ? 'summary' : kind;
  const body = envelope[key];
  if (!record(body) || Object.keys(body).length === 0) reject();
  if (kind === 'vpn') {
    if (!jsonValue(body)) reject();
    return response;
  }
  if (kind === 'device-summary' && envelope.vendor === 'openwrt') {
    const fields = ['interfaces_total', 'interfaces_up', 'uptime', 'memory_total', 'memory_free', 'services_total'];
    for (const field of fields) {
      const value = body[field];
      if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) reject();
    }
    if (Number(body.interfaces_up) > Number(body.interfaces_total) || Number(body.memory_free) > Number(body.memory_total)) reject();
    if (['hostname', 'model', 'version'].some(field => typeof body[field] !== 'string')) reject();
    if (!record(body.capabilities) || Object.values(body.capabilities).some(value => typeof value !== 'boolean')) reject();
    if (Object.entries(body).some(([name, value]) => name !== 'capabilities' && !scalar(value))) reject();
    return response;
  }
  const lists: Record<string, string | undefined> = kind === 'haproxy'
    ? { servers: 'server_count', backends: 'backend_count', frontends: 'frontend_count', acls: undefined, actions: undefined }
    : kind === 'crowdsec' ? { alerts: 'alert_count', decisions: 'decision_count' }
      : kind === 'monit' ? { services: 'service_count', tests: 'test_count', alerts: 'alert_count' } : {};
  for (const [name, count] of Object.entries(lists)) rows(body, name, count);
  for (const [name, value] of Object.entries(body)) {
    if (name in lists || (kind === 'tailscale' && name === 'settings')) continue;
    if (!scalar(value)) reject();
  }
  if (kind === 'crowdsec') {
    for (const prefix of ['alert', 'decision']) {
      const total = body[`${prefix}_total`], truncated = body[`${prefix}_truncated`];
      if (total === undefined && truncated === undefined) continue;
      const count = body[`${prefix}_count`];
      if (typeof total !== 'number' || !Number.isSafeInteger(total) || total < Number(count)) reject();
      if (typeof truncated !== 'boolean' || truncated !== (total > Number(count))) reject();
      if (Number(count) !== Math.min(total, 50)) reject();
    }
  }
  if (kind === 'device-summary') {
    const counts = ['interface_count', 'interfaces_up', 'interfaces_down'].map(name => body[name]);
    // Older normalized summaries omit this field; explicit null is still invalid.
    const unknown = body.interfaces_unknown === undefined ? 0 : body.interfaces_unknown;
    if ([...counts, unknown].some(value => typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0)) reject();
    if (Number(counts[0]) !== Number(counts[1]) + Number(counts[2]) + Number(unknown)) reject();
    if (['hostname', 'version', 'wan_status'].some(name => typeof body[name] !== 'string')) reject();
  } else if (kind === 'tailscale') {
    booleans(body, 'running');
    const settings = body.settings;
    if (!record(settings)) reject();
    booleans(settings, 'enabled');
    for (const [name, value] of Object.entries(settings)) {
      if (name === 'use_exit_node') {
        if (!Array.isArray(value) || value.some(item => typeof item !== 'string')) reject();
      } else if (!scalar(value)) reject();
    }
  } else if (kind === 'proxy') booleans(body, 'enabled', 'running', 'ssl_inspection', 'transparent_mode', 'cache_enabled', 'logging');
  else if (kind === 'telegraf') booleans(body, 'enabled', 'running', 'output_influxdb', 'output_graphite', 'output_prometheus');
  else if (kind === 'netflow') booleans(body, 'enabled', 'collect_enabled', 'running');
  else if (kind === 'crowdsec' || kind === 'monit') booleans(body, 'running');
  return response;
}
