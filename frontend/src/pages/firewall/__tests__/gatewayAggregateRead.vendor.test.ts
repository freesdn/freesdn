/** Existing OpenWrt summary API contract remains usable by the query validator. */
import { expect, it } from 'vitest';
import { validatedAggregate } from '../gateway-tabs/gatewayAggregateRead';

const ID = 'owned-gateway';
const response = () => ({ data: { gateway_id: ID, vendor: 'openwrt', summary: {
  hostname: 'owned-host', model: 'owned-model', version: 'owned-version', uptime: 120,
  interfaces_total: 2, interfaces_up: 1, memory_total: 1024, memory_free: 512,
  services_total: 3, capabilities: { wireguard: true },
} } });

it('accepts the existing OpenWrt summary without changing Axios response identity', () => {
  const value = response();
  expect(validatedAggregate(value, ID, 'device-summary')).toBe(value);
});

it('rejects an OpenWrt summary for another selected gateway', () => {
  expect(() => validatedAggregate(response(), 'other-gateway', 'device-summary')).toThrow('Gateway status is unavailable');
});

it('rejects OpenWrt summary counts which exceed their total', () => {
  const value = response(); value.data.summary.interfaces_up = 3;
  expect(() => validatedAggregate(value, ID, 'device-summary')).toThrow('Gateway status is unavailable');
});

it('rejects a capability object containing non-boolean values', () => {
  const value = response();
  const malformed = { data: { ...value.data, summary: { ...value.data.summary, capabilities: { wireguard: 'false' } } } };
  expect(() => validatedAggregate(malformed, ID, 'device-summary')).toThrow('Gateway status is unavailable');
});
