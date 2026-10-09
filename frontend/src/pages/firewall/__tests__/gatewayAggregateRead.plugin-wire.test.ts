import { expect, it } from 'vitest';
import { validatedAggregate } from '../gateway-tabs/gatewayAggregateRead';

const ID = 'owned-gateway';
function response(total = 75) {
  const count = Math.min(total, 50);
  return { data: { gateway_id: ID, vendor: 'opnsense', crowdsec: {
    running: true, alerts: Array.from({ length: count }, (_, id) => ({ id })), decisions: [],
    alert_count: count, decision_count: 0, alert_total: total, decision_total: 0,
    alert_truncated: total > count, decision_truncated: false,
  } } };
}

it.each([0, 1, 50, 75])('preserves a consistent CrowdSec window with total %s', total => {
  const result = response(total);
  expect(validatedAggregate(result, ID, 'crowdsec')).toBe(result);
});

const invalid = [
  { total: -1, truncated: false }, { total: 1.5, truncated: false },
  { total: '75', truncated: true }, { total: Infinity, truncated: true },
  { total: 49, truncated: false }, { total: 75, truncated: false },
  { total: 75, truncated: 'true' }, { total: undefined, truncated: true },
];
for (const prefix of ['alert', 'decision']) {
  it.each(invalid)(`rejects inconsistent ${prefix} window metadata %j`, metadata => {
    const result = response();
    const body: Record<string, unknown> = result.data.crowdsec;
    body[`${prefix}_total`] = metadata.total;
    body[`${prefix}_truncated`] = metadata.truncated;
    expect(() => validatedAggregate(result, ID, 'crowdsec')).toThrow('Gateway status is unavailable');
  });
}

it('preserves an older normalized envelope without window metadata', () => {
  const result = { data: { gateway_id: ID, crowdsec: { running: true, alerts: [], decisions: [], alert_count: 0, decision_count: 0 } } };
  expect(validatedAggregate(result, ID, 'crowdsec')).toBe(result);
});
