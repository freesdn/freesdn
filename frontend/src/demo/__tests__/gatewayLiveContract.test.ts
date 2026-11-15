// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The demo's gateway live reads pass the checks the gateway page applies to
 * real answers. They had no gateway_id envelope (and the summary and WAN
 * health lacked required fields), so every overview panel of the demo
 * gateway read "Gateway status is unavailable".
 */
import axios from 'axios';
import { describe, expect, it } from 'vitest';
import { validatedAggregate } from '@/pages/firewall/gateway-tabs/gatewayAggregateRead';
import { validatedSystemRead } from '@/pages/firewall/gateway-tabs/gatewaySystemRead';
import { demoIds } from '../identity';
import { demoAxiosAdapter } from '../mockApi';

const client = axios.create({ adapter: demoAxiosAdapter });
const GW = demoIds.opnsense;
const read = (tail: string) => client.get(`/firewall/gateways/${GW}/${tail}`);

describe('demo gateway live reads satisfy the gateway page contract', () => {
  it('device summary', async () => {
    const res = validatedAggregate(await read('device-summary'), GW, 'device-summary');
    expect(res.data.summary.hostname).toBe('hq-fw-01.demo.local');
  });

  it('firmware', async () => {
    const res = validatedSystemRead(await read('firmware'), GW, 'firmware');
    expect(res.data.firmware.current_version).toBe('24.7.8_1');
  });

  it('WAN health', async () => {
    const res = validatedSystemRead(await read('health'), GW, 'health');
    expect(res.data.gateways).toHaveLength(2);
  });

  it('names the gateway it answers for', async () => {
    expect((await read('firewall-rules')).data.gateway_id).toBe(GW);
  });
});
