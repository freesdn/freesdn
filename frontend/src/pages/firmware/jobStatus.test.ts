import { describe, expect, it } from 'vitest';
import { firmwareDeviceOutcome } from './jobStatus';

describe('firmware device outcomes', () => {
  it('never turns queue acceptance or missing results into success', () => {
    for (const job of [undefined, { status: 'pending' }, { devices: [] }, { status: 'completed', devices: [] }]) {
      expect(firmwareDeviceOutcome(job, 'device').status).toBe('pending');
    }
  });
  it('requires an explicit completed result for the selected device', () => {
    expect(firmwareDeviceOutcome({ devices: [{ device_id: 'other', status: 'completed' }] }, 'device').status).toBe('pending');
    expect(firmwareDeviceOutcome({ devices: [{ device_id: 'device', status: 'completed' }] }, 'device').status).toBe('success');
  });
  it('preserves running and unsupported failure outcomes', () => {
    expect(firmwareDeviceOutcome({ devices: [{ device_id: 'device', status: 'running' }] }, 'device').status).toBe('running');
    expect(firmwareDeviceOutcome({ status: 'failed', error_message: 'Unsupported' }, 'device')).toEqual({ status: 'failed', message: 'Unsupported' });
  });
});
