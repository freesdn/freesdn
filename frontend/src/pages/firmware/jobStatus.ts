/** Queue acceptance and missing per-device results are never completion evidence. */
export function firmwareDeviceOutcome(job: Record<string, unknown> | undefined, deviceId: string) {
  const results = Array.isArray(job?.devices) ? job.devices as Record<string, unknown>[] : [];
  const result = results.find(item => item.device_id === deviceId);
  const status = result?.status;
  const message = String(result?.message ?? job?.error_message ?? '');
  if (status === 'completed') return { status: 'success' as const, message };
  if (status === 'failed' || status === 'cancelled' || job?.status === 'failed' || job?.status === 'cancelled') {
    return { status: 'failed' as const, message };
  }
  if (status === 'running') return { status: 'running' as const, message };
  return { status: 'pending' as const, message };
}
