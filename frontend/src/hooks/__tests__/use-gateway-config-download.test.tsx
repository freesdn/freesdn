// SPDX-License-Identifier: AGPL-3.0-only
import { act, renderHook } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useGatewayConfigDownload } from '../use-gateway-config-download';

const state = vi.hoisted(() => ({ download: vi.fn(), toast: vi.fn() }));
vi.mock('@/lib/api', () => ({ gatewayApi: { downloadConfig: state.download } }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: state.toast }) }));
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }));

it.each([undefined, ''])('does not download or fail cleanup for absent gateway ID %s', async (id) => {
  const view = renderHook(() => useGatewayConfigDownload(id));
  await act(async () => { await view.result.current.download(); });
  expect(view.result.current.isDownloading).toBe(false);
  expect(state.download).not.toHaveBeenCalled();
  expect(state.toast).not.toHaveBeenCalled();
  expect(() => view.unmount()).not.toThrow();
});
