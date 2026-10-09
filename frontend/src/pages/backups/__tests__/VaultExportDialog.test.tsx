// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Component contract with owned scope fakes; not browser/authentication proof. */
import { StrictMode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { VaultExportDialog, type OwnedVaultScope } from '../VaultExportDialog';
const subscription = vi.hoisted(() => ({ current: undefined as (() => void) | undefined }));
vi.mock('@/stores/authStore', () => ({ useAuthStore: { subscribe: (callback: () => void) => {
  subscription.current = callback; return () => { subscription.current = undefined; };
} } }));
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (_key: string, fallback: string) => fallback }) }));
function scope(method: 'local' | 'ldap' | 'oidc' = 'local', mfa = false) {
  return { assertCurrent: vi.fn(), dispose: vi.fn(),
    requirements: vi.fn(async () => ({ method, mfa_required: mfa, oidc_redirect_uri: null })),
    authorizeLocal: vi.fn(async () => undefined), confirmLdap: vi.fn(async () => undefined),
    beginOidc: vi.fn(), completeOidc: vi.fn(), authorizeExternal: vi.fn(async () => undefined),
    create: vi.fn(async () => ({ id: 'owned-id', status: 'completed' })),
    observeLegacy: vi.fn(async () => ({ artifact_integrity: 'legacy_unverified' })),
    download: vi.fn(async () => ({ blob: new Blob(['owned sealed bytes']), artifact_integrity: 'legacy_unverified' })),
  };
}
async function requirements() { fireEvent.click(screen.getByText('Check confirmation requirements')); await screen.findByLabelText('Current account password'); }
afterEach(() => { cleanup(); vi.restoreAllMocks(); subscription.current = undefined; });
describe('vault confirmation dialog', () => {
  it.each(['local', 'ldap'] as const)('requires %s and MFA before one create; no request occurs on mount', async method => {
    const a = scope(method, true); const done = vi.fn();
    render(<VaultExportDialog scope={a as unknown as OwnedVaultScope} kind="create" onClose={vi.fn()} onComplete={done} />);
    expect(a.requirements).not.toHaveBeenCalled(); expect(a.create).not.toHaveBeenCalled();
    await requirements();
    const button = screen.getByText('Confirm and create vault'); expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Current account password'), { target: { value: 'synthetic-password' } });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Authenticator or remaining recovery code'), { target: { value: '123456' } });
    fireEvent.click(button); fireEvent.click(button);
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1)); expect(a.create).toHaveBeenCalledTimes(1);
    if (method === 'local') { expect(a.authorizeLocal).toHaveBeenCalledWith('synthetic-password', '123456'); expect(a.confirmLdap).not.toHaveBeenCalled(); }
    else { expect(a.confirmLdap).toHaveBeenCalledWith('synthetic-password'); expect(a.authorizeExternal).toHaveBeenCalledWith('123456');
      expect(a.confirmLdap.mock.invocationCallOrder[0]).toBeLessThan(a.authorizeExternal.mock.invocationCallOrder[0]); }
    expect(screen.getByLabelText('Current account password')).toHaveValue('');
  });
  it('does not even read requirements until explicit legacy acknowledgment', async () => {
    const a = scope(); render(<VaultExportDialog scope={a as unknown as OwnedVaultScope} kind="legacy" onClose={vi.fn()} onComplete={vi.fn()} />);
    expect(screen.getByText('Check confirmation requirements')).toBeDisabled(); expect(a.requirements).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('checkbox')); await requirements(); expect(a.requirements).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('checkbox')).toBeDisabled(); expect(a.observeLegacy).not.toHaveBeenCalled();
  });
  it('requires a configured OIDC callback and never falls back to password login', async () => {
    const a = scope('oidc'); render(<VaultExportDialog scope={a as unknown as OwnedVaultScope} kind="create" onClose={vi.fn()} onComplete={vi.fn()} />);
    fireEvent.click(screen.getByText('Check confirmation requirements'));
    await screen.findByText('The administrator must configure the vault OIDC callback before this account can export secrets.');
    expect(screen.getByText('Confirm with identity provider')).toBeDisabled(); expect(screen.queryByLabelText('Current account password')).toBeNull();
    expect(a.authorizeLocal).not.toHaveBeenCalled(); expect(a.create).not.toHaveBeenCalled();
  });
  it('does not render raw secret errors or offer an automatic retry after issuance', async () => {
    const a = scope(); a.authorizeLocal.mockRejectedValue(new Error('synthetic-private-password'));
    render(<VaultExportDialog scope={a as unknown as OwnedVaultScope} kind="create" onClose={vi.fn()} onComplete={vi.fn()} />);
    await requirements(); fireEvent.change(screen.getByLabelText('Current account password'), { target: { value: 'synthetic-password' } });
    fireEvent.click(screen.getByText('Confirm and create vault')); await screen.findByRole('alert');
    expect(screen.queryByText(/synthetic/)).toBeNull(); expect(screen.queryByText('Confirm and create vault')).toBeNull();
    expect(a.authorizeLocal).toHaveBeenCalledTimes(1); expect(a.create).not.toHaveBeenCalled(); expect(a.dispose).toHaveBeenCalled();
  });
  it('disposes and clears entered factors after an observed authority change', async () => {
    const a = scope(); render(<VaultExportDialog scope={a as unknown as OwnedVaultScope} kind="create" onClose={vi.fn()} onComplete={vi.fn()} />);
    await requirements(); fireEvent.change(screen.getByLabelText('Current account password'), { target: { value: 'synthetic-password' } });
    a.assertCurrent.mockImplementation(() => { throw new Error('changed'); }); act(() => subscription.current?.());
    expect(screen.queryByLabelText('Current account password')).toBeNull(); expect(a.dispose).toHaveBeenCalled(); expect(a.create).not.toHaveBeenCalled();
  });
  it('withholds late requirements after a real unmount and disposes the scope', async () => {
    let resolve!: (value: { method: 'local'; mfa_required: boolean; oidc_redirect_uri: null }) => void;
    const a = scope(); a.requirements.mockImplementation(() => new Promise(yes => { resolve = yes; })); const done = vi.fn();
    const view = render(<VaultExportDialog scope={a as unknown as OwnedVaultScope} kind="create" onClose={vi.fn()} onComplete={done} />);
    fireEvent.click(screen.getByText('Check confirmation requirements')); view.unmount();
    await act(async () => { resolve({ method: 'local', mfa_required: false, oidc_redirect_uri: null }); });
    expect(a.dispose).toHaveBeenCalled(); expect(done).not.toHaveBeenCalled(); expect(a.create).not.toHaveBeenCalled();
  });
  it('does not dispose a newly mounted scope during StrictMode effect replay', async () => {
    const a = scope(); const view = render(<StrictMode><VaultExportDialog scope={a as unknown as OwnedVaultScope} kind="create" onClose={vi.fn()} onComplete={vi.fn()} /></StrictMode>);
    await act(async () => { await Promise.resolve(); }); expect(a.dispose).not.toHaveBeenCalled();
    view.unmount(); await act(async () => { await Promise.resolve(); }); expect(a.dispose).toHaveBeenCalledTimes(1);
  });
});
