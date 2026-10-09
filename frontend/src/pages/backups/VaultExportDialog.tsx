// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { useAuthStore } from '@/stores/authStore';
import { beginVaultExport, type VaultFactorRequirements } from '@/lib/api/vaultExportTransport';
import { openVaultIdentityWindow } from '@/lib/api/vaultIdentityWindow';

export type OwnedVaultScope = ReturnType<typeof beginVaultExport>;
export type VaultExportResult = { kind: 'created'; id: string; status: string }
  | { kind: 'downloaded'; artifact_integrity: 'verified' | 'legacy_unverified' };

/** The caller captures the scope on a user action, before displaying this
 * dialog. Secret inputs never enter a query key, mutation cache or storage.
 * Closing aborts local work; it cannot roll back an issued server request.
 */
export function VaultExportDialog({ scope, kind, onClose, onComplete }: {
  scope: OwnedVaultScope; kind: 'create' | 'recorded' | 'legacy';
  onClose: () => void; onComplete: (result: VaultExportResult) => void;
}) {
  const { t } = useTranslation('backup');
  const [requirements, setRequirements] = useState<VaultFactorRequirements | null>(null);
  const [password, setPassword] = useState(''); const [mfa, setMfa] = useState('');
  const [ack, setAck] = useState(false); const [externalReady, setExternalReady] = useState(false);
  const [busy, setBusy] = useState(false); const [ended, setEnded] = useState(false);
  const [error, setError] = useState(false);
  const mounted = useRef(false); const generation = useRef({ value: 0 }); const inFlight = useRef(false);
  const popup = useRef<ReturnType<typeof openVaultIdentityWindow> | null>(null);
  const close = () => { scope.dispose(); popup.current?.cancel(); setPassword(''); setMfa(''); onClose(); };
  useEffect(() => {
    mounted.current = true; const lifecycle = generation.current; const own = ++lifecycle.value;
    const unsubscribe = useAuthStore.subscribe(() => {
      try { scope.assertCurrent(); } catch {
        scope.dispose(); popup.current?.cancel(); setPassword(''); setMfa(''); setEnded(true); setError(true);
      }
    });
    return () => {
      mounted.current = false; unsubscribe();
      // StrictMode immediately re-registers this effect. A real unmount still
      // suppresses late UI work synchronously and disposes the owned scope.
      queueMicrotask(() => { if (lifecycle.value === own) { scope.dispose(); popup.current?.cancel(); } });
    };
  }, [scope]);

  const run = (work: () => Promise<void>) => {
    if (inFlight.current || ended) return;
    inFlight.current = true; setBusy(true);
    void (async () => {
      try { scope.assertCurrent(); await work(); }
      catch { scope.dispose(); popup.current?.cancel(); if (mounted.current) { setError(true); setEnded(true); } }
      finally { inFlight.current = false; if (mounted.current) { setPassword(''); setMfa(''); setBusy(false); } }
    })();
  };
  const finish = async () => {
    if (kind === 'create') {
      const value = await scope.create(); scope.assertCurrent();
      if (!mounted.current) return;
      onComplete({ kind: 'created', ...value });
    } else {
      if (kind === 'legacy') await scope.observeLegacy();
      const value = await scope.download(); scope.assertCurrent();
      if (!mounted.current) return;
      const url = URL.createObjectURL(value.blob); const link = document.createElement('a');
      try {
        link.href = url; link.download = kind === 'legacy' ? 'freesdn-legacy-unverified.fsdnvault' : 'freesdn-backup.fsdnvault';
        document.body.appendChild(link);
        scope.assertCurrent(); if (!mounted.current) return;
        link.click();
        onComplete({ kind: 'downloaded', artifact_integrity: value.artifact_integrity });
      } finally { link.remove(); URL.revokeObjectURL(url); }
    }
    scope.dispose();
  };
  const confirm = () => run(async () => {
    if (!requirements || (kind === 'legacy' && !ack)) throw new Error();
    const code = requirements.mfa_required ? mfa : undefined;
    const suppliedPassword = password; setPassword(''); setMfa('');
    if (requirements.method === 'local') await scope.authorizeLocal(suppliedPassword, code);
    else {
      if (requirements.method === 'ldap') await scope.confirmLdap(suppliedPassword);
      else if (!externalReady) throw new Error();
      await scope.authorizeExternal(code);
    }
    await finish();
  });
  const startOidc = () => {
    if (inFlight.current || ended || !requirements?.oidc_redirect_uri) return;
    // Open inside the gesture, not after awaiting an HTTP request.
    try { popup.current = openVaultIdentityWindow(requirements.oidc_redirect_uri, scope.assertCurrent); }
    catch { setError(true); setEnded(true); scope.dispose(); return; }
    const owned = popup.current;
    run(async () => {
      owned.navigate(await scope.beginOidc());
      const response = await owned.result;
      await scope.completeOidc(response.state, response.code); scope.assertCurrent();
      if (mounted.current) setExternalReady(true);
    });
  };

  return <Dialog open onOpenChange={value => { if (!value) close(); }}>
    <DialogContent><DialogHeader>
      <DialogTitle>{t('vaultConfirmation.title', 'Confirm vault export')}</DialogTitle>
      <DialogDescription>{t('vaultConfirmation.description', 'This archive contains secrets. Confirm the current account for this one operation. Closing does not undo an issued request.')}</DialogDescription>
    </DialogHeader>
      {kind === 'legacy' && <div className="space-y-2 rounded border border-destructive p-3">
        <p>{t('vaultConfirmation.legacyWarning', 'This archive has no recorded original identity. Checking its current bytes cannot prove historical authenticity. Use only an archive whose origin you trust.')}</p>
        <Label className="flex items-center gap-2"><Checkbox checked={ack} disabled={busy || !!requirements || ended} onCheckedChange={v => setAck(v === true)} />
          {t('vaultConfirmation.legacyAck', 'I understand the legacy archive limitation.')}</Label>
      </div>}
      {error && <p role="alert">{t('vaultConfirmation.unconfirmed', 'Confirmation ended or the outcome is unconfirmed. Inspect the backup catalogue before starting another operation. Do not assume a failed response rolled back a backup.')}</p>}
      {requirements && !ended && <div className="space-y-3">
        {requirements.method !== 'oidc' && <div><Label htmlFor="vault-current-password">{t('vaultConfirmation.password', 'Current account password')}</Label>
          <Input id="vault-current-password" type="password" autoComplete="current-password" maxLength={1024} value={password} disabled={busy} onChange={e => setPassword(e.target.value)} /></div>}
        {requirements.method === 'oidc' && !externalReady && <Button disabled={busy || !requirements.oidc_redirect_uri} onClick={startOidc}>
          {t('vaultConfirmation.openIdentity', 'Confirm with identity provider')}</Button>}
        {requirements.method === 'oidc' && !requirements.oidc_redirect_uri && <p role="alert">{t('vaultConfirmation.callbackMissing', 'The administrator must configure the vault OIDC callback before this account can export secrets.')}</p>}
        {requirements.mfa_required && (requirements.method !== 'oidc' || externalReady) && <div>
          <Label htmlFor="vault-current-mfa">{t('vaultConfirmation.mfa', 'Authenticator or remaining recovery code')}</Label>
          <Input id="vault-current-mfa" autoComplete="one-time-code" maxLength={10} value={mfa} disabled={busy} onChange={e => setMfa(e.target.value)} /></div>}
      </div>}
      <DialogFooter><Button variant="outline" onClick={close}>{t('vaultConfirmation.close', 'Close')}</Button>
        {!requirements && !ended && <Button disabled={busy || (kind === 'legacy' && !ack)} onClick={() => run(async () => {
          const value = await scope.requirements(); if (mounted.current) setRequirements(value);
        })}>{t('vaultConfirmation.continue', 'Check confirmation requirements')}</Button>}
        {requirements && !ended && (requirements.method !== 'oidc' || externalReady) && <Button
          disabled={busy || (requirements.method !== 'oidc' && !password) || (requirements.mfa_required && !mfa)} onClick={confirm}>
          {kind === 'create' ? t('vaultConfirmation.create', 'Confirm and create vault') : t('vaultConfirmation.download', 'Confirm and download vault')}
        </Button>}
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}
