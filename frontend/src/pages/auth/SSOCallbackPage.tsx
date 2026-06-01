// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * SSOCallbackPage · Handles OIDC/SAML SSO callback redirects.
 * 
 * The IdP redirects here with ?code=...&state=... (OIDC) or
 * via a POST with SAMLResponse (SAML).
 */

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuthStore } from '@/stores/authStore';
import { ssoApi } from '@/lib/ssoApi';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Loader2, AlertCircle, CheckCircle } from 'lucide-react';
import { getApiErrorMessage } from '@/lib/api';

type CallbackStatus = 'processing' | 'success' | 'error';

export default function SSOCallbackPage() {
  const { t } = useTranslation('auth');
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState<CallbackStatus>('processing');
  const [errorMsg, setErrorMsg] = useState('');
  const loginWithSSO = useAuthStore((s) => s.loginWithSSO);
  const setMfaPending = useAuthStore((s) => s.setMfaPending);

  useEffect(() => {
    handleCallback();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleCallback() {
    const protocol = sessionStorage.getItem('sso_protocol');
    const savedState = sessionStorage.getItem('sso_state');
    // SAML IdPs return the state in `RelayState`; OIDC uses `state`.
    // We accept either so the downstream validator is protocol-agnostic.
    const state =
      searchParams.get('state') || searchParams.get('RelayState');
    const code = searchParams.get('code');
    const error = searchParams.get('error');
    const errorDescription = searchParams.get('error_description');

    // Clean up session storage immediately so a stale/replayed value
    // cannot be accepted by a second invocation of this page.
    sessionStorage.removeItem('sso_protocol');
    sessionStorage.removeItem('sso_state');

    // Check for IdP error
    if (error) {
      setStatus('error');
      setErrorMsg(errorDescription || error);
      return;
    }

    // ALWAYS validate state, regardless of protocol.
    // Previously SAML skipped this defense-in-depth check, leaving the
    // CSRF gate to the backend alone.  SAML RelayState and OIDC state
    // are both treated as opaque CSRF tokens here.
    if (!state) {
      setStatus('error');
      setErrorMsg(t('SSOCallbackPage.errors.missingState'));
      return;
    }
    if (!savedState) {
      setStatus('error');
      setErrorMsg(t('SSOCallbackPage.errors.missingStoredState'));
      return;
    }
    if (savedState !== state) {
      setStatus('error');
      setErrorMsg(t('SSOCallbackPage.errors.stateMismatch'));
      return;
    }

    try {
      let data;
      if (protocol === 'saml') {
        // SAML callback · the SAMLResponse might come as a POST param,
        // but since react-router only sees GET params, SAML gateways
        // sometimes encode as query params.
        const samlResponse = searchParams.get('SAMLResponse') || '';
        // Signature is (state, samlResponse) — args were reversed, which swapped
        // the values into the wrong named JSON fields (state<->saml_response) and
        // would fail backend state/CSRF validation once SAML is enabled. Matches
        // the oidcCallback(state, code) ordering below.
        const result = await ssoApi.samlCallback(state || '', samlResponse);
        data = result.data;
      } else {
        // Default: OIDC callback
        if (!code) {
          setStatus('error');
          setErrorMsg(t('SSOCallbackPage.errors.noAuthCode'));
          return;
        }
        const result = await ssoApi.oidcCallback(state || '', code);
        data = result.data;
      }

      // Fix 5, MFA-pending branch. Some SSO providers (especially
      // those that pin a second factor on top of the IdP, e.g.
      // Duo-as-MFA-after-OIDC) finish the protocol exchange but require
      // FreeSDN's own MFA before issuing tokens. In that case the
      // backend returns `{ require_mfa: true, mfa_token: ... }` instead
      // of authenticated. Reuse the LoginPage's inline MFA form by
      // stashing the pending token in the auth store and bouncing to
      // /login, the SAME flow password+MFA logins use.
      //
      // the SSO callback backend sets httpOnly cookies
      // and signals success via `authenticated: true`, raw access_token /
      // refresh_token are no longer present in the JSON body for browser
      // flows.  Check `authenticated` (not `access_token`) as the guard.
      const ssoShape = data as
        | { require_mfa?: boolean; mfa_token?: string; authenticated?: boolean }
        | undefined;
      if (ssoShape?.require_mfa === true && (ssoShape as { mfa_token?: string })?.mfa_token) {
        setMfaPending((ssoShape as { mfa_token: string }).mfa_token);
        const next = searchParams.get('next');
        const target = next ? `/login?next=${encodeURIComponent(next)}` : '/login';
        navigate(target, { replace: true });
        return;
      }

      if (!ssoShape?.authenticated) {
        throw new Error(t('SSOCallbackPage.errors.noAccessToken'));
      }

      // Cookies already set by the backend. Let the store fetch user profile.
      await loginWithSSO();

      setStatus('success');
      // Redirect to dashboard after brief success flash
      setTimeout(() => {
        navigate('/dashboard', { replace: true });
      }, 500);
    } catch (e: unknown) {
      setStatus('error');
      setErrorMsg(getApiErrorMessage(e, t('SSOCallbackPage.errors.authFailed')));
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <Card className="w-full max-w-sm">
        <CardContent noOffset className="p-8 text-center">
        {status === 'processing' && (
          <>
            <Loader2 className="mx-auto h-10 w-10 animate-spin text-primary" />
            <p className="mt-4 text-sm text-muted-foreground">
              {t('SSOCallbackPage.processing')}
            </p>
          </>
        )}

        {status === 'success' && (
          <>
            <CheckCircle className="mx-auto h-10 w-10 text-green-600" />
            <p className="mt-4 text-sm text-muted-foreground">
              {t('SSOCallbackPage.success')}
            </p>
          </>
        )}

        {status === 'error' && (
          <>
            <AlertCircle className="mx-auto h-10 w-10 text-destructive" />
            <p className="mt-3 font-medium text-destructive">
              {t('SSOCallbackPage.failedHeading')}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              {errorMsg}
            </p>
            <Button
              onClick={() => navigate('/login', { replace: true })}
              className="mt-4"
            >
              {t('SSOCallbackPage.backToLogin')}
            </Button>
          </>
        )}
        </CardContent>
      </Card>
    </div>
  );
}
