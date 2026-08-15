// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * SSOLoginButtons · Renders SSO provider buttons on the login page.
 */

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Lock, Shield, FolderOpen, Key, type LucideIcon } from 'lucide-react';
import { ssoApi, type SSOProviderPublic } from '@/lib/ssoApi';
import { useAuthStore } from '@/stores/authStore';
import { isDemoMode } from '@/demo/mode';

const protocolIcons: Record<string, LucideIcon> = {
  oidc: Lock,
  saml: Shield,
  ldap: FolderOpen,
};

interface Props {
  onError?: (message: string) => void;
}

export default function SSOLoginButtons({ onError }: Props) {
  const { t } = useTranslation('auth');
  const navigate = useNavigate();
  const { loginWithSSO } = useAuthStore();
  const [providers, setProviders] = useState<SSOProviderPublic[]>([]);
  const [loading, setLoading] = useState<string | null>(null);
  const [ldapProvider, setLdapProvider] = useState<SSOProviderPublic | null>(null);
  const [ldapCreds, setLdapCreds] = useState({ username: '', password: '' });

  useEffect(() => {
    // Demo mode is a read-only public build with no IdP. Never fetch or render
    // SSO providers, defense-in-depth so the mock adapter can never surface
    // provider data whose authorize_url would navigate to a real off-origin IdP.
    if (isDemoMode) return;
    ssoApi.getPublicProviders().then((res) => {
      setProviders(res.data);
    }).catch(() => {
      // Silently fail · SSO buttons just won't show
    });
  }, []);

  if (isDemoMode || providers.length === 0) return null;

  // NOTE: the SSO callback page is
  // mounted at /auth/sso/callback (see App.tsx), this is the canonical
  // path. The backend services/sso.py default implicit allow is
  // PUBLIC_BASE_URL + /auth/callback (mismatch). Operators MUST either
  //   (a) set the SSO provider's extra_settings.allowed_redirect_uris to
  //       include `${origin}/auth/sso/callback`, OR
  //   (b) update the backend default in services/sso.py:1002 to
  //       `/auth/sso/callback` to match this canonical path.
  // The canonical path is fixed here because changing the route would
  // break every currently-configured IdP. See SSOCallbackPage.tsx.
  const redirectUri = `${window.location.origin}/auth/sso/callback`;

  /** SECURITY: Validate that an IdP authorize URL has a usable
   * scheme. We deliberately do NOT enforce same-origin here because the
   * IdP authorize URL is by definition off-origin (e.g. accounts.google.com).
   * Origin-matching is enforced for same-origin redirects only via
   * isSafeRedirect(); IdP authorize URLs are validated by the backend's
   * allow-list when the provider is configured.
   */
  const hasSafeScheme = (url: string): boolean => {
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'https:' || parsed.protocol === 'http:';
    } catch {
      return false;
    }
  };

  const handleOIDC = async (provider: SSOProviderPublic) => {
    setLoading(provider.id);
    try {
      const { data } = await ssoApi.oidcAuthorize(provider.slug, redirectUri);
      // Store state for callback validation
      sessionStorage.setItem('sso_state', data.state);
      sessionStorage.setItem('sso_protocol', 'oidc');
      // SECURITY: refuse anything that isn't http(s), javascript:/data:
      // URIs must never navigate the top window.
      if (!hasSafeScheme(data.authorize_url)) {
        onError?.('Invalid SSO redirect URL');
        setLoading(null);
        return;
      }
      window.location.href = data.authorize_url;
    } catch (e: unknown) {
      const axiosErr = e as import('axios').AxiosError<{ detail?: string }>;
      onError?.(axiosErr.response?.data?.detail || t('ssoError'));
      setLoading(null);
    }
  };

  const handleSAML = async (provider: SSOProviderPublic) => {
    setLoading(provider.id);
    try {
      const { data } = await ssoApi.samlLogin(provider.slug, redirectUri);
      sessionStorage.setItem('sso_state', data.state);
      sessionStorage.setItem('sso_protocol', 'saml');
      if (!hasSafeScheme(data.authorize_url)) {
        onError?.('Invalid SSO redirect URL');
        setLoading(null);
        return;
      }
      window.location.href = data.authorize_url;
    } catch (e: unknown) {
      const axiosErr = e as import('axios').AxiosError<{ detail?: string }>;
      onError?.(axiosErr.response?.data?.detail || t('ssoError'));
      setLoading(null);
    }
  };

  const handleLDAP = async () => {
    if (!ldapProvider) return;
    setLoading(ldapProvider.id);
    try {
      const { data } = await ssoApi.ldapAuthenticate(
        ldapProvider.slug,
        ldapCreds.username,
        ldapCreds.password,
      );
      // Use the auth store to properly set tokens and user state
      await loginWithSSO(data.access_token, data.refresh_token);
      navigate('/dashboard');
    } catch (e: unknown) {
      const axiosErr = e as import('axios').AxiosError<{ detail?: string }>;
      onError?.(axiosErr.response?.data?.detail || t('ldapError'));
      setLoading(null);
    }
  };

  const handleClick = (provider: SSOProviderPublic) => {
    switch (provider.protocol) {
      case 'oidc':
        handleOIDC(provider);
        break;
      case 'saml':
        handleSAML(provider);
        break;
      case 'ldap':
        setLdapProvider(provider);
        break;
    }
  };

  // SAML is intentionally excluded: its callback is not yet implemented (501), so
  // we never render a SAML login button that can't complete. OIDC + LDAP work.
  const oidcProviders = providers.filter((p) => p.protocol === 'oidc');
  const ldapProviders = providers.filter((p) => p.protocol === 'ldap');

  return (
    <div className="mt-6">
      {/* Divider */}
      <div className="relative my-4">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-gray-300 dark:border-gray-600" />
        </div>
        <div className="relative flex justify-center text-sm">
          <span className="bg-white dark:bg-gray-800 px-2 text-gray-500 dark:text-gray-400">
            {t('orContinueWith', 'Or continue with')}
          </span>
        </div>
      </div>

      {/* OIDC login buttons */}
      <div className="space-y-2">
        {oidcProviders.map((provider) => (
          <button
            key={provider.id}
            onClick={() => handleClick(provider)}
            disabled={loading !== null}
            className="flex w-full items-center justify-center gap-2 rounded-md border border-gray-300 
                       bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-sm 
                       hover:bg-gray-50 disabled:opacity-50
                       dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600"
          >
            {provider.icon_url ? (
              <img src={provider.icon_url} alt="" className="h-5 w-5" />
            ) : (
              (() => {
                const Icon = protocolIcons[provider.protocol] || Key;
                return <Icon className="h-5 w-5" aria-hidden="true" />;
              })()
            )}
            <span>
              {loading === provider.id
                ? t('redirecting', 'Redirecting...')
                : t('signInWith', 'Sign in with {{name}}', { name: provider.name })}
            </span>
          </button>
        ))}
      </div>

      {/* LDAP · inline form */}
      {ldapProviders.length > 0 && !ldapProvider && (
        <div className="mt-2 space-y-2">
          {ldapProviders.map((provider) => (
            <button
              key={provider.id}
              onClick={() => handleClick(provider)}
              className="flex w-full items-center justify-center gap-2 rounded-md border border-gray-300 
                         bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-sm 
                         hover:bg-gray-50
                         dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600"
            >
              <FolderOpen className="h-5 w-5" aria-hidden="true" />
              <span>{t('signInWith', 'Sign in with {{name}}', { name: provider.name })}</span>
            </button>
          ))}
        </div>
      )}

      {/* LDAP credentials form */}
      {ldapProvider && (
        <div className="mt-3 space-y-2 rounded-md border border-gray-200 p-3 dark:border-gray-600">
          <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
            {t('ldapSignIn', 'Sign in with {{name}}', { name: ldapProvider.name })}
          </p>
          <input
            type="text"
            placeholder={t('username', 'Username')}
            value={ldapCreds.username}
            onChange={(e) => setLdapCreds({ ...ldapCreds, username: e.target.value })}
            className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm 
                       dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200"
          />
          <input
            type="password"
            placeholder={t('password', 'Password')}
            value={ldapCreds.password}
            onChange={(e) => setLdapCreds({ ...ldapCreds, password: e.target.value })}
            className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm 
                       dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200"
          />
          <div className="flex gap-2">
            <button
              onClick={handleLDAP}
              disabled={loading !== null || !ldapCreds.username || !ldapCreds.password}
              className="flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground 
                         hover:bg-primary/90 disabled:opacity-50"
            >
              {loading === ldapProvider.id ? t('signingIn', 'Signing in...') : t('signIn', 'Sign In')}
            </button>
            <button
              onClick={() => setLdapProvider(null)}
              className="rounded-md border border-gray-300 px-4 py-2 text-sm text-gray-700 
                         hover:bg-gray-50 dark:border-gray-600 dark:text-gray-300"
            >
              {t('cancel', 'Cancel')}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
