// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * SSO API Client · FreeSDN
 *
 * Endpoints for OIDC / SAML / LDAP authentication and provider management.
 */

import { api } from './api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SSOProviderPublic {
  id: string;
  name: string;
  slug: string;
  protocol: 'oidc' | 'saml' | 'ldap';
  icon_url: string | null;
  display_order: number;
}

export interface SSOProvider extends SSOProviderPublic {
  organization_id: string;
  description: string | null;
  status: 'active' | 'inactive' | 'testing';

  // OIDC (no client_secret)
  oidc_issuer: string | null;
  oidc_client_id: string | null;
  oidc_scopes: string | null;
  oidc_discovery_url: string | null;

  // SAML (no signing_key)
  saml_entity_id: string | null;
  saml_sso_url: string | null;
  saml_slo_url: string | null;
  saml_name_id_format: string | null;

  // LDAP (no bind_password)
  ldap_url: string | null;
  ldap_bind_dn: string | null;
  ldap_base_dn: string | null;
  ldap_user_search_filter: string | null;
  ldap_group_search_filter: string | null;
  ldap_use_tls: boolean | null;

  // Mappings
  attribute_mapping: Record<string, string>;
  role_mapping: Record<string, string>;

  // JIT
  jit_provisioning: boolean;
  default_role: string;

  created_at: string;
  updated_at: string;
}

export interface SSOAuthorizeResponse {
  authorize_url: string;
  state: string;
}

export interface SSOCallbackResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: {
    id: string;
    email: string;
    username: string;
    full_name: string | null;
    role: string;
    organization_id: string | null;
    auth_provider: string;
  };
}

export interface SSOTestResult {
  success: boolean;
  message: string;
  details: Record<string, unknown> | null;
}

// ---------------------------------------------------------------------------
// Public (login page)
// ---------------------------------------------------------------------------

export const ssoApi = {
  /** Get active SSO providers for the login page. */
  getPublicProviders: () =>
    api.get<SSOProviderPublic[]>('/auth/sso/providers/public'),

  // OIDC
  oidcAuthorize: (providerSlug: string, redirectUri?: string) =>
    api.post<SSOAuthorizeResponse>('/auth/sso/oidc/authorize', {
      provider_slug: providerSlug,
      redirect_uri: redirectUri,
    }),

  oidcCallback: (state: string, code: string) =>
    api.post<SSOCallbackResponse>('/auth/sso/oidc/callback', { state, code }),

  // SAML
  samlLogin: (providerSlug: string, redirectUri?: string) =>
    api.post<SSOAuthorizeResponse>('/auth/sso/saml/login', {
      provider_slug: providerSlug,
      redirect_uri: redirectUri,
    }),

  samlCallback: (state: string, samlResponse: string) =>
    api.post<SSOCallbackResponse>('/auth/sso/saml/callback', {
      state,
      saml_response: samlResponse,
    }),

  // LDAP
  ldapAuthenticate: (providerSlug: string, username: string, password: string) =>
    api.post<SSOCallbackResponse>('/auth/sso/ldap/authenticate', {
      provider_slug: providerSlug,
      username,
      password,
    }),

  // -------------------------------------------------------------------------
  // Admin · Provider CRUD
  // -------------------------------------------------------------------------

  listProviders: (organizationId?: string) =>
    api.get<SSOProvider[]>('/auth/sso/providers', {
      params: organizationId ? { organization_id: organizationId } : undefined,
    }),

  getProvider: (id: string) => api.get<SSOProvider>(`/auth/sso/providers/${id}`),

  createProvider: (data: Partial<SSOProvider> & { name: string; slug: string; protocol: string; organization_id: string }) =>
    api.post<SSOProvider>('/auth/sso/providers', data),

  updateProvider: (id: string, data: Partial<SSOProvider>) =>
    api.patch<SSOProvider>(`/auth/sso/providers/${id}`, data),

  deleteProvider: (id: string) => api.delete(`/auth/sso/providers/${id}`),

  testProvider: (id: string) =>
    api.post<SSOTestResult>(`/auth/sso/providers/${id}/test`),
};
