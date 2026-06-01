// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway Open API: OAuth2 client-credentials wrapper
 * for the documented Omada Open API at /openapi/v1/...
 */

import { api } from './client';

export interface OpenApiToken {
  accessToken: string;
  refreshToken?: string;
  expiresInSec: number;
  tokenType: string;
}

export const gatewayOpenApi = {
  getToken: (
    controllerId: string,
    body: { client_id: string; client_secret: string },
  ) => api.post<OpenApiToken>(`/gateway-openapi/${controllerId}/token`, body),

  refresh: (
    controllerId: string,
    body: {
      client_id: string;
      client_secret: string;
      refresh_token: string;
    },
  ) => api.post<OpenApiToken>(`/gateway-openapi/${controllerId}/refresh`, body),

  introspect: (controllerId: string, accessToken: string) =>
    api.post(`/gateway-openapi/${controllerId}/introspect`, {
      access_token: accessToken,
    }),

  listSites: (
    controllerId: string,
    accessToken: string,
    params?: { page?: number; page_size?: number },
  ) =>
    api.get(`/gateway-openapi/${controllerId}/sites`, {
      params: { ...params, access_token: accessToken },
    }),
};
