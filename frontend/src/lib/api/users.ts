// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type { UserAccount, UserCreatePayload, UserUpdatePayload } from './types';

export const usersApi = {
  list: (params?: { page?: number; per_page?: number }) =>
    api.get<{ items: UserAccount[]; total: number; page: number; per_page: number; pages: number }>('/users', { params }),

  getById: (id: string) =>
    api.get<UserAccount>(`/users/${id}`),

  create: (data: UserCreatePayload) =>
    api.post<UserAccount>('/users', data),

  update: (id: string, data: UserUpdatePayload) =>
    api.patch<UserAccount>(`/users/${id}`, data),

  delete: (id: string) =>
    api.delete(`/users/${id}`),
};
