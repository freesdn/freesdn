// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The summary line for a bulk delete run as one request per row.
 *
 * Pages used to borrow the bulk-connect sentence ("2 connected, 1 failed,
 * 0 skipped") for a delete, which describes a different action and drops the
 * reason a row failed. This says what was deleted and, when something was
 * not, the server's reason for the first failure.
 */
import type { TFunction } from 'i18next';
import { getApiErrorMessage } from '@/lib/api/errors';

export interface BulkDeleteSummary {
  /** The toast description. */
  description: string;
  deleted: number;
  failed: number;
}

export function summariseBulkDelete(results: PromiseSettledResult<unknown>[], t: TFunction): BulkDeleteSummary {
  const deleted = results.filter((r) => r.status === 'fulfilled').length;
  const failures = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
  const failed = failures.length;
  if (failed === 0) {
    return { description: t('common:BulkDelete.allDeleted', { count: deleted }), deleted, failed };
  }
  const reason = getApiErrorMessage(failures[0].reason);
  const description =
    deleted === 0
      ? t('common:BulkDelete.noneDeleted', { count: failed, reason })
      : t('common:BulkDelete.someFailed', { deleted, failed, reason });
  return { description, deleted, failed };
}
