// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * What a VLAN or WiFi delete did on the controller behind it.
 *
 * ``DELETE /network/vlans/{id}`` and ``DELETE /network/wifi/{id}`` push the
 * delete to the controller first and answer with ``controller_synced`` and
 * ``controller_warning`` (backend/app/api/v1/endpoints/network.py). Two
 * shapes exist for a delete the controller did not confirm:
 *
 * - today: ``{ success: true, controller_synced: false, controller_warning }``,
 *   and FreeSDN's record is removed anyway, so the VLAN or SSID may still be
 *   live on the controller;
 * - the shape the backend is moving to: the record is KEPT on refusal and the
 *   answer says so with ``success: false`` (or ``deleted: false`` /
 *   ``kept: true``), still carrying ``controller_synced: false`` and the
 *   warning.
 *
 * Both are read here, so the pages say the right thing before and after the
 * backend change.
 */

export type ControllerDeleteOutcome =
  /** The controller confirmed (or there is no controller to tell). */
  | { kind: 'deleted' }
  /** FreeSDN's record is gone, but the controller did not confirm. */
  | { kind: 'removed-unconfirmed'; warning: string | null }
  /** The controller did not confirm, so FreeSDN kept its record. */
  | { kind: 'kept'; warning: string | null };

type Dict = Record<string, unknown>;

const isDict = (value: unknown): value is Dict =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const text = (value: unknown): string | null =>
  typeof value === 'string' && value.trim() ? value.trim() : null;

/** Read a delete answer (the body, or the axios response that wraps it). */
export function readControllerDelete(value: unknown): ControllerDeleteOutcome {
  if (!isDict(value)) return { kind: 'deleted' };
  const body: Dict = !('controller_synced' in value) && !('success' in value) && isDict(value.data) ? value.data : value;
  const warning = text(body.controller_warning) ?? text(body.message) ?? text(body.detail);
  const kept = body.success === false || body.deleted === false || body.kept === true || body.record_kept === true;
  if (kept) return { kind: 'kept', warning };
  if (body.controller_synced === false) return { kind: 'removed-unconfirmed', warning };
  return { kind: 'deleted' };
}
