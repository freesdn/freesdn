// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SdnDependencies } from '../SdnDependencies';
import { hypervisorApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';
import type { SdnDependencyInspection } from '@/lib/api/hypervisor';

vi.mock('@/lib/api', () => ({ hypervisorApi: { inspectSdnDependencies: vi.fn() } }));
const time = '2026-09-18T09:00:00Z';
function observation(): SdnDependencyInspection {
  return {
    controller_id: 'controller', started_at: time, finished_at: time,
    collections: [{ resource: 'subnets', view: 'configured', parent_id: 'v1', status: 'available', content_scope: 'allowlisted_fields', items: [{ subnet: 'z1-10.0.0.0-24', vnet: 'v1' }], omitted_fields: 1, observed_at: time }],
    references: [{ source_resource: 'subnets', source_id: 'z1-10.0.0.0-24', field: 'vnet', view: 'configured', target_resource: 'vnets', target_id: 'v1', target_view: 'configured', status: 'visible' }],
    pending_state: 'unknown', subnet_parent_limit: 32, subnet_parents_selected: 1,
    subnet_parents_omitted_by_limit: 0, subnet_parent_inventory_complete: false,
    request_limit: 121, requests_made: 28, response_limit_reached: false,
    visibility: 'partial_or_unverified', atomic_snapshot: false, dependency_graph_complete: false,
    writes_enabled: false, unobserved_dependencies: ['guest_nic_references', 'route_map_entries'],
  };
}
function respond(data: SdnDependencyInspection) {
  vi.mocked(hypervisorApi.inspectSdnDependencies).mockResolvedValue({ data } as Awaited<ReturnType<typeof hypervisorApi.inspectSdnDependencies>>);
}
async function inspect() {
  await userEvent.click(screen.getByRole('button', { name: 'Inspect dependencies' }));
}
beforeEach(() => { vi.resetAllMocks(); respond(observation()); });

describe('SDN dependency observations', () => {
  it('only fetches on demand and keeps the incomplete, read-only boundary visible', async () => {
    renderWithProviders(<SdnDependencies controllerId="controller" />);
    expect(hypervisorApi.inspectSdnDependencies).not.toHaveBeenCalled();
    expect(screen.getByText(/not a complete dependency graph/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /apply|create|delete/i })).not.toBeInTheDocument();
    await inspect();
    await screen.findByText('VNet: v1');
    expect(hypervisorApi.inspectSdnDependencies).toHaveBeenCalledExactlyOnceWith('controller');
    expect(screen.getByText('Pending state is unknown')).toBeInTheDocument();
    expect(screen.getByText(/Target visible in this observation/)).toBeInTheDocument();
    expect(screen.getByText(/Still unverified: guest NIC references, route-map entries/)).toBeInTheDocument();
  });
  it('does not treat denied inventory or unexposed native views as empty', async () => {
    const data = observation();
    data.collections = [
      { ...data.collections[0], status: 'denied', items: null },
      { resource: 'ipams', view: 'running', status: 'not_observed', reason: 'view_not_exposed', content_scope: 'allowlisted_fields', omitted_fields: 0, items: null, observed_at: time },
    ];
    respond(data);
    renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect();
    await screen.findByText('Permission denied');
    expect(screen.queryByText(/No visible objects/)).not.toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText('Dependency family'), 'ipams');
    await userEvent.selectOptions(screen.getByLabelText('Configuration view'), 'running');
    expect(screen.getByText('Not observed')).toBeInTheDocument();
    expect(screen.getByText(/does not expose this configuration view/)).toBeInTheDocument();
    expect(hypervisorApi.inspectSdnDependencies).toHaveBeenCalledTimes(1);
  });
  it('hides previous observations during refresh and after failure without exposing diagnostics', async () => {
    renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByText('VNet: v1');
    let reject!: (error: Error) => void;
    vi.mocked(hypervisorApi.inspectSdnDependencies).mockImplementation(() => new Promise((_, fail) => { reject = fail; }));
    await userEvent.click(screen.getByRole('button', { name: 'Refresh dependency observations' }));
    expect(screen.queryByText('VNet: v1')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Refresh dependency observations' })).toBeDisabled();
    reject(new Error('secret upstream diagnostic'));
    await screen.findByText(/Previous data must not be treated as current/);
    expect(screen.queryByText('VNet: v1')).not.toBeInTheDocument();
    expect(screen.queryByText(/secret upstream/)).not.toBeInTheDocument();
    expect(hypervisorApi.inspectSdnDependencies).toHaveBeenCalledTimes(2);
  });
  it('rejects a response for a different controller', async () => {
    respond({ ...observation(), controller_id: 'foreign' });
    renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByText(/Previous data must not be treated as current/);
    expect(screen.queryByText('VNet: v1')).not.toBeInTheDocument();
  });
  it('keeps unknown coverage explicit when optional details are missing', async () => {
    const data = observation(); delete data.unobserved_dependencies;
    respond(data); renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect();
    await screen.findByText('Additional dependencies remain unverified; coverage details are unavailable.');
  });
  it('resets the request and selection on controller changes', async () => {
    const rendered = renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByText('VNet: v1');
    await userEvent.selectOptions(screen.getByLabelText('Dependency family'), 'dns');
    rendered.rerender(<SdnDependencies controllerId="other" />);
    expect(screen.queryByLabelText('Dependency family')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Inspect dependencies' })).toBeEnabled();
    expect(hypervisorApi.inspectSdnDependencies).toHaveBeenCalledTimes(1);
    respond({ ...observation(), controller_id: 'other' });
    await inspect(); await screen.findByText('VNet: v1');
    expect(screen.getByLabelText('Dependency family')).toHaveValue('subnets');
    expect(hypervisorApi.inspectSdnDependencies).toHaveBeenLastCalledWith('other');
  });
  it('shows selection and response limits without hiding incomplete coverage', async () => {
    const data = observation();
    data.subnet_parents_selected = 32; data.subnet_parents_omitted_by_limit = 7; data.response_limit_reached = true;
    data.collections[0] = { ...data.collections[0], status: 'not_observed', reason: 'response_limit', items: null };
    respond(data); renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByText(/7 additional visible parents were omitted/);
    expect(screen.getByRole('alert')).toHaveTextContent(/must not be treated as empty/);
    expect(screen.getByText(/collection exceeded the aggregate response budget/)).toBeInTheDocument();
  });
  it('distinguishes invisible targets from unreadable target collections', async () => {
    const data = observation();
    data.references = [{ ...data.references[0], status: 'not_visible' }, { ...data.references[0], target_id: 'v2', status: 'target_unavailable' }];
    respond(data); renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByText(/Target not visible; existence is unverified/);
    expect(screen.getByText(/Target collection unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/Pending-field overlays are not resolved/)).toBeInTheDocument();
  });
  it('identifies catalogues and explicitly discloses presentation limits', async () => {
    const data = observation();
    data.collections = [{ ...data.collections[0], resource: 'route-maps', parent_id: null, content_scope: 'identities_only', items: Array.from({ length: 51 }, (_, i) => ({ id: `route${i}` })) }];
    respond(data); renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByLabelText('Dependency family');
    await userEvent.selectOptions(screen.getByLabelText('Dependency family'), 'route-maps');
    expect(screen.getByText(/Nested rules are not part of this catalogue/)).toBeInTheDocument();
    expect(screen.getByText('Showing the first 50 of 51 returned entries.')).toBeInTheDocument();
    expect(screen.queryByText(/"route50"/)).not.toBeInTheDocument();
  });
  it('shows pending policy identities and deletion markers without inventing an effective policy', async () => {
    const data = observation();
    data.collections = [{ ...data.collections[0], resource: 'route-map-entries', view: 'pending', parent_id: null, items: [{ 'route-map-id': 'new-map', order: 10, entry_id: 'new-map_10', identity_source: 'pending', state: 'new', pending: { action: 'permit', call: 'deleted' } }] }];
    data.references = [];
    respond(data); renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByLabelText('Dependency family');
    await userEvent.selectOptions(screen.getByLabelText('Dependency family'), 'route-map-entries');
    await userEvent.selectOptions(screen.getByLabelText('Configuration view'), 'pending');
    expect(screen.getByText(/"identity_source": "pending"/)).toHaveTextContent('"call": "deleted"');
    expect(screen.getByText(/FRR evaluation and live enforcement are unverified/)).toBeInTheDocument();
    expect(screen.getByText(/Pending-field overlays are not resolved/)).toBeInTheDocument();
    expect(hypervisorApi.inspectSdnDependencies).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: /apply|create|delete/i })).not.toBeInTheDocument();
  });
  it('caps nested policy lists and overlays without mutating the response', async () => {
    const data = observation();
    const entries = Array.from({ length: 51 }, (_, i) => ({ seq: i, prefix: `prefix-${i}` }));
    data.collections = [{ ...data.collections[0], resource: 'prefix-list-entries', parent_id: null, items: [{ id: 'pl1', entries, pending: { entries: entries.map(e => ({ ...e, prefix: `pending-${e.seq}` })) } }] }];
    const before = JSON.stringify(data);
    respond(data); renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByLabelText('Dependency family');
    await userEvent.selectOptions(screen.getByLabelText('Dependency family'), 'prefix-list-entries');
    expect(screen.getByText(/"prefix-49"/)).toHaveTextContent('pending-49');
    expect(screen.queryByText(/"prefix-50"|"pending-50"/)).not.toBeInTheDocument();
    expect(screen.getByText('entries: showing the first 50 of 51 returned items.')).toBeInTheDocument();
    expect(screen.getByText('pending.entries: showing the first 50 of 51 returned items.')).toBeInTheDocument();
    expect(JSON.stringify(data)).toBe(before);
  });
  it('keeps policy permission failures and catalogue reference uncertainty visible', async () => {
    const data = observation();
    data.collections = [{ ...data.collections[0], resource: 'route-map-entries', parent_id: null, items: null, status: 'denied' }];
    data.references = [{ ...data.references[0], source_resource: 'route-map-entries', source_id: 'rm1_10', field: 'call', target_resource: 'route-maps', target_id: 'rm2', status: 'target_unavailable' }];
    respond(data); renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByLabelText('Dependency family');
    await userEvent.selectOptions(screen.getByLabelText('Dependency family'), 'route-map-entries');
    expect(screen.getByText('Permission denied')).toBeInTheDocument();
    expect(screen.queryByText(/No visible objects/)).not.toBeInTheDocument();
    expect(screen.getByText('rm1_10 · call → route-maps/rm2')).toBeInTheDocument();
    expect(screen.getByText(/Target collection unavailable/)).toBeInTheDocument();
  });
  it('shows separate memberships for the same node with a fabric configuration boundary', async () => {
    const data = observation();
    data.collections = [{ ...data.collections[0], resource: 'fabric-nodes', parent_id: null, items: [{ node_key: 'f1_pve1', node_id: 'pve1', fabric_id: 'f1', protocol: 'wireguard' }, { node_key: 'f2_pve1', node_id: 'pve1', fabric_id: 'f2', protocol: 'wireguard' }] }];
    data.references = [{ ...data.references[0], source_resource: 'fabric-nodes', source_id: 'f1_pve1', field: 'peers[0].node', target_resource: 'fabric-nodes', target_id: 'f1_pve2', status: 'not_visible' }];
    respond(data); renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByLabelText('Dependency family');
    await userEvent.selectOptions(screen.getByLabelText('Dependency family'), 'fabric-nodes');
    expect(screen.getByText(/"node_key": "f1_pve1"/)).toBeInTheDocument();
    expect(screen.getByText(/"node_key": "f2_pve1"/)).toBeInTheDocument();
    expect(screen.getByText(/do not prove host interface existence, active sessions/)).toBeInTheDocument();
    expect(screen.getByText('f1_pve1 · peers[0].node → fabric-nodes/f1_pve2')).toBeInTheDocument();
    expect(screen.getByText(/Target not visible; existence is unverified/)).toBeInTheDocument();
  });
  it('discloses nested fabric detail limits without changing the response', async () => {
    const data = observation();
    data.collections = [{ ...data.collections[0], resource: 'fabric-nodes', parent_id: null, view: 'pending', items: [{ node_key: 'f1_pve1', identity_source: 'pending', state: 'new', pending: { interfaces: Array.from({ length: 51 }, (_, i) => ({ name: `wg${i}` })), peers: Array.from({ length: 51 }, (_, i) => ({ node: `peer${i}` })) } }] }];
    const before = JSON.stringify(data);
    respond(data); renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByLabelText('Dependency family');
    await userEvent.selectOptions(screen.getByLabelText('Dependency family'), 'fabric-nodes');
    await userEvent.selectOptions(screen.getByLabelText('Configuration view'), 'pending');
    expect(screen.getByText(/"wg49"/)).toHaveTextContent('peer49');
    expect(screen.queryByText(/"wg50"|"peer50"/)).not.toBeInTheDocument();
    expect(screen.getByText('pending.interfaces: showing the first 50 of 51 returned items.')).toBeInTheDocument();
    expect(screen.getByText('pending.peers: showing the first 50 of 51 returned items.')).toBeInTheDocument();
    expect(JSON.stringify(data)).toBe(before);
  });
  it.each(['base', 'pending'])('makes unsupported fabric protocol details explicit in %s fields', async source => {
    const data = observation();
    const unsupported = { protocol: 'future', details_status: 'unsupported_protocol' };
    data.collections = [{ ...data.collections[0], resource: 'fabric-nodes', parent_id: null, items: [{ node_key: 'f1_pve1', ...(source === 'base' ? unsupported : { protocol: 'wireguard', pending: unsupported }) }] }];
    respond(data); renderWithProviders(<SdnDependencies controllerId="controller" />);
    await inspect(); await screen.findByLabelText('Dependency family');
    await userEvent.selectOptions(screen.getByLabelText('Dependency family'), 'fabric-nodes');
    expect(screen.getByText(/This fabric protocol is not supported by this reader/)).toBeInTheDocument();
    expect(screen.queryByText(/No visible objects/)).not.toBeInTheDocument();
    expect(hypervisorApi.inspectSdnDependencies).toHaveBeenCalledTimes(1);
  });
});
