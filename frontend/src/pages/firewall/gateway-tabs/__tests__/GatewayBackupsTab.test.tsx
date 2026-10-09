import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { GatewayBackupsTab, type GatewayBackupsTabProps } from '../GatewayBackupsTab';

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }));

const prefix = 'GatewayBackupsTab.diff.';
const complete = {
  comparison_available: true,
  has_changes: false,
  diff_lines: [] as string[],
  current_size: 12,
  backup_size: 12,
  summary: '0 additions, 0 deletions',
};
const base = {
  backups: [], backupsLoading: false, onCreateBackup: vi.fn(), isCreating: false,
  onRevertBackup: vi.fn(), onDeleteBackup: vi.fn(), onDownloadConfig: vi.fn(),
  configDiffLoading: false, configDiffData: undefined,
};
function show(extra: Record<string, unknown>) {
  return render(<GatewayBackupsTab {...({ ...base, ...extra } as GatewayBackupsTabProps)} />);
}

describe('gateway configuration comparison availability', () => {
  const unknown = [
    undefined, null, {},
    { ...complete, comparison_available: false },
    { ...complete, comparison_available: undefined },
    { ...complete, has_changes: undefined },
    { ...complete, has_changes: 'false' },
    { ...complete, has_changes: null },
    { ...complete, diff_lines: undefined },
    { ...complete, diff_lines: '+old' },
    { ...complete, has_changes: true, diff_lines: [{}] },
    { ...complete, diff_lines: ['+new'] },
    { ...complete, has_changes: true },
    { ...complete, backup_size: 0 },
  ];
  it.each(unknown.map((data, index) => ({ data, index })))('shows unavailable for incomplete payload $index', ({ data }) => {
    show({ configDiffData: { data } });
    expect(screen.getByText(prefix + 'unavailable')).toBeInTheDocument();
    expect(screen.queryByText(prefix + 'noChanges')).not.toBeInTheDocument();
    expect(screen.queryByText(prefix + 'changesDetected')).not.toBeInTheDocument();
  });

  it.each([false, true])('hides stale comparison on request error, changes=%s', (changed) => {
    show({ configDiffError: true, configDiffData: { data: {
      ...complete, has_changes: changed, diff_lines: changed ? ['+stale-private-data'] : [],
    } } });
    expect(screen.getByText(prefix + 'unavailable')).toBeInTheDocument();
    expect(screen.queryByText(prefix + 'noChanges')).not.toBeInTheDocument();
    expect(screen.queryByText(prefix + 'changesDetected')).not.toBeInTheDocument();
    expect(screen.queryByText('+stale-private-data')).not.toBeInTheDocument();
  });

  it.each([false, true])('loading hides stale comparison, changes=%s', (changed) => {
    show({ configDiffLoading: true, configDiffData: { data: {
      ...complete, has_changes: changed, diff_lines: changed ? ['+stale-private-data'] : [],
    } } });
    expect(screen.getByText(prefix + 'generating')).toBeInTheDocument();
    expect(screen.queryByText(prefix + 'noChanges')).not.toBeInTheDocument();
    expect(screen.queryByText(prefix + 'changesDetected')).not.toBeInTheDocument();
    expect(screen.queryByText('+stale-private-data')).not.toBeInTheDocument();
  });

  it.each([false, true])('renders a complete valid comparison, changes=%s', (changed) => {
    show({ configDiffData: { data: {
      ...complete, has_changes: changed, diff_lines: changed ? ['+new-owned-data'] : [],
    } } });
    expect(screen.getByText(prefix + (changed ? 'changesDetected' : 'noChanges'))).toBeInTheDocument();
    expect(screen.queryByText(prefix + 'unavailable')).not.toBeInTheDocument();
    if (changed) expect(screen.getByText('+new-owned-data')).toBeInTheDocument();
  });

  it('allows an explicit retry without triggering a device write', () => {
    const retry = vi.fn();
    show({ onRetryConfigDiff: retry });
    fireEvent.click(screen.getByRole('button', { name: prefix + 'retry' }));
    expect(retry).toHaveBeenCalledOnce();
    expect(base.onCreateBackup).not.toHaveBeenCalled();
    expect(base.onRevertBackup).not.toHaveBeenCalled();
    expect(base.onDeleteBackup).not.toHaveBeenCalled();
  });
});
