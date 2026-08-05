import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ExecuteScreen from '@/components/screens/ExecuteScreen';
import { AuthExpiredError } from '@/lib/auth';

const driveMocks = vi.hoisted(() => ({
  assertPrivateFolder: vi.fn(),
  ensureDedupeRootFolder: vi.fn(),
  ensureFolderPath: vi.fn(),
  moveFile: vi.fn(),
}));

vi.mock('@/lib/drive', () => driveMocks);
vi.mock('@/lib/state', () => ({
  getSettings: () => ({ dupesFolder: '_dupes', batchSize: 1 }),
}));
vi.mock('@/lib/dedup', () => ({
  isInDedupeFolder: () => false,
}));
vi.mock('@/lib/analytics', () => ({
  trackEvent: vi.fn(),
  trackException: vi.fn(),
}));

const files = [
  {
    id: 'first',
    name: 'first.txt',
    size: '10',
    parents: ['source'],
    parentChain: [{ id: 'source', name: 'Source' }],
    path: '/Source/first.txt',
  },
  {
    id: 'second',
    name: 'second.txt',
    size: '10',
    parents: ['source'],
    parentChain: [{ id: 'source', name: 'Source' }],
    path: '/Source/second.txt',
  },
  {
    id: 'retained',
    name: 'retained.txt',
    size: '10',
    parents: ['source'],
    parentChain: [{ id: 'source', name: 'Source' }],
    path: '/Source/retained.txt',
  },
];

describe('execution expiry handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    driveMocks.ensureDedupeRootFolder.mockResolvedValue({
      id: 'dupes-root',
      privacyReplacementCreated: false,
    });
    driveMocks.ensureFolderPath.mockResolvedValue({
      id: 'destination',
      privacyReplacementCreated: false,
    });
    driveMocks.assertPrivateFolder.mockResolvedValue(undefined);
    driveMocks.moveFile.mockRejectedValueOnce(new AuthExpiredError());
  });

  it('stops scheduling moves after expiry and reports the settled partial result', async () => {
    const onAuthExpired = vi.fn();

    render(
      <ExecuteScreen
        canWrite
        decisions={{ checksum: { action: 'discard', discardIds: ['first', 'second'] } }}
        dupGroups={[{ md5: 'checksum', files }]}
        onRequestWriteAccess={vi.fn()}
        onEnsureWriteAccess={vi.fn(() => Promise.resolve())}
        onAuthExpired={onAuthExpired}
        onComplete={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Move Files' }));

    await waitFor(() => {
      expect(onAuthExpired).toHaveBeenCalledWith({ successCount: 0, total: 2 });
    });
    expect(driveMocks.moveFile).toHaveBeenCalledTimes(1);
    expect(driveMocks.moveFile).toHaveBeenCalledWith('first', ['source'], 'destination');
  });

  it('revalidates the final destination and never moves into a folder that became shared', async () => {
    driveMocks.moveFile.mockReset();
    driveMocks.assertPrivateFolder.mockRejectedValueOnce(
      Object.assign(new Error('Cleanup destination is not private.'), { code: 'UNSAFE_DESTINATION' })
    );
    const onComplete = vi.fn();

    render(
      <ExecuteScreen
        canWrite
        decisions={{ checksum: { action: 'discard', discardIds: ['first'] } }}
        dupGroups={[{ md5: 'checksum', files }]}
        onRequestWriteAccess={vi.fn()}
        onEnsureWriteAccess={vi.fn(() => Promise.resolve())}
        onAuthExpired={vi.fn()}
        onComplete={onComplete}
      />
    );

    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Move Files' }));

    await waitFor(() => expect(onComplete).toHaveBeenCalled());
    expect(driveMocks.assertPrivateFolder).toHaveBeenCalledWith('destination');
    expect(driveMocks.moveFile).not.toHaveBeenCalled();
  });

  it('preserves the private-replacement notice through completion', async () => {
    driveMocks.moveFile.mockReset();
    driveMocks.moveFile.mockResolvedValue({ id: 'first' });
    driveMocks.ensureDedupeRootFolder.mockResolvedValue({
      id: 'private-root',
      privacyReplacementCreated: true,
    });
    const onComplete = vi.fn();

    render(
      <ExecuteScreen
        canWrite
        decisions={{ checksum: { action: 'discard', discardIds: ['first'] } }}
        dupGroups={[{ md5: 'checksum', files }]}
        onRequestWriteAccess={vi.fn()}
        onEnsureWriteAccess={vi.fn(() => Promise.resolve())}
        onAuthExpired={vi.fn()}
        onComplete={onComplete}
      />
    );

    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Move Files' }));

    const notice = 'Created a private _dupes destination because an existing cleanup folder is shared.';
    expect(await screen.findByText(notice)).toBeInTheDocument();
    await waitFor(() => {
      expect(onComplete).toHaveBeenCalledWith(expect.any(Array), { destinationNotice: notice });
    });
  });

  it('preserves the private-replacement notice when the session expires', async () => {
    driveMocks.ensureDedupeRootFolder.mockResolvedValue({
      id: 'private-root',
      privacyReplacementCreated: true,
    });
    const onAuthExpired = vi.fn();

    render(
      <ExecuteScreen
        canWrite
        decisions={{ checksum: { action: 'discard', discardIds: ['first'] } }}
        dupGroups={[{ md5: 'checksum', files }]}
        onRequestWriteAccess={vi.fn()}
        onEnsureWriteAccess={vi.fn(() => Promise.resolve())}
        onAuthExpired={onAuthExpired}
        onComplete={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Move Files' }));

    await waitFor(() => {
      expect(onAuthExpired).toHaveBeenCalledWith({
        successCount: 0,
        total: 1,
        destinationNotice:
          'Created a private _dupes destination because an existing cleanup folder is shared.',
      });
    });
  });

  it('shows the private-replacement notice if setup later fails', async () => {
    driveMocks.moveFile.mockReset();
    driveMocks.ensureDedupeRootFolder.mockRejectedValueOnce(
      Object.assign(new Error('Verification failed.'), { privacyReplacementCreated: true })
    );

    render(
      <ExecuteScreen
        canWrite
        decisions={{ checksum: { action: 'discard', discardIds: ['first'] } }}
        dupGroups={[{ md5: 'checksum', files }]}
        onRequestWriteAccess={vi.fn()}
        onEnsureWriteAccess={vi.fn(() => Promise.resolve())}
        onAuthExpired={vi.fn()}
        onComplete={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Move Files' }));

    expect(await screen.findByText(
      'Created a private _dupes destination because an existing cleanup folder is shared.'
    )).toBeInTheDocument();
    expect(screen.getByText('Move setup: Verification failed.')).toBeInTheDocument();
  });

  it('blocks an all-copy decision before any Drive mutation', () => {
    const onRequestWriteAccess = vi.fn();
    render(
      <ExecuteScreen
        canWrite
        decisions={{ checksum: { action: 'discard', discardIds: ['first', 'second', 'retained'] } }}
        dupGroups={[{ md5: 'checksum', files }]}
        onRequestWriteAccess={onRequestWriteAccess}
        onEnsureWriteAccess={vi.fn()}
        onAuthExpired={vi.fn()}
        onComplete={vi.fn()}
      />
    );

    expect(screen.getByRole('alert')).toHaveTextContent('Keep at least one copy');
    expect(screen.queryByRole('button', { name: 'Move Files' })).not.toBeInTheDocument();
    expect(onRequestWriteAccess).not.toHaveBeenCalled();
    expect(driveMocks.ensureDedupeRootFolder).not.toHaveBeenCalled();
    expect(driveMocks.ensureFolderPath).not.toHaveBeenCalled();
    expect(driveMocks.moveFile).not.toHaveBeenCalled();
  });
});
