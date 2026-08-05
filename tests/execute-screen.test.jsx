import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ExecuteScreen from '@/components/screens/ExecuteScreen';
import { AuthExpiredError } from '@/lib/auth';

const driveMocks = vi.hoisted(() => ({
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
];

describe('execution expiry handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    driveMocks.ensureDedupeRootFolder.mockResolvedValue('dupes-root');
    driveMocks.ensureFolderPath.mockResolvedValue('destination');
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
});
