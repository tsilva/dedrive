import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ReviewScreen from '@/components/screens/ReviewScreen';

vi.mock('@/components/FilePreview', () => ({
  default: ({ file }) => <div>Preview: {file.name}</div>,
}));
vi.mock('@/hooks/useKeyboardShortcuts', () => ({
  useKeyboardShortcuts: vi.fn(),
}));
vi.mock('@/lib/preview', () => ({
  prefetchPreview: vi.fn(() => Promise.resolve()),
}));

const group = {
  md5: 'checksum-1',
  wastedSize: 12,
  files: [
    { id: 'keep', name: 'copy.txt', size: '12' },
    { id: 'discard', name: 'copy.txt', size: '12' },
  ],
};

describe('review completion routing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns through the no-move route when all groups were kept or skipped', async () => {
    const onExecute = vi.fn();
    const onNoMovesComplete = vi.fn();

    render(
      <ReviewScreen
        dupGroups={[group]}
        decisions={{ 'checksum-1': { action: 'skip' } }}
        onDecision={vi.fn()}
        onExecute={onExecute}
        onNoMovesComplete={onNoMovesComplete}
        onAuthExpired={vi.fn()}
      />
    );

    expect(screen.getByText('Review Complete')).toBeInTheDocument();
    await waitFor(() => expect(onNoMovesComplete).toHaveBeenCalledTimes(1));
    expect(onExecute).not.toHaveBeenCalled();
  });

  it('enters execution only when at least one file is marked to move', async () => {
    const onExecute = vi.fn();
    const onNoMovesComplete = vi.fn();

    render(
      <ReviewScreen
        dupGroups={[group]}
        decisions={{ 'checksum-1': { action: 'discard', discardIds: ['discard'] } }}
        onDecision={vi.fn()}
        onExecute={onExecute}
        onNoMovesComplete={onNoMovesComplete}
        onAuthExpired={vi.fn()}
      />
    );

    await waitFor(() => expect(onExecute).toHaveBeenCalledTimes(1));
    expect(onNoMovesComplete).not.toHaveBeenCalled();
  });
});
