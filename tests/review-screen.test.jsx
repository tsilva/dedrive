import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ReviewScreen from '@/components/screens/ReviewScreen';
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts';

vi.mock('@/components/FilePreview', () => ({
  default: ({ file }) => <div>Preview: {file.name}</div>,
}));
vi.mock('@/hooks/useKeyboardShortcuts', () => ({
  useKeyboardShortcuts: vi.fn(),
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

  it('blocks mouse and keyboard confirmation when every copy is selected', () => {
    const onDecision = vi.fn();
    render(
      <ReviewScreen
        dupGroups={[group]}
        decisions={{}}
        onDecision={onDecision}
        onExecute={vi.fn()}
        onNoMovesComplete={vi.fn()}
        onAuthExpired={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /discard file 1/i }));
    fireEvent.click(screen.getByRole('button', { name: /discard file 2/i }));

    expect(screen.getByRole('button', { name: /keep at least one copy/i })).toBeDisabled();
    expect(screen.getByText('Keep at least one copy in every duplicate group.')).toBeInTheDocument();

    const shortcutConfig = useKeyboardShortcuts.mock.calls.at(-1)[0];
    shortcutConfig.onConfirmCurrent();
    expect(onDecision).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: /keep file 1/i }));
    fireEvent.click(screen.getByRole('button', { name: /discard selected and next/i }));
    expect(onDecision).toHaveBeenCalledWith('checksum-1', {
      action: 'discard',
      discardIds: ['discard'],
    });
  });

  it('mounts four previews at a time and keeps selections across file pages', () => {
    const pagedGroup = {
      ...group,
      files: Array.from({ length: 6 }, (_, index) => ({
        id: `file-${index + 1}`,
        name: `copy-${index + 1}.txt`,
        size: '12',
      })),
    };

    render(
      <ReviewScreen
        dupGroups={[pagedGroup]}
        decisions={{}}
        onDecision={vi.fn()}
        onExecute={vi.fn()}
        onNoMovesComplete={vi.fn()}
        onAuthExpired={vi.fn()}
      />
    );

    expect(screen.getAllByText(/Preview:/)).toHaveLength(4);
    expect(screen.getByText('Files 1–4 of 6')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /discard file 1/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next files' }));

    expect(screen.getAllByText(/Preview:/)).toHaveLength(2);
    expect(screen.getByText('Files 5–6 of 6')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /discard file 1/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Previous files' }));

    expect(screen.getByRole('button', { name: /keep file 1/i })).toHaveAttribute('aria-pressed', 'true');
    const shortcutConfig = useKeyboardShortcuts.mock.calls.at(-1)[0];
    expect(shortcutConfig.maxIndex).toBe(4);
  });
});
