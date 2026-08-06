import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ReviewScreen from '@/components/screens/ReviewScreen';
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts';

vi.mock('@/components/FilePreview', () => ({
  default: ({ file }) => <div data-preview-id={file.id}>Preview: {file.name}</div>,
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

function StatefulReview({ groups }) {
  const [decisions, setDecisions] = useState({});

  return (
    <ReviewScreen
      dupGroups={groups}
      decisions={decisions}
      onDecision={(md5, decision) => {
        setDecisions((current) => ({ ...current, [md5]: decision }));
      }}
      onExecute={vi.fn()}
      onNoMovesComplete={vi.fn()}
      onAuthExpired={vi.fn()}
    />
  );
}

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

  it('requires a keep choice and derives discard IDs from the unselected copies', () => {
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

    expect(screen.getByRole('button', { name: /select a copy to keep/i })).toBeDisabled();
    expect(screen.getByText('Select at least one copy to keep.')).toBeInTheDocument();

    const shortcutConfig = useKeyboardShortcuts.mock.calls.at(-1)[0];
    shortcutConfig.onConfirmCurrent();
    expect(onDecision).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: /keep file 1/i }));
    fireEvent.click(screen.getByRole('button', { name: /keep selected and next/i }));
    expect(onDecision).toHaveBeenCalledWith('checksum-1', {
      action: 'discard',
      discardIds: ['discard'],
    });
  });

  it('allows keeping every copy without scheduling a move', () => {
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

    fireEvent.click(screen.getByRole('button', { name: /keep file 1/i }));
    fireEvent.click(screen.getByRole('button', { name: /keep file 2/i }));
    fireEvent.click(screen.getByRole('button', { name: /keep all and next/i }));

    expect(onDecision).toHaveBeenCalledWith('checksum-1', {
      action: 'discard',
      discardIds: [],
    });
  });

  it('renders four files ahead and keeps selections across file pages', () => {
    const pagedGroup = {
      ...group,
      files: Array.from({ length: 6 }, (_, index) => ({
        id: `file-${index + 1}`,
        name: `copy-${index + 1}.txt`,
        size: '12',
      })),
    };

    const { container } = render(
      <ReviewScreen
        dupGroups={[pagedGroup]}
        decisions={{}}
        onDecision={vi.fn()}
        onExecute={vi.fn()}
        onNoMovesComplete={vi.fn()}
        onAuthExpired={vi.fn()}
      />
    );

    expect(screen.getAllByText(/Preview:/)).toHaveLength(6);
    expect(container.querySelectorAll('[data-preview-state="visible"]')).toHaveLength(4);
    expect(container.querySelectorAll('[data-preview-state="prefetch"]')).toHaveLength(2);
    expect(screen.getByText('Files 1–4 of 6')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /keep file 1/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next files' }));

    expect(screen.getAllByText(/Preview:/)).toHaveLength(2);
    expect(screen.getByText('Files 5–6 of 6')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /keep file 1/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Previous files' }));

    expect(screen.getByRole('button', { name: /stop keeping file 1/i })).toHaveAttribute('aria-pressed', 'true');
    const shortcutConfig = useKeyboardShortcuts.mock.calls.at(-1)[0];
    expect(shortcutConfig.maxIndex).toBe(4);
  });

  it('caps the mounted review window at four visible and four prefetched files', () => {
    const currentGroup = {
      ...group,
      files: Array.from({ length: 4 }, (_, index) => ({
        id: `current-${index + 1}`,
        name: `current-${index + 1}.txt`,
        size: '12',
      })),
    };
    const nextGroup = {
      ...group,
      md5: 'checksum-2',
      files: Array.from({ length: 6 }, (_, index) => ({
        id: `next-${index + 1}`,
        name: `next-${index + 1}.txt`,
        size: '12',
      })),
    };

    const { container } = render(
      <ReviewScreen
        dupGroups={[currentGroup, nextGroup]}
        decisions={{}}
        onDecision={vi.fn()}
        onExecute={vi.fn()}
        onNoMovesComplete={vi.fn()}
        onAuthExpired={vi.fn()}
      />
    );

    expect(screen.getAllByText(/Preview:/)).toHaveLength(8);
    expect(container.querySelectorAll('[data-preview-state="visible"]')).toHaveLength(4);
    expect(container.querySelectorAll('[data-preview-state="prefetch"]')).toHaveLength(4);
    expect(screen.queryByText('Preview: next-5.txt')).not.toBeInTheDocument();
  });

  it('promotes a prefetched preview without remounting it', async () => {
    const nextGroup = {
      ...group,
      md5: 'checksum-2',
      files: [
        { id: 'next-keep', name: 'next-copy.txt', size: '12' },
        { id: 'next-discard', name: 'next-copy.txt', size: '12' },
      ],
    };
    const { container } = render(<StatefulReview groups={[group, nextGroup]} />);
    const prefetchedNode = container.querySelector('[data-preview-id="next-keep"]');

    expect(prefetchedNode.closest('.file-card')).toHaveAttribute('data-preview-state', 'prefetch');
    fireEvent.click(screen.getByRole('button', { name: /keep file 1/i }));
    fireEvent.click(screen.getByRole('button', { name: /keep selected and next/i }));

    await waitFor(() => {
      expect(container.querySelector('[data-preview-id="next-keep"]'))
        .toBe(prefetchedNode);
      expect(prefetchedNode.closest('.file-card')).toHaveAttribute('data-preview-state', 'visible');
    });
  });
});
