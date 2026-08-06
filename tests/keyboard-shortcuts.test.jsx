import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts';

function ShortcutHarness({
  onSelectIndex,
  onConfirmCurrent,
  onSkipCurrent = vi.fn(),
  onExecute = vi.fn(),
}) {
  useKeyboardShortcuts({
    enabled: true,
    maxIndex: 4,
    onSelectIndex,
    onConfirmCurrent,
    onSkipCurrent,
    onExecute,
  });

  return (
    <div>
      <input aria-label="Editable field" />
      <button type="button">Focused button</button>
    </div>
  );
}

describe('review keyboard shortcuts', () => {
  it('maps number-row and numpad keys to the four visible copies', () => {
    const onSelectIndex = vi.fn();
    render(
      <ShortcutHarness
        onSelectIndex={onSelectIndex}
        onConfirmCurrent={vi.fn()}
      />
    );

    fireEvent.keyDown(window, { key: '1', code: 'Digit1' });
    fireEvent.keyDown(window, { key: '4', code: 'Digit4' });
    fireEvent.keyDown(window, { key: '2', code: 'Numpad2' });
    fireEvent.keyDown(window, { key: '5', code: 'Digit5' });

    expect(onSelectIndex.mock.calls).toEqual([[0], [3], [1]]);
  });

  it('confirms with Enter or N while respecting editable, button, and fullscreen contexts', () => {
    const onConfirmCurrent = vi.fn();
    const { container } = render(
      <ShortcutHarness
        onSelectIndex={vi.fn()}
        onConfirmCurrent={onConfirmCurrent}
      />
    );

    fireEvent.keyDown(window, { key: 'Enter', code: 'Enter' });
    fireEvent.keyDown(window, { key: 'n', code: 'KeyN' });
    expect(onConfirmCurrent).toHaveBeenCalledTimes(2);

    fireEvent.keyDown(screen.getByLabelText('Editable field'), { key: 'Enter', code: 'Enter' });
    fireEvent.keyDown(screen.getByRole('button', { name: 'Focused button' }), {
      key: 'Enter',
      code: 'Enter',
    });
    fireEvent.keyDown(window, { key: 'Enter', code: 'Enter', metaKey: true });

    const overlay = document.createElement('div');
    overlay.className = 'fullscreen-modal-overlay';
    container.appendChild(overlay);
    fireEvent.keyDown(window, { key: 'Enter', code: 'Enter' });

    expect(onConfirmCurrent).toHaveBeenCalledTimes(2);
  });
});
