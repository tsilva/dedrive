'use client';

import { useEffect } from 'react';

function isEditableTarget(target) {
  if (!(target instanceof HTMLElement)) return false;

  const tagName = target.tagName;
  return target.isContentEditable
    || tagName === 'INPUT'
    || tagName === 'TEXTAREA'
    || tagName === 'SELECT';
}

function getShortcutIndex(event) {
  if (/^[1-9]$/.test(event.key)) {
    return parseInt(event.key, 10) - 1;
  }

  if (event.key === '0') {
    return 9;
  }

  if (/^Digit[0-9]$/.test(event.code)) {
    const digit = parseInt(event.code.slice(-1), 10);
    return digit === 0 ? 9 : digit - 1;
  }

  if (/^Numpad[0-9]$/.test(event.code)) {
    const digit = parseInt(event.code.slice(-1), 10);
    return digit === 0 ? 9 : digit - 1;
  }

  return null;
}

export function useKeyboardShortcuts({ enabled = true, maxIndex = 0, onSelectIndex }) {
  useEffect(() => {
    if (!enabled || maxIndex <= 0 || typeof onSelectIndex !== 'function') return undefined;

    const handleKeyDown = (event) => {
      if (
        event.defaultPrevented
        || event.repeat
        || event.isComposing
        || event.ctrlKey
        || event.metaKey
        || event.altKey
        || isEditableTarget(event.target)
        || document.querySelector('.fullscreen-modal-overlay')
      ) {
        return;
      }

      const shortcutIndex = getShortcutIndex(event);
      if (shortcutIndex === null || shortcutIndex >= maxIndex) return;

      event.preventDefault();
      onSelectIndex(shortcutIndex);
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [enabled, maxIndex, onSelectIndex]);
}
