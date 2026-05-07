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

function isButtonTarget(target) {
  return target instanceof HTMLElement && Boolean(target.closest('button, a, [role="button"]'));
}

export function useKeyboardShortcuts({
  enabled = true,
  maxIndex = 0,
  onSelectIndex,
  onSkipCurrent,
  onConfirmCurrent,
  onExecute,
}) {
  useEffect(() => {
    if (
      !enabled
      || (
        typeof onSelectIndex !== 'function'
        && typeof onSkipCurrent !== 'function'
        && typeof onConfirmCurrent !== 'function'
        && typeof onExecute !== 'function'
      )
    ) {
      return undefined;
    }

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

      const key = event.key.toLowerCase();

      if (key === 's' && typeof onSkipCurrent === 'function') {
        event.preventDefault();
        onSkipCurrent();
        return;
      }

      if ((key === 'n' || event.key === 'Enter') && typeof onConfirmCurrent === 'function') {
        if (event.key === 'Enter' && isButtonTarget(event.target)) return;
        event.preventDefault();
        onConfirmCurrent();
        return;
      }

      if (key === 'e' && typeof onExecute === 'function') {
        event.preventDefault();
        onExecute();
        return;
      }

      if (maxIndex <= 0 || typeof onSelectIndex !== 'function') return;

      const shortcutIndex = getShortcutIndex(event);
      if (shortcutIndex === null || shortcutIndex >= maxIndex) return;

      event.preventDefault();
      onSelectIndex(shortcutIndex);
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [enabled, maxIndex, onSelectIndex, onSkipCurrent, onConfirmCurrent, onExecute]);
}
