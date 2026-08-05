import { describe, expect, it } from 'vitest';
import { countMovableFiles, validateDiscardDecision } from '@/lib/decisions';

const group = {
  md5: 'checksum',
  files: [{ id: 'a' }, { id: 'b' }, { id: 'c' }],
};

describe('discard decision safety', () => {
  it('normalizes duplicate IDs while preserving at least one copy', () => {
    expect(validateDiscardDecision(group, {
      action: 'discard',
      discardIds: ['a', 'a', 'b'],
    })).toEqual({ valid: true, discardIds: ['a', 'b'], error: null });
    expect(countMovableFiles(group, {
      action: 'discard',
      discardIds: ['a', 'a', 'b'],
    })).toBe(2);
  });

  it('accepts keep-all and skip decisions', () => {
    expect(validateDiscardDecision(group, { action: 'discard', discardIds: [] })).toMatchObject({
      valid: true,
      discardIds: [],
    });
    expect(validateDiscardDecision(group, { action: 'skip' })).toMatchObject({
      valid: true,
      discardIds: [],
    });
  });

  it('rejects all-copy and stale decisions', () => {
    expect(validateDiscardDecision(group, {
      action: 'discard',
      discardIds: ['a', 'b', 'c'],
    })).toMatchObject({ valid: false, discardIds: [] });
    expect(validateDiscardDecision(group, {
      action: 'discard',
      discardIds: ['a', 'missing'],
    })).toMatchObject({ valid: false, discardIds: [] });
  });
});
