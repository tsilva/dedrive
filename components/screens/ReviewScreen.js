'use client';

import { useState, useMemo, useCallback, useEffect } from 'react';
import { formatSize, formatDate } from '@/lib/utils';
import { countMovableFiles, validateDiscardDecision } from '@/lib/decisions';
import FilePreview from '@/components/FilePreview';
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts';

const FILE_PAGE_SIZE = 4;

export default function ReviewScreen({
  dupGroups,
  decisions,
  onDecision,
  onExecute,
  onNoMovesComplete,
  onAuthExpired,
  workflowError = null,
}) {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [selectedDiscardIds, setSelectedDiscardIds] = useState([]);
  const [filePageIndex, setFilePageIndex] = useState(0);

  // Filter to only show groups that haven't been decided yet
  const pendingGroups = useMemo(() => {
    return dupGroups.filter((g) => !decisions[g.md5]);
  }, [dupGroups, decisions]);

  // Clamp currentIndex when pendingGroups changes (e.g., after rapid navigation)
  useEffect(() => {
    if (currentIndex >= pendingGroups.length && pendingGroups.length > 0) {
      setCurrentIndex(pendingGroups.length - 1);
    }
  }, [currentIndex, pendingGroups.length]);

  // Get current group (or null if done)
  const group = pendingGroups[currentIndex] || null;
  const progress = dupGroups.length - pendingGroups.length;
  const total = dupGroups.length;
  const selectedDiscardIdSet = useMemo(() => new Set(selectedDiscardIds), [selectedDiscardIds]);
  const currentMoveCount = selectedDiscardIds.length;
  const filePageCount = Math.max(1, Math.ceil((group?.files.length || 0) / FILE_PAGE_SIZE));
  const firstVisibleFileIndex = filePageIndex * FILE_PAGE_SIZE;
  const visibleFiles = group?.files.slice(
    firstVisibleFileIndex,
    firstVisibleFileIndex + FILE_PAGE_SIZE
  ) || [];
  const currentDecisionValidation = useMemo(() => {
    if (!group) return { valid: false, error: null };
    return validateDiscardDecision(group, {
      action: 'discard',
      discardIds: selectedDiscardIds,
    });
  }, [group, selectedDiscardIds]);
  const decidedGroups = useMemo(() => {
    return dupGroups.filter((currentGroup) => {
      const decision = decisions[currentGroup.md5];
      return decision && decision.action !== 'skip';
    });
  }, [decisions, dupGroups]);
  const moveCount = useMemo(() => {
    return decidedGroups.reduce((count, currentGroup) => {
      return count + countMovableFiles(currentGroup, decisions[currentGroup.md5]);
    }, 0);
  }, [decidedGroups, decisions]);

  useEffect(() => {
    setSelectedDiscardIds([]);
    setFilePageIndex(0);
  }, [group?.md5]);

  useEffect(() => {
    if (filePageIndex >= filePageCount) setFilePageIndex(filePageCount - 1);
  }, [filePageCount, filePageIndex]);

  const handleToggleDiscardByIndex = useCallback((visibleFileIndex) => {
    const fileIndex = firstVisibleFileIndex + visibleFileIndex;
    if (!group || visibleFileIndex < 0 || fileIndex >= group.files.length) return;
    const file = group.files[fileIndex];
    setSelectedDiscardIds((current) => {
      if (current.includes(file.id)) {
        return current.filter((id) => id !== file.id);
      }
      return [...current, file.id];
    });
  }, [firstVisibleFileIndex, group]);

  const handleConfirmCurrent = useCallback(() => {
    if (!group || !currentDecisionValidation.valid) return;
    setFilePageIndex(0);
    onDecision(group.md5, {
      discardIds: currentDecisionValidation.discardIds,
      action: 'discard',
    });
  }, [currentDecisionValidation, group, onDecision]);

  const handleSkipCurrent = useCallback(() => {
    if (!group) return;
    setFilePageIndex(0);
    onDecision(group.md5, { action: 'skip' });
  }, [group, onDecision]);

  const handleExecute = useCallback(() => {
    if (moveCount === 0) return;
    onExecute?.();
  }, [moveCount, onExecute]);

  useKeyboardShortcuts({
    enabled: Boolean(group),
    maxIndex: visibleFiles.length,
    onSelectIndex: handleToggleDiscardByIndex,
    onSkipCurrent: handleSkipCurrent,
    onConfirmCurrent: handleConfirmCurrent,
    onExecute: handleExecute,
  });

  useEffect(() => {
    if (pendingGroups.length === 0 && dupGroups.length > 0) {
      if (moveCount > 0) {
        onExecute?.();
      } else {
        onNoMovesComplete?.();
      }
    }
  }, [pendingGroups.length, dupGroups.length, moveCount, onExecute, onNoMovesComplete]);

  if (dupGroups.length === 0) {
    return (
      <div className="screen">
        <div className="empty-state">No duplicates found. Run a scan first.</div>
      </div>
    );
  }

  if (pendingGroups.length === 0 || !group) {
    return (
      <div className="screen">
        <div className="setup-title" style={{ marginBottom: 24 }}>Review Complete</div>
        <div className="empty-state">
          All {total} duplicate groups reviewed.
        </div>
      </div>
    );
  }

  return (
    <div className="screen">
      {workflowError && (
        <div className="account-notice account-notice-error" role="alert">
          {workflowError}
        </div>
      )}
      <div className="review-toolbar">
        <div className="review-nav-label">
          Group {progress + 1} of {total} ({pendingGroups.length} remaining)
        </div>
        <div className="review-actions">
          <button
            className="btn btn-skip"
            onClick={handleSkipCurrent}
            title="Skip this group (S)"
          >
            Skip Current
          </button>
          <button
            className="btn"
            onClick={handleExecute}
            disabled={moveCount === 0}
            title="Go to execute (E)"
          >
            Go to Execute ({moveCount} file{moveCount === 1 ? '' : 's'} marked)
          </button>
        </div>
      </div>

      <div className="group-header">
        <div className="group-md5">MD5: {group.md5.slice(0, 12)}...</div>
        <div className="group-info">
          {group.files.length} files • {formatSize(group.wastedSize)} wasted
        </div>
        <div className="group-hint">
          Press 1-4 to mark visible duplicates to discard, Enter or N for next, S to skip, E to execute.
        </div>
        <div className="group-selection-summary">
          {selectedDiscardIds.length} selected to discard • {group.files.length - currentMoveCount} will be kept
        </div>
        {!currentDecisionValidation.valid && currentDecisionValidation.error && (
          <div className="group-warning" role="alert">{currentDecisionValidation.error}</div>
        )}
        {group.uncertain && (
          <div className="group-warning">Size mismatch - review carefully</div>
        )}
      </div>

      <div className="group-confirm-row">
        <button
          className="btn btn-primary"
          onClick={handleConfirmCurrent}
          disabled={!currentDecisionValidation.valid}
          title="Confirm this group and move to next group (Enter or N)"
        >
          {!currentDecisionValidation.valid
            ? 'Keep at Least One Copy'
            : selectedDiscardIds.length === 0
              ? 'Keep All and Next'
              : 'Discard Selected and Next'}
        </button>
      </div>

      <div className="file-pagination" aria-label="Duplicate file pages">
        <button
          className="btn"
          type="button"
          onClick={() => setFilePageIndex((page) => Math.max(0, page - 1))}
          disabled={filePageIndex === 0}
          aria-label="Previous files"
        >
          Previous
        </button>
        <span aria-live="polite">
          Files {firstVisibleFileIndex + 1}–{firstVisibleFileIndex + visibleFiles.length} of {group.files.length}
        </span>
        <button
          className="btn"
          type="button"
          onClick={() => setFilePageIndex((page) => Math.min(filePageCount - 1, page + 1))}
          disabled={filePageIndex >= filePageCount - 1}
          aria-label="Next files"
        >
          Next
        </button>
      </div>

      <div className="files-grid">
        {visibleFiles.map((f, i) => (
          <div
            key={f.id}
            className={`file-card${selectedDiscardIdSet.has(f.id) ? ' file-discard' : ''}`}
            data-index={i}
          >
            <div className="file-card-toolbar">
              <button
                className={`file-choice-badge${selectedDiscardIdSet.has(f.id) ? ' active' : ''}`}
                onClick={() => handleToggleDiscardByIndex(i)}
                aria-label={`${selectedDiscardIdSet.has(f.id) ? 'Keep' : 'Discard'} file ${i + 1}: ${f.name}`}
                aria-pressed={selectedDiscardIdSet.has(f.id)}
                title={`Toggle file ${i + 1}`}
              >
                {i + 1}
              </button>
              <div className="file-choice-copy">
                {selectedDiscardIdSet.has(f.id) ? 'Selected to discard' : 'Kept unless selected'}
              </div>
            </div>
            <div className="file-preview">
              <FilePreview file={f} onAuthExpired={onAuthExpired} />
            </div>
            <div className="file-meta">
              <div className="file-name" title={f.path || f.name}>{f.name}</div>
              <div className="file-path">{f.path || '/'}</div>
              <div className="file-details">
                <span>{formatSize(parseInt(f.size) || 0)}</span>
                <span>{formatDate(f.modifiedTime)}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
