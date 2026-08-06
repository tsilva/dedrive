'use client';

import { useState, useMemo, useCallback, useEffect } from 'react';
import { formatSize, formatDate } from '@/lib/utils';
import { countMovableFiles, validateDiscardDecision } from '@/lib/decisions';
import FilePreview from '@/components/FilePreview';
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts';

const FILE_PAGE_SIZE = 4;
const PREFETCH_AHEAD = 4;

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
  const [selectedKeepIds, setSelectedKeepIds] = useState([]);
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
  const selectedKeepIdSet = useMemo(() => new Set(selectedKeepIds), [selectedKeepIds]);
  const selectedKeepCount = group?.files.reduce((count, file) => {
    return count + (selectedKeepIdSet.has(file.id) ? 1 : 0);
  }, 0) || 0;
  const currentMoveCount = group ? group.files.length - selectedKeepCount : 0;
  const filePageCount = Math.max(1, Math.ceil((group?.files.length || 0) / FILE_PAGE_SIZE));
  const firstVisibleFileIndex = filePageIndex * FILE_PAGE_SIZE;
  const visibleFiles = useMemo(() => {
    return group?.files.slice(
      firstVisibleFileIndex,
      firstVisibleFileIndex + FILE_PAGE_SIZE
    ) || [];
  }, [firstVisibleFileIndex, group]);
  const reviewWindowEntries = useMemo(() => {
    if (!group) return [];

    const visibleEntries = visibleFiles.map((file, visibleIndex) => ({
      file,
      groupMd5: group.md5,
      visible: true,
      visibleIndex,
    }));
    const prefetchedEntries = [];
    const nextFileIndex = firstVisibleFileIndex + visibleFiles.length;

    for (let fileIndex = nextFileIndex; fileIndex < group.files.length; fileIndex++) {
      prefetchedEntries.push({
        file: group.files[fileIndex],
        groupMd5: group.md5,
        visible: false,
        visibleIndex: null,
      });
      if (prefetchedEntries.length >= PREFETCH_AHEAD) break;
    }

    for (
      let groupIndex = currentIndex + 1;
      groupIndex < pendingGroups.length && prefetchedEntries.length < PREFETCH_AHEAD;
      groupIndex++
    ) {
      const upcomingGroup = pendingGroups[groupIndex];
      for (const file of upcomingGroup.files) {
        prefetchedEntries.push({
          file,
          groupMd5: upcomingGroup.md5,
          visible: false,
          visibleIndex: null,
        });
        if (prefetchedEntries.length >= PREFETCH_AHEAD) break;
      }
    }

    return [...visibleEntries, ...prefetchedEntries];
  }, [currentIndex, firstVisibleFileIndex, group, pendingGroups, visibleFiles]);
  const currentDecisionValidation = useMemo(() => {
    if (!group) return { valid: false, error: null };

    if (selectedKeepCount === 0) {
      return {
        valid: false,
        discardIds: [],
        error: 'Select at least one copy to keep.',
      };
    }

    return validateDiscardDecision(group, {
      action: 'discard',
      discardIds: group.files
        .filter((file) => !selectedKeepIdSet.has(file.id))
        .map((file) => file.id),
    });
  }, [group, selectedKeepCount, selectedKeepIdSet]);
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
    setSelectedKeepIds([]);
    setFilePageIndex(0);
  }, [group?.md5]);

  useEffect(() => {
    if (filePageIndex >= filePageCount) setFilePageIndex(filePageCount - 1);
  }, [filePageCount, filePageIndex]);

  const handleToggleKeepByIndex = useCallback((visibleFileIndex) => {
    const fileIndex = firstVisibleFileIndex + visibleFileIndex;
    if (!group || visibleFileIndex < 0 || fileIndex >= group.files.length) return;
    const file = group.files[fileIndex];
    setSelectedKeepIds((current) => {
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
    onSelectIndex: handleToggleKeepByIndex,
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
    <div className="screen review-screen">
      {workflowError && (
        <div className="account-notice account-notice-error" role="alert">
          {workflowError}
        </div>
      )}
      <div className="review-command-bar">
        <div className="review-command-copy">
          <div className="review-nav-label">
            Group {progress + 1} of {total} ({pendingGroups.length} remaining)
          </div>
          <div className="group-info">
            {group.files.length} copies • {formatSize(group.wastedSize)} recoverable
          </div>
          <div className="group-md5">MD5: {group.md5.slice(0, 12)}...</div>
          <div className="group-hint">
            Press 1-4 to choose copies to keep, Enter or N for next, S to skip, E to execute.
          </div>
          <div className="group-selection-summary">
            {selectedKeepCount} selected to keep • {currentMoveCount} will move
          </div>
          {!currentDecisionValidation.valid && currentDecisionValidation.error && (
            <div className="group-warning" role="status">{currentDecisionValidation.error}</div>
          )}
          {group.uncertain && (
            <div className="group-warning">Size mismatch - review carefully</div>
          )}
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
          <button
            className="btn btn-primary"
            onClick={handleConfirmCurrent}
            disabled={!currentDecisionValidation.valid}
            title="Keep selected copies and move to the next group (Enter or N)"
          >
            {!currentDecisionValidation.valid
              ? 'Select a Copy to Keep'
              : currentMoveCount === 0
                ? 'Keep All and Next'
                : 'Keep Selected and Next'}
          </button>
        </div>
      </div>

      {filePageCount > 1 && (
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
      )}

      <div className={`files-grid files-grid-count-${visibleFiles.length}`}>
        {reviewWindowEntries.map(({ file: f, groupMd5, visible, visibleIndex }) => {
          const selectedToKeep = groupMd5 === group.md5 && selectedKeepIdSet.has(f.id);
          return (
            <div
              key={f.id}
              className={`file-card${selectedToKeep ? ' file-keep' : ''}${visible ? '' : ' file-card-prefetch'}`}
              data-index={visible ? visibleIndex : undefined}
              data-preview-state={visible ? 'visible' : 'prefetch'}
              aria-hidden={visible ? undefined : true}
              inert={visible ? undefined : true}
            >
              <div className="file-card-toolbar">
                <button
                  className={`file-choice-badge${selectedToKeep ? ' active' : ''}`}
                  onClick={() => visible && handleToggleKeepByIndex(visibleIndex)}
                  aria-label={visible
                    ? `${selectedToKeep ? 'Stop keeping' : 'Keep'} file ${visibleIndex + 1}: ${f.name}`
                    : undefined}
                  aria-pressed={visible ? selectedToKeep : undefined}
                  aria-keyshortcuts={visible ? String(visibleIndex + 1) : undefined}
                  title={visible ? `Keep copy ${visibleIndex + 1}` : undefined}
                  disabled={!visible}
                  tabIndex={visible ? undefined : -1}
                >
                  {visible ? visibleIndex + 1 : '•'}
                </button>
                <div className="file-card-identity">
                  <div className="file-name" title={f.path || f.name}>{f.name}</div>
                  <div className="file-path" title={f.path || '/'}>{f.path || '/'}</div>
                </div>
                <div className="file-card-status">
                  <div className="file-choice-copy">
                    {selectedToKeep ? 'Keep' : 'Will move'}
                  </div>
                  <div className="file-details">
                    <span>{formatSize(parseInt(f.size) || 0)}</span>
                    <span>{formatDate(f.modifiedTime)}</span>
                  </div>
                </div>
              </div>
              <div className="file-preview">
                <FilePreview file={f} onAuthExpired={onAuthExpired} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
