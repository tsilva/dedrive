'use client';

import { useState, useMemo, useCallback, useEffect } from 'react';
import { formatSize, formatDate } from '@/lib/utils';
import { prefetchPreview } from '@/lib/preview';
import FilePreview from '@/components/FilePreview';
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts';

export default function ReviewScreen({ dupGroups, decisions, onDecision, onExecute }) {
  const [currentIndex, setCurrentIndex] = useState(0);

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
  const decidedGroups = useMemo(() => {
    return dupGroups.filter((currentGroup) => decisions[currentGroup.md5]?.action === 'keep');
  }, [decisions, dupGroups]);
  const moveCount = useMemo(() => {
    return decidedGroups.reduce((count, currentGroup) => {
      const keepId = decisions[currentGroup.md5]?.keep;
      return count + currentGroup.files.filter((file) => file.id !== keepId).length;
    }, 0);
  }, [decidedGroups, decisions]);

  const handleKeepByIndex = useCallback((fileIndex) => {
    if (!group || fileIndex >= group.files.length) return;
    const file = group.files[fileIndex];
    onDecision(group.md5, { keep: file.id, action: 'keep' });
  }, [group, onDecision]);

  const handleSkipCurrent = useCallback(() => {
    if (!group) return;
    onDecision(group.md5, { action: 'skip' });
  }, [group, onDecision]);

  useKeyboardShortcuts({
    enabled: Boolean(group),
    maxIndex: group?.files.length ?? 0,
    onSelectIndex: handleKeepByIndex,
    onSkipCurrent: handleSkipCurrent,
  });

  // Prefetch previews for upcoming groups (next 2 groups)
  useEffect(() => {
    if (!pendingGroups.length) return;

    const PREFETCH_AHEAD = 2;
    const filesToPrefetch = [];

    for (let i = 1; i <= PREFETCH_AHEAD; i++) {
      const nextIndex = currentIndex + i;
      if (nextIndex < pendingGroups.length) {
        const nextGroup = pendingGroups[nextIndex];
        filesToPrefetch.push(...nextGroup.files);
      }
    }

    filesToPrefetch.forEach((file) => {
      prefetchPreview(file).catch(() => {});
    });
  }, [currentIndex, pendingGroups]);

  useEffect(() => {
    if (pendingGroups.length === 0 && dupGroups.length > 0) {
      onExecute?.();
    }
  }, [pendingGroups.length, dupGroups.length, onExecute]);

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
      <div className="review-toolbar">
        <div className="review-nav-label">
          Group {progress + 1} of {total} ({pendingGroups.length} remaining)
        </div>
        <div className="review-actions">
          <button
            className="btn btn-skip"
            onClick={handleSkipCurrent}
          >
            Skip Current
          </button>
          <button
            className="btn"
            onClick={() => onExecute?.()}
            disabled={moveCount === 0}
          >
            Go to Execute ({moveCount} file{moveCount === 1 ? '' : 's'} selected)
          </button>
        </div>
      </div>

      <div className="group-header">
        <div className="group-md5">MD5: {group.md5.slice(0, 12)}...</div>
        <div className="group-info">
          {group.files.length} files • {formatSize(group.wastedSize)} wasted
        </div>
        <div className="group-hint">
          Click a numbered badge or press 1-9 to keep that file. Press S to skip this group.
        </div>
        {group.uncertain && (
          <div className="group-warning">Size mismatch - review carefully</div>
        )}
      </div>

      <div className="files-grid">
        {group.files.map((f, i) => (
          <div
            key={f.id}
            className="file-card"
            data-index={i}
          >
            <div className="file-card-toolbar">
              <button
                className="file-choice-badge"
                onClick={() => handleKeepByIndex(i)}
                aria-label={`Keep file ${i + 1}: ${f.name}`}
                title={`Keep file ${i + 1}`}
              >
                {i + 1}
              </button>
              <div className="file-choice-copy">Keep this file</div>
            </div>
            <div className="file-preview">
              <FilePreview file={f} />
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
