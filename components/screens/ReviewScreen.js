'use client';

import { useState, useMemo, useCallback, useEffect } from 'react';
import { formatSize, formatDate } from '@/lib/utils';
import { setSetting, getSetting } from '@/lib/state';
import { prefetchPreview } from '@/lib/preview';
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts';
import FilePreview from '@/components/FilePreview';

const REVIEW_INDEX_KEY = 'reviewIndex';

export default function ReviewScreen({ dupGroups, decisions, onDecision, onExecute }) {
  // Load saved index or start at 0
  const [currentIndex, setCurrentIndex] = useState(() => {
    return getSetting(REVIEW_INDEX_KEY, 0);
  });

  // Save index whenever it changes
  useEffect(() => {
    setSetting(REVIEW_INDEX_KEY, currentIndex);
  }, [currentIndex]);

  // Filter to only show groups that haven't been decided yet
  const pendingGroups = useMemo(() => {
    return dupGroups.filter((g) => !decisions[g.md5]);
  }, [dupGroups, decisions]);

  // Get current group (or null if done)
  const group = pendingGroups[currentIndex] || null;
  const progress = dupGroups.length - pendingGroups.length;
  const total = dupGroups.length;

  const handleKeepByIndex = useCallback((fileIndex) => {
    if (!group || fileIndex >= group.files.length) return;
    const file = group.files[fileIndex];
    onDecision(group.md5, { keep: file.id, action: 'keep' });
    // Auto-advance to next group
    setCurrentIndex((i) => Math.min(i + 1, pendingGroups.length - 1));
  }, [group, onDecision, pendingGroups.length]);

  // Keyboard shortcuts: left = keep first file, right = keep second file
  const keyboardHandlers = useMemo(() => ({
    onLeft: () => handleKeepByIndex(0),
    onRight: () => handleKeepByIndex(1),
  }), [handleKeepByIndex]);

  useKeyboardShortcuts(!!group, keyboardHandlers);

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
    
    // Prefetch in the background without blocking
    filesToPrefetch.forEach(file => {
      prefetchPreview(file).catch(() => {});
    });
  }, [currentIndex, pendingGroups]);
  useEffect(() => {
    if (pendingGroups.length === 0 && dupGroups.length > 0) {
      // All groups reviewed, auto-advance to execute
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

  if (pendingGroups.length === 0) {
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
      </div>

      <div className="group-header">
        <div className="group-md5">MD5: {group.md5.slice(0, 12)}...</div>
        <div className="group-info">
          {group.files.length} files • {formatSize(group.wastedSize)} wasted
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
            <div className="file-actions">
              <button
                className="btn btn-keep"
                onClick={() => handleKeepByIndex(i)}
              >
                Keep
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="shortcuts" style={{ textAlign: 'center', marginTop: 24 }}>
        <span><kbd>←</kbd> Keep first file</span>
        <span style={{ marginLeft: 16 }}><kbd>→</kbd> Keep second file</span>
      </div>
    </div>
  );
}
