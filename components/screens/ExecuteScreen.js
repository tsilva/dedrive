'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { formatSize } from '@/lib/utils';
import { getSettings } from '@/lib/state';
import { moveFile, ensureDedupeRootFolder, ensureFolderPath } from '@/lib/drive';
import { isInDedupeFolder } from '@/lib/dedup';
import { pooledMap } from '@/lib/utils';
import { trackEvent, trackException } from '@/lib/analytics';

export default function ExecuteScreen({
  canWrite,
  decisions,
  dupGroups,
  onRequestWriteAccess,
  onComplete,
}) {
  const [confirmed, setConfirmed] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [grantingWriteAccess, setGrantingWriteAccess] = useState(false);
  const [grantError, setGrantError] = useState(null);
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [results, setResults] = useState(null);
  const completedRef = useRef(0);
  const executingRef = useRef(false);

  const moves = useMemo(() => {
    const settings = getSettings();
    const list = [];
    for (const g of dupGroups) {
      const d = decisions[g.md5];
      if (!d || d.action !== 'keep') continue;
      for (const f of g.files) {
        if (f.id !== d.keep && !isInDedupeFolder(f, settings.dupesFolder)) {
          list.push(f);
        }
      }
    }
    return list;
  }, [dupGroups, decisions]);

  useEffect(() => {
    if (canWrite) {
      setGrantError(null);
    }
  }, [canWrite]);

  async function handleGrantWriteAccess() {
    if (!onRequestWriteAccess) return;

    setGrantError(null);
    setGrantingWriteAccess(true);

    try {
      await onRequestWriteAccess();
    } catch (error) {
      setGrantError(error.message || 'Google did not grant write access.');
    } finally {
      setGrantingWriteAccess(false);
    }
  }

  async function handleExecute() {
    if (executingRef.current) return;
    if (moves.length === 0 || !confirmed || !canWrite) return;

    executingRef.current = true;
    trackEvent('execute_started', {
      move_count: moves.length,
    });
    setExecuting(true);
    setResults(null);
    completedRef.current = 0;
    setProgress({ current: 0, total: moves.length });

    const settings = getSettings();
    try {
      const dupesRootId = await ensureDedupeRootFolder(settings.dupesFolder);
      const moveResults = await pooledMap(
        moves,
        async (file) => {
          try {
            if (isInDedupeFolder(file, settings.dupesFolder)) {
              completedRef.current++;
              setProgress({ current: completedRef.current, total: moves.length });
              return { ok: true, name: file.name, skipped: true };
            }

            const pathParts = (file.path || '/' + file.name).split('/').filter(Boolean);
            pathParts.pop();
            const destFolderId = await ensureFolderPath(pathParts, dupesRootId);
            await moveFile(file.id, file.parents || [], destFolderId);
            completedRef.current++;
            setProgress({ current: completedRef.current, total: moves.length });
            return { ok: true, name: file.name };
          } catch (e) {
            completedRef.current++;
            setProgress({ current: completedRef.current, total: moves.length });
            return { ok: false, name: file.name, error: e.message };
          }
        },
        settings.batchSize
      );

      setResults(moveResults);
      const failedCount = moveResults.filter((result) => !result.ok).length;
      trackEvent('execute_completed', {
        move_count: moves.length,
        success_count: moveResults.length - failedCount,
        failure_count: failedCount,
      });
      if (failedCount > 0) {
        trackException('execute_partial_failure');
      }
      await onComplete?.(moveResults);
    } catch (error) {
      setResults([{ ok: false, name: 'Move setup', error: error.message || 'Move setup failed.' }]);
      trackException('execute_failed', true);
    } finally {
      setExecuting(false);
      executingRef.current = false;
    }
  }

  const failed = results?.filter((r) => !r.ok) ?? [];
  const showWriteAccessPrompt = !results && !canWrite;

  return (
    <div className="screen">
      <div className="setup-title" style={{ marginBottom: 24 }}>Execute</div>

      {moves.length === 0 ? (
        <div className="empty-state">No files to move. Review duplicates first.</div>
      ) : (
        <>
          <div className="dry-run-header">
            {moves.length} files will be moved to <code>_dupes/</code>
          </div>
          <table className="dry-run-table">
            <thead>
              <tr>
                <th>File</th>
                <th>Size</th>
                <th>Current Path</th>
              </tr>
            </thead>
            <tbody>
              {moves.map((m, i) => (
                <tr key={i}>
                  <td>{m.name}</td>
                  <td>{formatSize(parseInt(m.size) || 0)}</td>
                  <td className="path-cell">{m.path || '/'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="dry-run-total">
            Total: {formatSize(moves.reduce((s, m) => s + (parseInt(m.size) || 0), 0))}
          </div>

          {showWriteAccessPrompt && (
            <div className="permission-panel">
              <div className="permission-panel-title">Write access is required to move files</div>
              <div className="permission-panel-copy">
                Scan and review used read-only Drive access. Grant write access now to move the selected duplicates
                into <code>_dupes/</code>.
              </div>
              <button
                className="btn btn-primary"
                onClick={handleGrantWriteAccess}
                disabled={grantingWriteAccess}
              >
                {grantingWriteAccess ? 'Requesting Access...' : 'Grant Write Access'}
              </button>
              {grantError && <div className="permission-panel-error">{grantError}</div>}
            </div>
          )}

          <div className="confirm-row">
            <input
              type="checkbox"
              id="execute-confirm"
              checked={confirmed}
              disabled={!canWrite}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            <label htmlFor="execute-confirm">
              I understand these files will be moved to <code>_dupes/</code>
            </label>
          </div>

          {executing && (
            <>
              <div className="progress-container">
                <div
                  className="progress-bar"
                  style={{ width: progress.total > 0 ? `${Math.round((progress.current / progress.total) * 100)}%` : '0%' }}
                />
              </div>
              <div className="progress-label">
                Moving files... {progress.current}/{progress.total}
              </div>
            </>
          )}

          {!executing && !results && (
            <button
              className="btn btn-danger"
              onClick={handleExecute}
              disabled={!confirmed || !canWrite}
            >
              Move Files
            </button>
          )}
        </>
      )}

      {results && (
        <div>
          <div className="execute-summary">
            {failed.length === 0 ? 'Move complete.' : `Move complete with ${failed.length} failure${failed.length === 1 ? '' : 's'}.`}
          </div>
          {failed.length > 0 && (
            <div className="execute-errors">
              <div className="error-header">{failed.length} failed:</div>
              {failed.map((f, i) => (
                <div key={i} className="error-item">{f.name}: {f.error}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
