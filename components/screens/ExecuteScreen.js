'use client';

import { useState, useMemo, useRef } from 'react';
import { formatSize } from '@/lib/utils';
import { getSettings } from '@/lib/state';
import { moveFile, ensureFolderPath } from '@/lib/drive';
import { pooledMap } from '@/lib/utils';
import { trackEvent, trackException } from '@/lib/analytics';

export default function ExecuteScreen({ dupGroups, decisions }) {
  const [confirmed, setConfirmed] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [results, setResults] = useState(null);
  const completedRef = useRef(0);

  const moves = useMemo(() => {
    const list = [];
    for (const g of dupGroups) {
      const d = decisions[g.md5];
      if (!d || d.action !== 'keep') continue;
      for (const f of g.files) {
        if (f.id !== d.keep) {
          list.push(f);
        }
      }
    }
    return list;
  }, [dupGroups, decisions]);

  async function handleExecute() {
    if (moves.length === 0 || !confirmed) return;

    trackEvent('execute_started', {
      move_count: moves.length,
    });
    setExecuting(true);
    setResults(null);
    completedRef.current = 0;
    setProgress({ current: 0, total: moves.length });

    const settings = getSettings();

    const moveResults = await pooledMap(
      moves,
      async (file) => {
        try {
          const pathParts = (file.path || '/' + file.name).split('/').filter(Boolean);
          pathParts.pop();
          const destParts = [settings.dupesFolder, ...pathParts];
          const destFolderId = await ensureFolderPath(destParts);
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
    setExecuting(false);
    const failedCount = moveResults.filter((result) => !result.ok).length;
    trackEvent('execute_completed', {
      move_count: moves.length,
      success_count: moveResults.length - failedCount,
      failure_count: failedCount,
    });
    if (failedCount > 0) {
      trackException('execute_partial_failure');
    }
  }

  const succeeded = results?.filter((r) => r.ok).length ?? 0;
  const failed = results?.filter((r) => !r.ok) ?? [];

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

          <div className="confirm-row">
            <input
              type="checkbox"
              id="execute-confirm"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            <label htmlFor="execute-confirm">
              I understand these files will be moved to <code>_dupes/</code>
            </label>
          </div>

          {(executing || progress.total > 0) && (
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

          <button
            className="btn btn-danger"
            onClick={handleExecute}
            disabled={!confirmed || executing}
          >
            Move Files
          </button>
        </>
      )}

      {results && (
        <div>
          <div className="execute-summary">
            Moved {succeeded} of {results.length} files
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
