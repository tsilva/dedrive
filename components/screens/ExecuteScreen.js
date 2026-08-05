'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { formatSize } from '@/lib/utils';
import { getSettings } from '@/lib/state';
import {
  assertPrivateFolder,
  moveFile,
  ensureDedupeRootFolder,
  ensureFolderPath,
} from '@/lib/drive';
import { isInDedupeFolder } from '@/lib/dedup';
import { validateDiscardDecision } from '@/lib/decisions';
import { pooledMap } from '@/lib/utils';
import { isAuthExpiredError } from '@/lib/auth';
import { trackEvent, trackException } from '@/lib/analytics';

const PRIVATE_REPLACEMENT_NOTICE =
  'Created a private _dupes destination because an existing cleanup folder is shared.';

export default function ExecuteScreen({
  canWrite,
  decisions,
  dupGroups,
  onRequestWriteAccess,
  onEnsureWriteAccess,
  onAuthExpired,
  onComplete,
}) {
  const [confirmed, setConfirmed] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [grantingWriteAccess, setGrantingWriteAccess] = useState(false);
  const [grantError, setGrantError] = useState(null);
  const [sessionExpiring, setSessionExpiring] = useState(false);
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [results, setResults] = useState(null);
  const [destinationNotice, setDestinationNotice] = useState(null);
  const completedRef = useRef(0);
  const executingRef = useRef(false);
  const authExpiredRef = useRef(false);
  const destinationNoticeRef = useRef(null);

  function recordDestinationResult(result) {
    if (!result?.privacyReplacementCreated) return;
    destinationNoticeRef.current = PRIVATE_REPLACEMENT_NOTICE;
    setDestinationNotice(PRIVATE_REPLACEMENT_NOTICE);
  }

  const movePlan = useMemo(() => {
    const settings = getSettings();
    const list = [];
    for (const g of dupGroups) {
      const d = decisions[g.md5];
      if (!d || d.action === 'skip') continue;
      const validation = validateDiscardDecision(g, d);
      if (!validation.valid) {
        return { moves: [], validationError: validation.error };
      }
      const discardIds = new Set(validation.discardIds);
      if (discardIds.size === 0) continue;
      for (const f of g.files) {
        if (discardIds.has(f.id) && !isInDedupeFolder(f, settings.dupesFolder)) {
          list.push(f);
        }
      }
    }
    return { moves: list, validationError: null };
  }, [dupGroups, decisions]);
  const { moves, validationError } = movePlan;

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
    if (validationError || moves.length === 0 || !confirmed || !canWrite) return;

    executingRef.current = true;
    setGrantError(null);

    try {
      await onEnsureWriteAccess?.();
    } catch (error) {
      executingRef.current = false;
      if (isAuthExpiredError(error)) {
        onAuthExpired?.();
        return;
      }
      setGrantError(error.message || 'Google authorization could not be refreshed.');
      return;
    }

    trackEvent('execute_started', {
      move_count: moves.length,
    });
    setExecuting(true);
    setResults(null);
    setSessionExpiring(false);
    setDestinationNotice(null);
    destinationNoticeRef.current = null;
    authExpiredRef.current = false;
    completedRef.current = 0;
    setProgress({ current: 0, total: moves.length });

    const settings = getSettings();
    try {
      const dupesRoot = await ensureDedupeRootFolder(settings.dupesFolder);
      recordDestinationResult(dupesRoot);
      const moveResults = await pooledMap(
        moves,
        async (file) => {
          const markCompleted = () => {
            completedRef.current++;
            setProgress({ current: completedRef.current, total: moves.length });
          };

          if (authExpiredRef.current) {
            markCompleted();
            return {
              ok: false,
              name: file.name,
              authExpired: true,
              aborted: true,
              error: 'Move cancelled after the Google session expired.',
            };
          }

          try {
            if (isInDedupeFolder(file, settings.dupesFolder)) {
              markCompleted();
              return { ok: true, name: file.name, skipped: true };
            }

            const destination = await ensureFolderPath(file.parentChain || [], dupesRoot.id);
            recordDestinationResult(destination);
            await assertPrivateFolder(destination.id);
            await moveFile(file.id, file.parents || [], destination.id);
            markCompleted();
            return { ok: true, name: file.name };
          } catch (e) {
            recordDestinationResult(e);
            if (isAuthExpiredError(e)) {
              authExpiredRef.current = true;
              setSessionExpiring(true);
            }
            markCompleted();
            return {
              ok: false,
              name: file.name,
              authExpired: isAuthExpiredError(e),
              error: e.message,
            };
          }
        },
        settings.batchSize
      );

      if (authExpiredRef.current) {
        const successCount = moveResults.filter((result) => result.ok && !result.skipped).length;
        await onAuthExpired?.({
          successCount,
          total: moves.length,
          ...(destinationNoticeRef.current
            ? { destinationNotice: destinationNoticeRef.current }
            : {}),
        });
        return;
      }

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
      await onComplete?.(moveResults, {
        ...(destinationNoticeRef.current
          ? { destinationNotice: destinationNoticeRef.current }
          : {}),
      });
    } catch (error) {
      recordDestinationResult(error);
      if (isAuthExpiredError(error)) {
        setSessionExpiring(true);
        await onAuthExpired?.({
          successCount: 0,
          total: moves.length,
          ...(destinationNoticeRef.current
            ? { destinationNotice: destinationNoticeRef.current }
            : {}),
        });
        return;
      }
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

      {destinationNotice && (
        <div className="account-notice account-notice-info" role="status">
          {destinationNotice}
        </div>
      )}

      {validationError ? (
        <div className="account-notice account-notice-error" role="alert">
          {validationError} No Drive changes were made.
        </div>
      ) : moves.length === 0 ? (
        <div className="empty-state">No files marked to move.</div>
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

          {grantError && !showWriteAccessPrompt && (
            <div className="permission-panel-error">{grantError}</div>
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
                {sessionExpiring
                  ? `Google session expired. Finalizing in-flight moves... ${progress.current}/${progress.total}`
                  : `Moving files... ${progress.current}/${progress.total}`}
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
