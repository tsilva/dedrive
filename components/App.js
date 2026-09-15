'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import dynamic from 'next/dynamic';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import Script from 'next/script';
import Header from './Header';
import Footer from './Footer';
import AccountScreen from './screens/AccountScreen';
import { useDecisions } from '@/hooks/useDecisions';
import {
  hasWriteAccess,
  initAuth,
  invalidateAuth,
  isAuthExpiredError,
  ensureReadAccess,
  ensureWriteAccess,
  requestReadAccess,
  requestWriteAccess,
  signOut,
} from '@/lib/auth';
import { clearFolderCache, getDriveRootId, getUserInfo, fetchAllFiles } from '@/lib/drive';
import {
  excludeBlacklistedPathFiles,
  excludeDedupeFolderFiles,
  filterOwnedMyDriveTree,
  findDuplicates,
  resolvePaths,
  computeStats,
} from '@/lib/dedup';
import { clearPreviewCache } from '@/lib/preview';
import { countMovableFiles, validateDiscardDecision } from '@/lib/decisions';
import { getSettings, saveSettings, purgeAppBrowserData } from '@/lib/state';
import { trackEvent, trackException } from '@/lib/analytics';

const CLIENT_ID = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
const ScanScreen = dynamic(() => import('./screens/ScanScreen'));
const ReviewScreen = dynamic(() => import('./screens/ReviewScreen'));
const ExecuteScreen = dynamic(() => import('./screens/ExecuteScreen'));

export default function App({ clientId = CLIENT_ID }) {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [screen, setScreen] = useState('account');
  const [authInitStatus, setAuthInitStatus] = useState(clientId ? 'loading' : 'error');
  const [authInitError, setAuthInitError] = useState(
    clientId ? null : 'Google sign-in is unavailable because the OAuth client ID is not configured.'
  );
  const [user, setUser] = useState(null);
  const [authNotice, setAuthNotice] = useState(null);
  const [completionNotice, setCompletionNotice] = useState(null);
  const [authError, setAuthError] = useState(null);
  const [canWrite, setCanWrite] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState({ page: 0, fileCount: 0 });
  const [scanError, setScanError] = useState(null);
  const [reviewError, setReviewError] = useState(null);
  const { decisions, setDecision, removeDecisions, clearDecisions } = useDecisions();
  const [dupGroups, setDupGroups] = useState([]);
  const [blacklistedPrefixes, setBlacklistedPrefixes] = useState(
    () => getSettings().blacklistedPathPrefixes
  );
  const [ignoreSmallFiles, setIgnoreSmallFiles] = useState(() => getSettings().ignoreSmallFiles ?? true);
  const authExpiryHandledRef = useRef(false);

  const stats = dupGroups.length > 0 ? computeStats(dupGroups) : null;

  const clearWorkflowState = useCallback(() => {
    clearPreviewCache();
    clearFolderCache();
    clearDecisions();
    setDupGroups([]);
    setScanning(false);
    setScanProgress({ page: 0, fileCount: 0 });
    setScanError(null);
    setReviewError(null);
  }, [clearDecisions]);

  const handleAuthExpired = useCallback((details = {}) => {
    if (authExpiryHandledRef.current) return;
    authExpiryHandledRef.current = true;

    invalidateAuth();
    clearWorkflowState();
    setUser(null);
    setCanWrite(false);
    setAuthNotice(null);
    setCompletionNotice(null);

    const destinationCopy = details.destinationNotice ? ` ${details.destinationNotice}` : '';
    if (Number.isInteger(details.successCount) && Number.isInteger(details.total)) {
      setAuthError(
        `Your Google session expired after ${details.successCount} of ${details.total} files moved. ` +
        `Completed moves remain in _dupes. Sign in again and run a new scan.${destinationCopy}`
      );
    } else {
      setAuthError(`Your Google session expired. Sign in again and start a new scan.${destinationCopy}`);
    }
    setScreen('account');
  }, [clearWorkflowState]);

  const handleGsiLoad = useCallback(() => {
    if (!clientId) return;

    try {
      initAuth(clientId);
      setAuthInitError(null);
      setAuthInitStatus('ready');
    } catch (error) {
      console.error('Auth init failed:', error);
      setAuthInitStatus('error');
      setAuthInitError('Google sign-in could not initialize. Refresh the page and try again.');
    }
  }, [clientId]);

  const handleGsiError = useCallback(() => {
    if (!clientId) return;
    setAuthInitStatus('error');
    setAuthInitError('Google sign-in could not load. Check your connection and refresh the page.');
  }, [clientId]);

  const handleSignIn = useCallback(async () => {
    if (authInitStatus !== 'ready') {
      setAuthError('Google sign-in is not ready yet. Wait for it to finish loading and try again.');
      return;
    }

    trackEvent('sign_in_started');
    setAuthNotice(null);
    setCompletionNotice(null);
    setAuthError(null);

    try {
      await requestReadAccess();
      const nextUser = await getUserInfo();
      clearWorkflowState();
      authExpiryHandledRef.current = false;
      setUser(nextUser);
      setCanWrite(hasWriteAccess());
      setScreen('account');
    } catch (error) {
      signOut();
      clearWorkflowState();
      setUser(null);
      setCanWrite(false);
      setAuthError(error.message);
      console.error('Sign in failed:', error);
    }
  }, [authInitStatus, clearWorkflowState]);

  const handleSignOut = useCallback(() => {
    trackEvent('sign_out');
    signOut();
    clearWorkflowState();
    authExpiryHandledRef.current = false;
    setUser(null);
    setCanWrite(false);
    setAuthNotice(null);
    setCompletionNotice(null);
    setAuthError(null);
    setScreen('account');
  }, [clearWorkflowState]);

  const handleAddBlacklistedPrefix = useCallback((prefix) => {
    if (!prefix || blacklistedPrefixes.includes(prefix)) return;
    const next = [...blacklistedPrefixes, prefix];
    setBlacklistedPrefixes(next);
    saveSettings({ blacklistedPathPrefixes: next });
  }, [blacklistedPrefixes]);

  const handleRemoveBlacklistedPrefix = useCallback((prefix) => {
    const next = blacklistedPrefixes.filter((item) => item !== prefix);
    if (next.length === blacklistedPrefixes.length) return;
    setBlacklistedPrefixes(next);
    saveSettings({ blacklistedPathPrefixes: next });
  }, [blacklistedPrefixes]);

  const handleIgnoreSmallFilesChange = useCallback((enabled) => {
    setIgnoreSmallFiles(enabled);
    saveSettings({ ignoreSmallFiles: enabled });
  }, []);

  const handleStartScan = useCallback(async () => {
    trackEvent('scan_started');
    clearWorkflowState();
    setAuthNotice(null);
    setCompletionNotice(null);
    setAuthError(null);
    setScreen('scan');
    setScanning(true);
    setScanProgress({ page: 0, fileCount: 0 });

    try {
      await ensureReadAccess();
      const [rootId, allFiles] = await Promise.all([
        getDriveRootId(),
        fetchAllFiles(({ page, fileCount }) => {
          setScanProgress({ page, fileCount });
        }),
      ]);

      const settings = getSettings();
      const ownedTreeFiles = filterOwnedMyDriveTree(allFiles, rootId);
      const resolvedFiles = excludeDedupeFolderFiles(resolvePaths(ownedTreeFiles), settings.dupesFolder);
      const pathFilteredFiles = excludeBlacklistedPathFiles(resolvedFiles, settings.blacklistedPathPrefixes);
      const blacklistedCount = resolvedFiles.length - pathFilteredFiles.length;
      const scannedFiles = ignoreSmallFiles
        ? pathFilteredFiles.filter((file) => file.size == null || !(Number(file.size) < 1024))
        : pathFilteredFiles;
      const groups = findDuplicates(scannedFiles);
      const scanStats = computeStats(groups);
      setDupGroups(groups);
      trackEvent('scan_completed', {
        file_count: scannedFiles.length,
        blacklisted_file_count: blacklistedCount,
        duplicate_group_count: scanStats.totalGroups,
        duplicate_file_count: scanStats.totalFiles,
        uncertain_group_count: scanStats.uncertainCount,
        potential_savings_bytes: scanStats.totalWasted,
      });
      setScanning(false);
      if (groups.length > 0) {
        setScreen('review');
      } else {
        clearWorkflowState();
        setCompletionNotice('No duplicates found. Your Drive was left unchanged.');
        setScreen('account');
      }
    } catch (e) {
      trackException('scan_failed');
      trackEvent('scan_failed', {
        error_type: e.message?.split(':')[0] || 'unknown',
      });
      console.error('Scan failed:', e);

      if (isAuthExpiredError(e)) {
        handleAuthExpired();
        return;
      }

      clearWorkflowState();
      setAuthError(`Scan failed: ${e.message || 'Unknown error'}. You can try again.`);
      setScreen('account');
    }
  }, [clearWorkflowState, handleAuthExpired, ignoreSmallFiles]);

  const handleNoMovesComplete = useCallback(() => {
    clearWorkflowState();
    setAuthNotice(null);
    setAuthError(null);
    setCompletionNotice('Review complete. No files were marked to move.');
    setScreen('account');
  }, [clearWorkflowState]);

  const handleDecision = useCallback((md5, decision) => {
    setReviewError(null);
    setDecision(md5, decision);
  }, [setDecision]);

  const handleExecute = useCallback(() => {
    const decidedGroups = dupGroups.filter((group) => {
      const decision = decisions[group.md5];
      return decision && decision.action !== 'skip';
    });
    const invalidGroups = decidedGroups.filter((group) => {
      return !validateDiscardDecision(group, decisions[group.md5]).valid;
    });
    if (invalidGroups.length > 0) {
      removeDecisions(invalidGroups.map((group) => group.md5));
      setReviewError(
        invalidGroups.length === 1
          ? 'One duplicate group had an unsafe or stale selection. Review it again before executing.'
          : `${invalidGroups.length} duplicate groups had unsafe or stale selections. Review them again before executing.`
      );
      setScreen('review');
      return;
    }

    const reviewedGroups = dupGroups.filter((group) => decisions[group.md5]);
    const skippedGroups = dupGroups.filter((group) => decisions[group.md5]?.action === 'skip');
    const moveCount = decidedGroups.reduce((count, group) => {
      return count + countMovableFiles(group, decisions[group.md5]);
    }, 0);

    if (moveCount === 0) {
      handleNoMovesComplete();
      return;
    }

    trackEvent('review_completed', {
      reviewed_group_count: reviewedGroups.length,
      discard_review_group_count: decidedGroups.length,
      skipped_group_count: skippedGroups.length,
      remaining_group_count: dupGroups.length - reviewedGroups.length,
      move_candidate_count: moveCount,
    });
    setReviewError(null);
    setScreen('execute');
  }, [decisions, dupGroups, handleNoMovesComplete, removeDecisions]);

  const handleRequestWriteAccess = useCallback(async () => {
    await requestWriteAccess();
    setCanWrite(hasWriteAccess());
  }, []);

  const handleEnsureWriteAccess = useCallback(async () => {
    await ensureWriteAccess();
    setCanWrite(hasWriteAccess());
  }, []);

  const handleExecuteComplete = useCallback(async (moveResults, details = {}) => {
    const successCount = moveResults.filter((result) => result.ok && !result.skipped).length;
    const failedCount = moveResults.filter((result) => !result.ok).length;
    const fileLabel = successCount === 1 ? 'file' : 'files';
    const failureCopy = failedCount > 0
      ? ` ${failedCount} ${failedCount === 1 ? 'file' : 'files'} could not be moved.`
      : '';

    signOut();
    await purgeAppBrowserData();
    setIgnoreSmallFiles(getSettings().ignoreSmallFiles ?? true);
    clearWorkflowState();
    setUser(null);
    setCanWrite(false);
    setAuthNotice(null);
    const destinationCopy = details.destinationNotice ? ` ${details.destinationNotice}` : '';
    setCompletionNotice(
      `${successCount} ${fileLabel} deduped.${failureCopy} App auth and local data were purged.${destinationCopy}`
    );
    setAuthError(null);
    setScreen('account');
  }, [clearWorkflowState]);

  useEffect(() => {
    if (searchParams.get('start') !== 'signin') return;
    if (user || screen !== 'account') return;

    router.replace(pathname);
    setAuthError(null);
    setAuthNotice('You are now on the secure app. Click Sign in with Google to continue.');
  }, [pathname, router, screen, searchParams, user]);

  return (
    <div className="app">
      <Script
        src="https://accounts.google.com/gsi/client"
        onLoad={handleGsiLoad}
        onError={handleGsiError}
        strategy="afterInteractive"
      />
      <Header screen={screen} user={user} />
      <main className={`main${screen === 'review' ? ' main-review' : ''}`}>
        {screen === 'account' && (
          <AccountScreen
            error={authInitError || authError}
            notice={authNotice}
            completionNotice={completionNotice}
            user={user}
            signInStatus={authInitStatus}
            ignoreSmallFiles={ignoreSmallFiles}
            onIgnoreSmallFilesChange={handleIgnoreSmallFilesChange}
            blacklistedPrefixes={blacklistedPrefixes}
            onSignIn={handleSignIn}
            onSignOut={handleSignOut}
            onStartScan={handleStartScan}
            onAddBlacklistedPrefix={handleAddBlacklistedPrefix}
            onRemoveBlacklistedPrefix={handleRemoveBlacklistedPrefix}
          />
        )}
        {screen === 'scan' && (
          <ScanScreen
            scanning={scanning}
            progress={scanProgress}
            stats={stats}
            error={scanError}
          />
        )}
        {screen === 'review' && (
          <ReviewScreen
            dupGroups={dupGroups}
            decisions={decisions}
            onDecision={handleDecision}
            onExecute={handleExecute}
            onNoMovesComplete={handleNoMovesComplete}
            onAuthExpired={handleAuthExpired}
            workflowError={reviewError}
          />
        )}
        {screen === 'execute' && (
          <ExecuteScreen
            canWrite={canWrite}
            decisions={decisions}
            dupGroups={dupGroups}
            onRequestWriteAccess={handleRequestWriteAccess}
            onEnsureWriteAccess={handleEnsureWriteAccess}
            onAuthExpired={handleAuthExpired}
            onComplete={handleExecuteComplete}
          />
        )}
      </main>
      <Footer />
    </div>
  );
}
