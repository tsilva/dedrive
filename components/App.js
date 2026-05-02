'use client';

import { useState, useCallback, useEffect } from 'react';
import dynamic from 'next/dynamic';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import Script from 'next/script';
import Header from './Header';
import Footer from './Footer';
import AccountScreen from './screens/AccountScreen';
import { useDecisions } from '@/hooks/useDecisions';
import { useScanResults } from '@/hooks/useScanResults';
import {
  hasWriteAccess,
  initAuth,
  releaseWriteAccess,
  requestReadAccess,
  requestWriteAccess,
  setAuthCallback,
  signOut,
} from '@/lib/auth';
import { clearFolderCache, getUserInfo, fetchAllFiles } from '@/lib/drive';
import { excludeDedupeFolderFiles, findDuplicates, resolvePaths, computeStats } from '@/lib/dedup';
import { clearPreviewCache } from '@/lib/preview';
import { getSettings, purgeAppBrowserData } from '@/lib/state';
import { trackEvent, trackException } from '@/lib/analytics';

const CLIENT_ID = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
const ScanScreen = dynamic(() => import('./screens/ScanScreen'));
const ReviewScreen = dynamic(() => import('./screens/ReviewScreen'));
const ExecuteScreen = dynamic(() => import('./screens/ExecuteScreen'));

export default function App() {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [screen, setScreen] = useState('account');
  const [gsiLoaded, setGsiLoaded] = useState(false);
  const [user, setUser] = useState(null);
  const [authNotice, setAuthNotice] = useState(null);
  const [authError, setAuthError] = useState(null);
  const [canWrite, setCanWrite] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState({ page: 0, fileCount: 0 });
  const [scanError, setScanError] = useState(null);
  const { decisions, setDecision, clearDecisions } = useDecisions();
  const { dupGroups, save, clear: clearScanResults } = useScanResults();

  const stats = dupGroups.length > 0 ? computeStats(dupGroups) : null;

  const clearWorkflowState = useCallback(() => {
    clearPreviewCache();
    clearFolderCache();
    clearDecisions();
    clearScanResults();
    setScanning(false);
    setScanProgress({ page: 0, fileCount: 0 });
    setScanError(null);
  }, [clearDecisions, clearScanResults]);

  // Auth callback
  useEffect(() => {
    setAuthCallback(() => {
      clearWorkflowState();
      setUser(null);
      setCanWrite(false);
      setAuthNotice(null);
      setAuthError('Your Google session expired. Sign in again.');
      setScreen('account');
    });
    return () => setAuthCallback(null);
  }, [clearWorkflowState]);

  // Auto-init auth when GSI loads
  useEffect(() => {
    if (gsiLoaded && CLIENT_ID) {
      try {
        initAuth(CLIENT_ID);
      } catch (e) {
        console.error('Auth init failed:', e);
      }
    }
  }, [gsiLoaded]);

  const handleGsiLoad = useCallback(() => {
    setGsiLoaded(true);
  }, []);

  const handleSignIn = useCallback(async () => {
    trackEvent('sign_in_started');
    setAuthNotice(null);
    setAuthError(null);

    try {
      await requestReadAccess();
      const nextUser = await getUserInfo();
      clearWorkflowState();
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
  }, [clearWorkflowState]);

  const handleSignOut = useCallback(() => {
    trackEvent('sign_out');
    signOut();
    clearWorkflowState();
    setUser(null);
    setCanWrite(false);
    setAuthNotice(null);
    setAuthError(null);
    setScreen('account');
  }, [clearWorkflowState]);

  const handleStartScan = useCallback(async () => {
    trackEvent('scan_started');
    clearWorkflowState();
    setAuthNotice(null);
    setAuthError(null);
    setScreen('scan');
    setScanning(true);
    setScanProgress({ page: 0, fileCount: 0 });

    try {
      const allFiles = await fetchAllFiles(({ page, fileCount }) => {
        setScanProgress({ page, fileCount });
      });

      const settings = getSettings();
      const scannedFiles = excludeDedupeFolderFiles(resolvePaths(allFiles), settings.dupesFolder);
      const groups = findDuplicates(scannedFiles);
      const scanStats = computeStats(groups);
      save(scannedFiles, groups);
      trackEvent('scan_completed', {
        file_count: scannedFiles.length,
        duplicate_group_count: scanStats.totalGroups,
        duplicate_file_count: scanStats.totalFiles,
        uncertain_group_count: scanStats.uncertainCount,
        potential_savings_bytes: scanStats.totalWasted,
      });
      setScanning(false);
      if (groups.length > 0) {
        setScreen('review');
      }
    } catch (e) {
      setScanError(e.message);
      setScanning(false);
      trackException('scan_failed');
      trackEvent('scan_failed', {
        error_type: e.message?.split(':')[0] || 'unknown',
      });
      console.error('Scan failed:', e);
    }
  }, [clearWorkflowState, save]);

  const handleExecute = useCallback(() => {
    const decidedGroups = dupGroups.filter((group) => decisions[group.md5]?.action === 'keep');
    const moveCount = decidedGroups.reduce((count, group) => {
      const keepId = decisions[group.md5]?.keep;
      return count + group.files.filter((file) => file.id !== keepId).length;
    }, 0);

    trackEvent('review_completed', {
      reviewed_group_count: decidedGroups.length,
      remaining_group_count: dupGroups.length - decidedGroups.length,
      move_candidate_count: moveCount,
    });
    setScreen('execute');
  }, [decisions, dupGroups]);

  const handleRequestWriteAccess = useCallback(async () => {
    await requestWriteAccess();
    setCanWrite(hasWriteAccess());
  }, []);

  const handleReleaseWriteAccess = useCallback(() => {
    const released = releaseWriteAccess();
    if (!released) return;

    setCanWrite(false);
    setUser(null);
    setAuthNotice('Write access was cleared. Sign in again to run another scan.');
  }, []);

  const handlePurgeAuthData = useCallback(async () => {
    signOut();
    clearWorkflowState();
    await purgeAppBrowserData();
    setUser(null);
    setCanWrite(false);
    setAuthNotice('App auth data was purged from this browser.');
    setAuthError(null);
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
        strategy="afterInteractive"
      />
      <Header screen={screen} user={user} />
      <main className="main">
        {screen === 'account' && (
          <AccountScreen
            error={authError}
            notice={authNotice}
            user={user}
            onSignIn={handleSignIn}
            onSignOut={handleSignOut}
            onStartScan={handleStartScan}
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
            onDecision={setDecision}
            onExecute={handleExecute}
          />
        )}
        {screen === 'execute' && (
          <ExecuteScreen
            canWrite={canWrite}
            decisions={decisions}
            dupGroups={dupGroups}
            onRequestWriteAccess={handleRequestWriteAccess}
            onReleaseWriteAccess={handleReleaseWriteAccess}
            onPurgeAuthData={handlePurgeAuthData}
          />
        )}
      </main>
      <Footer />
    </div>
  );
}
