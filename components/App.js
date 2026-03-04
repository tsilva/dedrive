'use client';

import { useState, useCallback, useEffect } from 'react';
import Script from 'next/script';
import Header from './Header';
import AccountScreen from './screens/AccountScreen';
import ScanScreen from './screens/ScanScreen';
import ReviewScreen from './screens/ReviewScreen';
import ExecuteScreen from './screens/ExecuteScreen';
import { useDecisions } from '@/hooks/useDecisions';
import { useScanResults } from '@/hooks/useScanResults';
import { initAuth, signIn, signOut, setAuthCallback } from '@/lib/auth';
import { getUserInfo, fetchAllFiles } from '@/lib/drive';
import { findDuplicates, resolvePaths, computeStats } from '@/lib/dedup';
import { clearPreviewCache } from '@/lib/preview';

const CLIENT_ID = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;

export default function App() {
  const [screen, setScreen] = useState('account');
  const [gsiLoaded, setGsiLoaded] = useState(false);
  const [user, setUser] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState({ page: 0, fileCount: 0 });
  const [scanError, setScanError] = useState(null);
  const [decisions, setDecision, reloadDecisions] = useDecisions();
  const { dupGroups, loaded, save } = useScanResults();

  const stats = dupGroups.length > 0 ? computeStats(dupGroups) : null;

  // Auth callback
  useEffect(() => {
    setAuthCallback(async (signedIn) => {
      if (signedIn) {
        try {
          const u = await getUserInfo();
          setUser(u);
          setScreen('account');
        } catch (e) {
          console.error('Failed to get user info:', e);
        }
      } else {
        setUser(null);
        setScreen('account');
      }
    });
  }, []);

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

  const handleSignIn = useCallback(() => {
    signIn();
  }, []);

  const handleSignOut = useCallback(() => {
    signOut();
    clearPreviewCache();
    setUser(null);
    setScreen('account');
  }, []);

  const handleStartScan = useCallback(async () => {
    setScreen('scan');
    setScanning(true);
    setScanError(null);
    setScanProgress({ page: 0, fileCount: 0 });

    try {
      const allFiles = await fetchAllFiles(({ page, fileCount }) => {
        setScanProgress({ page, fileCount });
      });

      resolvePaths(allFiles);
      const groups = findDuplicates(allFiles);
      await save(allFiles, groups);
      setScanning(false);
    } catch (e) {
      setScanError(e.message);
      setScanning(false);
      console.error('Scan failed:', e);
    }
  }, [save]);

  const handleReview = useCallback(() => {
    if (dupGroups.length > 0) setScreen('review');
  }, [dupGroups]);

  const handleExecute = useCallback(() => {
    setScreen('execute');
  }, []);

  return (
    <div className="app">
      <Script
        src="https://accounts.google.com/gsi/client"
        onLoad={handleGsiLoad}
        strategy="afterInteractive"
      />
      <Header screen={screen} onNavigate={setScreen} />
      <div className="main">
        {screen === 'account' && (
          <AccountScreen
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
            onReview={handleReview}
          />
        )}
        {screen === 'review' && (
          <ReviewScreen
            dupGroups={dupGroups}
            decisions={decisions}
            onDecision={setDecision}
            onExecute={handleExecute}
            onDecisionsImported={reloadDecisions}
          />
        )}
        {screen === 'execute' && (
          <ExecuteScreen dupGroups={dupGroups} decisions={decisions} />
        )}
      </div>
    </div>
  );
}
