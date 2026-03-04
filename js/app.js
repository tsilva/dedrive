import { initAuth, signIn, signOut, setAuthCallback } from './auth.js';
import { getUserInfo, fetchAllFiles, moveFile, ensureFolderPath } from './drive.js';
import { findDuplicates, resolvePaths, computeStats } from './dedup.js';
import {
  getSettings, saveSettings, getDecisions, setDecision,
  saveScanResults, loadScanResults, exportDecisions, importDecisions,
} from './state.js';
import {
  showScreen, renderSetup, renderLogin, renderScanProgress, renderScanResults,
  initReview, setupReviewNav, renderDryRun, renderExecuteProgress, renderExecuteResults,
} from './ui.js';
import { pooledMap } from './utils.js';

let allFiles = [];
let dupGroups = [];

async function init() {
  const settings = getSettings();

  // Setup screen
  renderSetup(settings.clientId, async (clientId) => {
    saveSettings({ clientId });
    await initAuth(clientId);
    showScreen('login');
  });

  // Auth callback
  setAuthCallback(async (signedIn) => {
    if (signedIn) {
      try {
        const user = await getUserInfo();
        renderLogin(user);
        showScreen('login');
      } catch (e) {
        console.error('Failed to get user info:', e);
      }
    } else {
      renderLogin(null);
      showScreen('setup');
    }
  });

  // Navigation
  for (const el of document.querySelectorAll('.nav-item')) {
    el.addEventListener('click', () => {
      const screen = el.dataset.screen;
      if (screen) showScreen(screen);
    });
  }

  // Sign in/out
  document.getElementById('sign-in-btn')?.addEventListener('click', signIn);
  document.getElementById('sign-out-btn')?.addEventListener('click', () => {
    signOut();
    renderLogin(null);
    showScreen('setup');
  });

  // Start scan
  document.getElementById('start-scan-btn')?.addEventListener('click', startScan);

  // Review button
  document.getElementById('review-btn')?.addEventListener('click', () => {
    if (dupGroups.length > 0) {
      startReview();
      showScreen('review');
    }
  });

  // Review navigation
  setupReviewNav();

  // Execute
  document.getElementById('go-execute-btn')?.addEventListener('click', () => {
    showScreen('execute');
    renderDryRun(dupGroups, getDecisions());
  });
  document.getElementById('execute-btn')?.addEventListener('click', executeMove);

  // Export/import
  document.getElementById('export-btn')?.addEventListener('click', exportDecisions);
  document.getElementById('import-btn')?.addEventListener('click', () => {
    document.getElementById('import-file')?.click();
  });
  document.getElementById('import-file')?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (file) {
      await importDecisions(file);
      if (dupGroups.length > 0) startReview();
    }
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    const activeScreen = document.querySelector('.screen.active');
    if (!activeScreen || activeScreen.id !== 'screen-review') return;
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

    if (e.key === 'ArrowLeft' || e.key === 'h') {
      document.getElementById('prev-group')?.click();
    } else if (e.key === 'ArrowRight' || e.key === 'l') {
      document.getElementById('next-group')?.click();
    } else if (e.key === '1') {
      const btn = document.querySelector('.file-card[data-index="0"] .btn-keep');
      btn?.click();
    } else if (e.key === '2') {
      const btn = document.querySelector('.file-card[data-index="1"] .btn-keep');
      btn?.click();
    } else if (e.key === 's') {
      document.getElementById('skip-group')?.click();
    }
  });

  // Try to restore previous scan
  const saved = await loadScanResults();
  if (saved) {
    allFiles = saved.files || [];
    dupGroups = saved.groups || [];
    if (dupGroups.length > 0) {
      const stats = computeStats(dupGroups);
      renderScanResults(stats);
    }
  }

  // Auto-init auth if client ID exists
  if (settings.clientId) {
    await initAuth(settings.clientId);
    showScreen('login');
  } else {
    showScreen('setup');
  }
}

async function startScan() {
  showScreen('scan');
  document.getElementById('scan-results').style.display = 'none';
  document.getElementById('review-btn').style.display = 'none';

  try {
    allFiles = await fetchAllFiles(({ page, fileCount }) => {
      renderScanProgress(page, fileCount);
    });

    resolvePaths(allFiles);
    dupGroups = findDuplicates(allFiles);
    const stats = computeStats(dupGroups);
    renderScanResults(stats);

    await saveScanResults({ files: allFiles, groups: dupGroups });
  } catch (e) {
    document.getElementById('scan-progress-label').textContent = `Error: ${e.message}`;
    console.error('Scan failed:', e);
  }
}

function startReview() {
  const decisions = getDecisions();
  initReview(dupGroups, decisions, (md5, decision) => {
    setDecision(md5, decision);
  });
}

async function executeMove() {
  const decisions = getDecisions();
  const moves = [];

  for (const g of dupGroups) {
    const d = decisions[g.md5];
    if (!d || d.action !== 'keep') continue;
    for (const f of g.files) {
      if (f.id !== d.keep) {
        moves.push(f);
      }
    }
  }

  if (moves.length === 0) return;

  const checkbox = document.getElementById('execute-confirm');
  if (!checkbox?.checked) {
    checkbox?.focus();
    return;
  }

  document.getElementById('execute-btn').disabled = true;
  const settings = getSettings();
  let completed = 0;

  const results = await pooledMap(
    moves,
    async (file) => {
      try {
        // Build destination path: _dupes/original/path/structure
        const pathParts = (file.path || '/' + file.name).split('/').filter(Boolean);
        pathParts.pop(); // remove filename
        const destParts = [settings.dupesFolder, ...pathParts];
        const destFolderId = await ensureFolderPath(destParts);
        await moveFile(file.id, file.parents || [], destFolderId);
        completed++;
        renderExecuteProgress(completed, moves.length);
        return { ok: true, name: file.name };
      } catch (e) {
        completed++;
        renderExecuteProgress(completed, moves.length);
        return { ok: false, name: file.name, error: e.message };
      }
    },
    settings.batchSize
  );

  renderExecuteResults(results);
  document.getElementById('execute-btn').disabled = false;
}

init();
