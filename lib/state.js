const DB_NAME = 'dedrive';
const DB_VERSION = 1;
const STORE_NAME = 'scans';

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbSet(key, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbDelete(key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// localStorage helpers
export function getSetting(key, fallback = null) {
  try {
    const v = localStorage.getItem(`dedrive_${key}`);
    return v !== null ? JSON.parse(v) : fallback;
  } catch {
    return fallback;
  }
}

export function setSetting(key, value) {
  localStorage.setItem(`dedrive_${key}`, JSON.stringify(value));
}

export function removeSetting(key) {
  localStorage.removeItem(`dedrive_${key}`);
}

// Settings
const DEFAULT_SETTINGS = {
  dupesFolder: '_dupes',
  excludePaths: [],
  maxPreviewMb: 10,
  batchSize: 10,
};

export function getSettings() {
  return { ...DEFAULT_SETTINGS, ...getSetting('settings', {}) };
}

export function saveSettings(partial) {
  const current = getSettings();
  setSetting('settings', { ...current, ...partial });
}

// Decisions: { [md5]: { keep: fileId, action: 'keep'|'skip' } }
export function getDecisions() {
  return getSetting('decisions', {});
}

export function setDecision(md5, decision) {
  const all = getDecisions();
  all[md5] = decision;
  setSetting('decisions', all);
}

export function clearDecisions() {
  removeSetting('decisions');
}

// Scan results (IndexedDB for large data)
export async function saveScanResults(data) {
  await idbSet('lastScan', data);
}

export async function loadScanResults() {
  return idbGet('lastScan');
}

export async function clearScanResults() {
  await idbDelete('lastScan');
}

// Export/Import decisions
export function exportDecisions() {
  const decisions = getDecisions();
  const blob = new Blob([JSON.stringify(decisions, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `dedrive-decisions-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function importDecisions(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result);
        setSetting('decisions', data);
        resolve(data);
      } catch (e) {
        reject(new Error('Invalid JSON file'));
      }
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}
