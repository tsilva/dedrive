const STORAGE_PREFIX = 'dedrive_';
const DB_NAME = 'dedrive';

// localStorage helpers
export function getSetting(key, fallback = null) {
  try {
    const v = localStorage.getItem(`${STORAGE_PREFIX}${key}`);
    return v !== null ? JSON.parse(v) : fallback;
  } catch {
    return fallback;
  }
}

export function setSetting(key, value) {
  localStorage.setItem(`${STORAGE_PREFIX}${key}`, JSON.stringify(value));
}

export function removeSetting(key) {
  localStorage.removeItem(`${STORAGE_PREFIX}${key}`);
}

function clearPrefixedStorage(storage) {
  if (!storage) return;

  for (let i = storage.length - 1; i >= 0; i--) {
    const key = storage.key(i);
    if (key?.startsWith(STORAGE_PREFIX)) {
      storage.removeItem(key);
    }
  }
}

export function purgeAppBrowserData() {
  try {
    clearPrefixedStorage(localStorage);
    clearPrefixedStorage(sessionStorage);
  } catch {
    // Storage can be unavailable in private or restricted browser contexts.
  }

  if (!globalThis.indexedDB?.deleteDatabase) {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    const request = indexedDB.deleteDatabase(DB_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
    request.onblocked = () => resolve();
  });
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
