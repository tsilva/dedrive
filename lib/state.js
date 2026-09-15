const STORAGE_PREFIX = 'dedrive_';
const DB_NAME = 'dedrive';

// localStorage helpers
function getSetting(key, fallback = null) {
  try {
    const v = localStorage.getItem(`${STORAGE_PREFIX}${key}`);
    return v !== null ? JSON.parse(v) : fallback;
  } catch {
    return fallback;
  }
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
  maxPreviewMb: 10,
  batchSize: 10,
  blacklistedPathPrefixes: [],
  ignoreSmallFiles: true,
};

export function getSettings() {
  const settings = { ...DEFAULT_SETTINGS, ...getSetting('settings', {}) };

  if (!Array.isArray(settings.blacklistedPathPrefixes)) {
    settings.blacklistedPathPrefixes = [];
  }

  return settings;
}

export function saveSettings(partial) {
  const next = { ...getSettings(), ...partial };

  try {
    localStorage.setItem(`${STORAGE_PREFIX}settings`, JSON.stringify(next));
  } catch {
    // Storage can be unavailable in private or restricted browser contexts.
  }

  return next;
}
