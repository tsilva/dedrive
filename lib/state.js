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
