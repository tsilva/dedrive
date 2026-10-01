'use client';

import { useState } from 'react';
import { normalizePathPrefix } from '@/lib/dedup';

export default function AccountScreen({
  error,
  completionNotice,
  user,
  onSignIn,
  onSignOut,
  onStartScan,
  ignoreSmallFiles = true,
  onIgnoreSmallFilesChange,
  blacklistedPrefixes = [],
  onAddBlacklistedPrefix,
  onRemoveBlacklistedPrefix,
  signInStatus = 'ready',
}) {
  const [prefixDraft, setPrefixDraft] = useState('');
  const [prefixError, setPrefixError] = useState(null);
  const handleAddPrefix = (event) => {
    event.preventDefault();
    const normalized = normalizePathPrefix(prefixDraft);

    if (!normalized) {
      setPrefixError('Enter a folder path such as /Archive/2020.');
      return;
    }
    if (blacklistedPrefixes.includes(normalized)) {
      setPrefixError('That path prefix is already excluded.');
      return;
    }

    onAddBlacklistedPrefix?.(normalized);
    setPrefixDraft('');
    setPrefixError(null);
  };

  const signInDisabled = signInStatus !== 'ready';
  const resolvedSignInLabel = signInStatus === 'loading'
    ? 'Loading Google sign-in...'
    : signInStatus === 'error'
      ? 'Google sign-in unavailable'
      : 'Sign in with Google';

  return (
    <div className="screen">
      <div className="account-container">
        <div className="account-header">
          <h1 className="account-heading">{user ? 'Set up your scan' : 'Connect Google Drive'}</h1>
          <p className="account-subtitle">
            {user ? 'Choose your settings, then scan for exact duplicates.' : 'Sign in to find duplicates in your files.'}
          </p>
        </div>

        {completionNotice && <div className="account-notice account-notice-success">{completionNotice}</div>}
        {error && <div className="account-notice account-notice-error">{error}</div>}

        {user && (
          <div className="user-card">
            {user.photoLink && (
              <img src={user.photoLink} className="user-avatar-large" alt="" />
            )}
            <div className="user-info-stack">
              <div className="user-name">{user.displayName}</div>
              <div className="user-email">{user.emailAddress}</div>
            </div>
          </div>
        )}

        {user && (
          <div className="path-filters">
            <label className="small-files-setting">
              <input
                type="checkbox"
                checked={ignoreSmallFiles}
                onChange={(event) => onIgnoreSmallFilesChange?.(event.target.checked)}
                aria-describedby="small-files-help"
              />
              Ignore files smaller than 1 KB
            </label>
            <p id="small-files-help" className="account-helper path-filters-desc">
              Skip files under 1,024 bytes when finding duplicates.
            </p>
          </div>
        )}

        {user && (
          <div className="path-filters">
            <div className="path-filters-title">Skip scanning these paths</div>
            <p className="account-helper path-filters-desc">
              Files whose Drive path starts with an excluded prefix are left out of scans.
              Matching ignores case and covers child folders automatically.
            </p>
            {blacklistedPrefixes.length > 0 && (
              <ul className="prefix-list">
                {blacklistedPrefixes.map((prefix) => (
                  <li key={prefix} className="prefix-chip">
                    <code>{prefix}</code>
                    <button
                      type="button"
                      className="prefix-remove"
                      aria-label={`Remove excluded path ${prefix}`}
                      onClick={() => onRemoveBlacklistedPrefix?.(prefix)}
                    >
                      ×
                    </button>
                  </li>
                ))}
              </ul>
            )}
            <form className="prefix-form" onSubmit={handleAddPrefix}>
              <input
                className="input"
                type="text"
                value={prefixDraft}
                onChange={(event) => {
                  setPrefixDraft(event.target.value);
                  setPrefixError(null);
                }}
                placeholder="/Archive/2020"
                aria-label="Path prefix to exclude from scans"
              />
              <button className="btn" type="submit">Add</button>
            </form>
            {prefixError && <div className="prefix-error" role="alert">{prefixError}</div>}
          </div>
        )}

        <div className="account-actions">
          {!user && (
            <>
              <button className="btn-google" onClick={onSignIn} disabled={signInDisabled} aria-busy={signInStatus === 'loading'}>
                <img src="/icons/google.svg" width="18" height="18" alt="" aria-hidden="true" />
                {resolvedSignInLabel}
              </button>
              <p className="account-helper">Read-only access. Nothing changes during a scan.</p>
            </>
          )}
          {user && (
            <div className="signed-in-actions">
              <button className="btn btn-primary btn-large" onClick={onStartScan}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 16, height: 16 }}>
                  <circle cx="11" cy="11" r="8"/>
                  <path d="M21 21l-4.35-4.35"/>
                </svg>
                Start Scan
              </button>
              <button className="btn btn-text" onClick={onSignOut}>Sign Out</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
