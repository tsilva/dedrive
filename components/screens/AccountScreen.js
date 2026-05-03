'use client';

import Link from 'next/link';

export default function AccountScreen({
  error,
  notice,
  completionNotice,
  user,
  onSignIn,
  onSignOut,
  onStartScan,
  signInHref = null,
  signInLabel = 'Sign in with Google',
  signInHelper = null,
  signInVariant = 'google',
}) {
  const isGoogleSignIn = signInVariant === 'google';
  const signInClassName = isGoogleSignIn ? 'btn-google' : 'btn btn-start btn-large';
  const signInContent = (
    <>
      {isGoogleSignIn ? (
        <svg className="google-logo" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
          <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
          <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
          <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
        </svg>
      ) : (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 16, height: 16 }}>
          <path d="M5 12h14" />
          <path d="m12 5 7 7-7 7" />
        </svg>
      )}
      {signInLabel}
    </>
  );

  const signInAction = signInHref ? (
    <Link href={signInHref} className={signInClassName}>
      {signInContent}
    </Link>
  ) : (
    <button className={signInClassName} onClick={onSignIn}>
      {signInContent}
    </button>
  );

  return (
    <div className="screen">
      <div className="account-container">
        <div className="account-header">
          <div className="account-logo">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <h1 className="account-title">dedrive</h1>
          <p className="account-subtitle">
            Review duplicates with read-only Drive access first. Scans exclude Shared with me items, and write access is requested only when you move files.
          </p>
        </div>

        {!user && (
          <div className="account-features">
            <div className="feature-item">
              <div className="feature-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="11" cy="11" r="8"/>
                  <path d="M21 21l-4.35-4.35"/>
                </svg>
              </div>
              <div className="feature-text">
                <strong>Smart Scan</strong>
                <span>Analyzes file checksums to find true duplicates</span>
              </div>
            </div>
            <div className="feature-item">
              <div className="feature-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                  <polyline points="14 2 14 8 20 8"/>
                </svg>
              </div>
              <div className="feature-text">
                <strong>Preview & Compare</strong>
                <span>Review duplicates side-by-side before deciding</span>
              </div>
            </div>
            <div className="feature-item">
              <div className="feature-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M3 6h18"/>
                  <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6"/>
                  <path d="M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                </svg>
              </div>
              <div className="feature-text">
                <strong>Safe Cleanup</strong>
                <span>Requests write access only for the final move into <code>_dupes/</code> and never deletes</span>
              </div>
            </div>
          </div>
        )}

        {completionNotice && <div className="account-notice account-notice-success">{completionNotice}</div>}
        {notice && <div className="account-notice account-notice-info">{notice}</div>}
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

        <div className="account-actions">
          {!user && (
            <>
              {signInAction}
              {signInHelper && <p className="account-helper">{signInHelper}</p>}
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
