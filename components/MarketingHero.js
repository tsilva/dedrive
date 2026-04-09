import Link from 'next/link';

export default function MarketingHero() {
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

        <div className="account-features">
          <div className="feature-item">
            <div className="feature-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
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
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
              </svg>
            </div>
            <div className="feature-text">
              <strong>Preview &amp; Compare</strong>
              <span>Review duplicates side-by-side before deciding</span>
            </div>
          </div>
          <div className="feature-item">
            <div className="feature-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
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

        <div className="account-actions">
          <Link
            href="/app?start=signin"
            prefetch={false}
            className="btn btn-start btn-large"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 16, height: 16 }} aria-hidden="true">
              <path d="M5 12h14" />
              <path d="m12 5 7 7-7 7" />
            </svg>
            <span aria-hidden="true">Start</span>
            <span className="sr-only"> the secure Google Drive duplicate scan flow</span>
          </Link>
          <p className="account-helper">
            You will be redirected to the secure app page, where you can sign in with Google.
          </p>
        </div>
      </div>
    </div>
  );
}
