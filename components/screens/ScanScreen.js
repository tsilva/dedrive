'use client';

import { formatSize } from '@/lib/utils';

export default function ScanScreen({ scanning, progress, stats, error }) {
  return (
    <div className="screen">
      <div className="setup-title" style={{ marginBottom: 24 }}>Scan</div>
      <div className="progress-container">
        <div
          className={`progress-bar${scanning ? ' indeterminate' : ''}`}
          style={{ width: scanning || stats ? '100%' : '0%' }}
        />
      </div>
      <div className="progress-label">
        {scanning
          ? `Scanning... Page ${progress.page} • ${progress.fileCount.toLocaleString()} files`
          : stats
            ? `Scan complete • ${stats.totalGroups.toLocaleString()} duplicates found`
            : 'Ready to scan'}
      </div>

      {error && (
        <div className="account-notice account-notice-error" style={{ marginTop: 16 }}>
          {error}
        </div>
      )}

      {stats && (
        <div className="stats-grid">
          <div className="stat">
            <div className="stat-value">{stats.totalGroups.toLocaleString()}</div>
            <div className="stat-label">Duplicate groups</div>
          </div>
          <div className="stat">
            <div className="stat-value">{stats.totalFiles.toLocaleString()}</div>
            <div className="stat-label">Duplicate files</div>
          </div>
          <div className="stat">
            <div className="stat-value">{formatSize(stats.totalWasted)}</div>
            <div className="stat-label">Potential savings</div>
          </div>
          {stats.uncertainCount > 0 && (
            <div className="stat stat-warning">
              <div className="stat-value">{stats.uncertainCount}</div>
              <div className="stat-label">Uncertain (size mismatch)</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
