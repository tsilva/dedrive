'use client';

import { SCREEN_STEPS } from './screen-steps';

export default function Header({ screen, user }) {
  const getScreenStatus = (id) => {
    const order = ['account', 'scan', 'review', 'execute'];
    const currentIdx = order.indexOf(screen);
    const screenIdx = order.indexOf(id);
    if (screenIdx < currentIdx) return 'completed';
    if (screenIdx === currentIdx) return 'active';
    return 'disabled';
  };

  return (
    <header className="header">
      <div className="logo">dedrive</div>
      <nav className="nav" aria-label="Workflow steps">
        {SCREEN_STEPS.map((s) => {
          const status = getScreenStatus(s.id);
          return (
            <div
              key={s.id}
              className={`nav-item nav-item-${status}${status === 'active' ? ' active' : ''}`}
            >
              {status === 'completed' ? '✓ ' : ''}{s.label}
            </div>
          );
        })}
      </nav>
      <div className="header-actions">
        {user ? (
          <div className="user-info">
            {user.photoLink && (
              <img src={user.photoLink} alt="" className="user-avatar" />
            )}
            <span className="user-email">{user.emailAddress}</span>
          </div>
        ) : (
          <a
            href="https://github.com/tsilva/dedrive"
            target="_blank"
            rel="noopener noreferrer"
            className="github-link"
            aria-label="View source on GitHub"
          >
            <svg viewBox="0 0 24 24" className="github-icon" aria-hidden="true">
              <path fill="currentColor" d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
            </svg>
          </a>
        )}
      </div>
    </header>
  );
}
