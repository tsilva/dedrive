'use client';

const SCREENS = [
  { id: 'account', label: 'Account' },
  { id: 'scan', label: 'Scan' },
  { id: 'review', label: 'Review' },
  { id: 'execute', label: 'Execute' },
];

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
      <div className="logo">DEDRIVE</div>
      <nav className="nav">
        {SCREENS.map((s) => {
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
      {user && (
        <div className="user-info">
          {user.photoLink && (
            <img src={user.photoLink} alt="" className="user-avatar" />
          )}
          <span className="user-email">{user.emailAddress}</span>
        </div>
      )}
    </header>
  );
}
