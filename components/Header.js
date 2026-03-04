'use client';

const SCREENS = [
  { id: 'account', label: 'Account' },
  { id: 'scan', label: 'Scan' },
  { id: 'review', label: 'Review' },
  { id: 'execute', label: 'Execute' },
];

export default function Header({ screen, onNavigate }) {
  return (
    <header className="header">
      <div className="logo">DEDRIVE</div>
      <nav className="nav">
        {SCREENS.map((s) => (
          <div
            key={s.id}
            className={`nav-item${screen === s.id ? ' active' : ''}`}
            onClick={() => onNavigate(s.id)}
          >
            {s.label}
          </div>
        ))}
      </nav>
    </header>
  );
}
