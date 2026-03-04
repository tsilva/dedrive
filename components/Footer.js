'use client';

export default function Footer() {
  const hash = process.env.NEXT_PUBLIC_GIT_HASH;
  const date = process.env.NEXT_PUBLIC_GIT_DATE;

  return (
    <footer className="footer">
      <span className="footer-version mono">
        {hash && <span className="footer-hash">release {hash.slice(0, 7)}</span>}
        {date && <span className="footer-date">· {date}</span>}
      </span>
    </footer>
  );
}
