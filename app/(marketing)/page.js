import Link from 'next/link';
import Footer from '@/components/Footer';

export default function MarketingPage() {
  return (
    <div className="marketing-shell">
      <header className="marketing-header">
        <div className="logo">dedrive</div>
        <div className="marketing-header-actions">
          <a
            href="https://github.com/tsilva/dedrive-web"
            target="_blank"
            rel="noopener noreferrer"
            className="btn"
          >
            GitHub
          </a>
          <Link href="/app" className="btn btn-primary">
            Open Secure App
          </Link>
        </div>
      </header>

      <main className="marketing-main">
        <section className="marketing-hero">
          <div className="marketing-kicker">Private Google Drive cleanup</div>
          <h1 className="marketing-title">
            Scan first with read-only access. Request write access only if you choose to move duplicates.
          </h1>
          <p className="marketing-copy">
            dedrive runs entirely in your browser, groups files by checksum, previews matches side-by-side,
            and only asks for write access at the final move step.
          </p>
          <div className="marketing-actions">
            <Link href="/app" className="btn btn-primary btn-large">
              Launch `/app`
            </Link>
            <a
              href="https://github.com/tsilva/dedrive-web"
              target="_blank"
              rel="noopener noreferrer"
              className="btn"
            >
              Review Source
            </a>
          </div>
        </section>

        <section className="marketing-grid">
          <article className="marketing-card">
            <h2>Read-only by default</h2>
            <p>Scanning, metadata review, previews, and duplicate selection work without Drive write access.</p>
          </article>
          <article className="marketing-card">
            <h2>No durable scan cache</h2>
            <p>Drive inventory and review decisions stay in memory for the active tab instead of persisting after logout.</p>
          </article>
          <article className="marketing-card">
            <h2>Isolated secure route</h2>
            <p>The privileged Drive UI lives at <code>/app</code> without analytics scripts and with stricter browser headers.</p>
          </article>
        </section>

        <section className="marketing-panel">
          <div>
            <h2>How it works</h2>
            <p>1. Open <code>/app</code> and sign in with read-only Drive access.</p>
            <p>2. Scan your owned, non-trashed files and review duplicate groups locally.</p>
            <p>3. Grant write access only when you decide to move the extra copies into <code>_dupes/</code>.</p>
          </div>
          <div>
            <h2>What does not leave the browser</h2>
            <p>File content stays local to your browser session. The app does not upload Drive data to its own backend.</p>
            <p>Optional analytics stay on this public landing page and are not loaded inside the secure app.</p>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
}
