'use client';

import { useRef, useState } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import localFont from 'next/font/local';
import styles from './MarketingHero.module.css';

const inter = localFont({
  src: '../public/fonts/InterVariable.woff2',
  variable: '--marketing-font',
  display: 'swap',
  weight: '100 900',
});

const steps = [
  {
    label: 'Read-only scan',
    title: 'Identical content',
    reassurance: 'Nothing changes during a scan.',
    description: 'Write access is requested only before moving files.',
    icon: 'shield',
  },
  {
    label: 'Choose what stays',
    title: 'Your files. Your choice.',
    reassurance: 'You choose every copy to keep.',
    description: 'Compare previews and source folders before making a decision. You can also skip a group.',
    icon: 'check-circle',
  },
  {
    label: 'Move the extras',
    title: 'A safe place for extras',
    reassurance: 'Moved safely. Never deleted.',
    description: 'Approve write access only when you are ready to move the extra copies into a private _dupes folder.',
    icon: 'folder',
  },
];

function Icon({ name, className = '' }) {
  return <img src={`/icons/feather/${name}.svg`} width="24" height="24" alt="" aria-hidden="true" className={`${styles.icon} ${className}`} />;
}

export default function MarketingHero() {
  const [activeStep, setActiveStep] = useState(0);
  const tabRefs = useRef([]);
  const step = steps[activeStep];

  function handleStepKey(event, index) {
    let next;
    if (event.key === 'ArrowRight') next = (index + 1) % steps.length;
    if (event.key === 'ArrowLeft') next = (index + steps.length - 1) % steps.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = steps.length - 1;
    if (next === undefined) return;
    event.preventDefault();
    setActiveStep(next);
    tabRefs.current[next]?.focus();
  }

  return (
    <div className={`${styles.page} ${inter.variable}`}>
      <a className={styles.skipLink} href="#main-content">Skip to content</a>
      <header className={styles.header}>
        <div className={styles.headerInner}>
          <Link href="/" className={styles.wordmark} aria-label="dedrive home">dedrive</Link>
          <nav className={styles.nav} aria-label="Main navigation">
            <a href="#how-it-works">How it works</a>
            <a href="https://github.com/tsilva/dedrive" target="_blank" rel="noopener noreferrer" className={styles.github} aria-label="View source on GitHub">
              <Icon name="github" /><span>GitHub</span>
            </a>
          </nav>
        </div>
      </header>
      <main id="main-content">
        <section className={styles.hero} aria-labelledby="hero-title">
          <div className={styles.heroInner}>
            <h1 id="hero-title" className={styles.title}>Keep the file.<br /><span>Lose the duplicates.</span></h1>
            <div className={styles.intro}>
              <p>Find exact duplicates in your Google Drive. Decide what stays. Move the extras safely.</p>
              <Link href="/app?start=signin" prefetch={false} className={styles.cta}>
                Find duplicates <Icon name="arrow-right" />
              </Link>
              <p className={styles.helper}>
                <img src="/icons/google.svg" width="24" height="24" alt="" aria-hidden="true" />
                Sign in with Google on the next screen.
              </p>
            </div>
          </div>
        </section>
        <section id="how-it-works" className={styles.workflow} aria-labelledby="workflow-title">
          <h2 id="workflow-title">Three steps. Every decision is yours.</h2>
          <div className={styles.steps} role="tablist" aria-label="How dedrive works">
            {steps.map((item, index) => (
              <button key={item.label} ref={(element) => { tabRefs.current[index] = element; }}
                id={`step-${index}`} role="tab" type="button" aria-selected={activeStep === index}
                aria-controls="example-preview" tabIndex={activeStep === index ? 0 : -1}
                className={styles.step} onClick={() => setActiveStep(index)} onKeyDown={(event) => handleStepKey(event, index)}>
                <span className={styles.stepNumber}>0{index + 1}</span><span>{item.label}</span>
              </button>
            ))}
          </div>
          <div id="example-preview" className={styles.preview} role="tabpanel" aria-labelledby={`step-${activeStep}`} tabIndex={0}>
            <div className={styles.fileList}>
              <p className={styles.exampleLabel}>Example preview</p>
              <h3>{step.title}</h3>
              <ul>
                {['My Drive / Photos / photo.jpg', 'My Drive / Backup / photo-copy.jpg', 'My Drive / Trips / 2024 / IMG_1234.jpg'].map((path) => (
                  <li key={path}><Icon name="file" /><span>{path}</span></li>
                ))}
              </ul>
            </div>
            <div className={styles.comparison}>
              {['photo.jpg', 'photo-copy.jpg'].map((name, index) => (
                <figure key={name} className={styles.file}>
                  <Image src="/images/coastal-duplicates.png" alt={index === 0 ? 'Coastal cliffs, blue sea, and wildflowers' : 'An identical copy of the coastal photograph'} width={1536} height={1024} sizes="(max-width: 600px) 42vw, (max-width: 1050px) 38vw, 22vw" loading="eager" />
                  <figcaption>
                    <span className={styles.filename}>{name}</span>
                    <span className={index === 0 ? styles.keep : styles.move}>
                      <Icon name={index === 0 ? 'check-circle' : 'arrow-right'} />
                      {index === 0 ? 'Keep' : activeStep === 2 ? 'To _dupes' : 'Move to _dupes'}
                    </span>
                  </figcaption>
                </figure>
              ))}
            </div>
            <aside className={styles.reassurance}>
              <Icon name={step.icon} className={styles.reassuranceIcon} />
              <div><h3>{step.reassurance}</h3><p>{step.description}</p></div>
            </aside>
          </div>
          <div className={styles.safetyNote}>
            <Icon name="folder" />
            <p>Extras go to a private <code>_dupes</code> folder. Files are never permanently deleted.</p>
          </div>
        </section>
      </main>
      <footer className={styles.footer}>
        <div className={styles.footerItem}>
          <Icon name="monitor" />
          <div><h2>Runs in your browser</h2><p>Scanning and comparison run in your browser.<br />No files are uploaded to dedrive.</p></div>
        </div>
        <div className={styles.footerItem}>
          <Icon name="file" />
          <div><h2>Some items are skipped</h2><p>Shared with me items and native Google<br className={styles.desktopBreak} /> Docs, Sheets, and Slides are not scanned.</p></div>
        </div>
      </footer>
    </div>
  );
}
