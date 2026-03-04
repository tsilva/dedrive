<div align="center">
  <img src="logo.png" alt="dedrive-web" width="512"/>

  [![Live Demo](https://img.shields.io/badge/Live-dedrive.tsilva.eu-green?style=flat-square&logo=vercel)](https://dedrive.tsilva.eu)
  [![Next.js](https://img.shields.io/badge/Next.js-16-black?style=flat-square&logo=next.js)](https://nextjs.org/)
  [![License](https://img.shields.io/badge/License-ISC-blue?style=flat-square)](LICENSE)
  [![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-F7DF1E?style=flat-square&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)

  **🔍 Find and clean up duplicate files in your Google Drive — entirely from your browser 🧹**

  [Getting Started](#-getting-started) · [How It Works](#-how-it-works) · [Setup](#%EF%B8%8F-setup)
</div>

---

## 🤔 The Problem

Google Drive doesn't tell you about duplicate files. Over time, copies pile up — downloaded twice, synced from multiple devices, shared across folders. You're paying for storage you don't need, and there's no built-in way to find or fix it.

**dedrive-web scans your entire Drive, groups files by MD5 checksum, and lets you review and relocate duplicates — all without uploading a single byte to any server.**

## ✨ Features

- **100% client-side** — your files never leave your browser, no backend server involved
- **Full Drive scan** — fetches all owned files via the Google Drive API with automatic pagination
- **Smart dedup** — groups files by MD5 checksum, skips Google Workspace files (Docs, Sheets, etc.)
- **Visual review** — preview images, PDFs, and text files side-by-side before deciding
- **Keyboard shortcuts** — navigate groups with arrow keys, pick keepers with `1`/`2`, skip with `S`
- **Non-destructive** — duplicates are moved to a `_dupes/` folder, never deleted
- **Export/import decisions** — save your review progress as JSON and resume later
- **Persistent state** — scan results stored in IndexedDB, decisions in localStorage

## 🚀 Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- A Google Cloud project with the Drive API enabled
- An OAuth 2.0 Client ID for a web application

### Quick Start

```bash
git clone https://github.com/tsilva/dedrive-web.git
cd dedrive-web
./setup.sh     # interactive: creates GCP project, enables Drive API, configures OAuth
npm run dev    # open http://localhost:3000
```

The setup script walks you through creating a GCP project, enabling the Drive API, configuring the OAuth consent screen, and generating a Client ID. It writes the credentials to `.env.local` automatically.

### Manual Setup

If you prefer to configure things yourself:

1. Create a Google Cloud project and enable the **Google Drive API**
2. Configure the **OAuth consent screen** (External, add `https://www.googleapis.com/auth/drive` scope)
3. Create an **OAuth 2.0 Client ID** (Web application) with `http://localhost:3000` as an authorized JavaScript origin
4. Create `.env.local` at the project root:

```
NEXT_PUBLIC_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
```

5. Install and run:

```bash
npm install
npm run dev
```

## 🔄 How It Works

```
Sign In → Scan Drive → Review Duplicates → Execute Moves
```

1. **Sign in** with your Google account (OAuth implicit grant via Google Identity Services)
2. **Scan** fetches all your owned, non-trashed files from Google Drive
3. **Review** presents duplicate groups sorted by wasted space — pick which copy to keep, or skip
4. **Execute** moves the unchosen duplicates into a `_dupes/` folder in your Drive, preserving the original directory structure

Files are grouped by MD5 checksum. Groups with mismatched file sizes are flagged for careful review.

## ⚙️ Setup

| Command | Description |
|---------|-------------|
| `npm run dev` | Start dev server on `http://localhost:3000` |
| `npm run build` | Production build |
| `npm run start` | Serve production build |
| `./setup.sh` | Interactive GCP + OAuth setup |

## 🏗️ Architecture

```
app/
  page.js              # Entry point (client-only, SSR disabled)
  layout.js            # Root layout with metadata
  globals.css          # All styles

components/
  App.js               # Main orchestrator — screen state, auth, scan flow
  Header.js            # Navigation header
  screens/             # One component per screen (Account, Scan, Review, Execute)
  FilePreview.js       # Image/PDF/text preview component
  PdfPreview.js        # PDF.js renderer

hooks/
  useDecisions.js      # Read/write per-group keep/skip decisions (localStorage)
  useScanResults.js    # Load/save duplicate groups (IndexedDB)
  useKeyboardShortcuts.js  # Arrow keys + number keys for review
  useSettings.js       # App settings from localStorage

lib/
  auth.js              # Google Identity Services token client
  drive.js             # Drive API v3 client with retry + pagination
  dedup.js             # MD5 grouping, path resolution, stats
  preview.js           # Lazy file preview with in-memory cache
  state.js             # localStorage + IndexedDB persistence
  utils.js             # formatSize, formatDate, debounce, pooledMap
```

## 📄 License

[ISC](LICENSE)

---

<div align="center">

⭐ **Found this useful? [Give it a star](https://github.com/tsilva/dedrive-web)** ⭐

</div>
