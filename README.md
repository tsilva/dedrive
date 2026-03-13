<div align="center">
  <img src="logo.png" alt="dedrive-web" width="512"/>

  [![Live Demo](https://img.shields.io/badge/Live-dedrive.tsilva.eu-green?style=flat-square&logo=vercel)](https://dedrive.tsilva.eu)
  [![Next.js](https://img.shields.io/badge/Next.js-16-black?style=flat-square&logo=next.js)](https://nextjs.org/)
  [![License](https://img.shields.io/badge/License-ISC-blue?style=flat-square)](LICENSE)
  [![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-F7DF1E?style=flat-square&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)

  **🔍 Find and clean up duplicate files in your Google Drive with read-only access first 🧹**

  [Getting Started](#-getting-started) · [How It Works](#-how-it-works) · [Setup](#%EF%B8%8F-setup)
</div>

---

## 🤔 The Problem

Google Drive doesn't tell you about duplicate files. Over time, copies pile up — downloaded twice, synced from multiple devices, shared across folders. You're paying for storage you don't need, and there's no built-in way to find or fix it.

**dedrive-web scans your Drive in the browser, groups files by MD5 checksum, and only asks for write access if you choose to move duplicates into `_dupes/`.**

## ✨ Features

- **100% client-side** — your files never leave your browser, no backend server involved
- **Public landing + secure app split** — `/` stays public, `/app` hosts the privileged Drive workflow without analytics scripts
- **Read-only first** — scan, review, and previews use `drive.readonly`; write access is requested only before moves
- **Full Drive scan** — fetches your owned, non-trashed files via the Google Drive API with automatic pagination, excluding Shared with me items
- **Smart dedup** — groups files by MD5 checksum, skips Google Workspace files (Docs, Sheets, etc.)
- **Visual review** — preview images, PDFs, and text files side-by-side before deciding
- **Multi-file review** — every duplicate card gets a numbered keep badge, and the review can jump straight to execute with partial selections
- **Non-destructive** — duplicates are moved to a `_dupes/` folder, never deleted
- **No durable scan cache** — file inventory and review state stay in memory for the active tab
- **Google Analytics ready** — optional GA4 tracking stays on the public landing page only
- **SEO and sharing metadata** — canonical tags, social cards, icons, manifest, robots, and structured data

## 🚀 Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- A Google Cloud project with the Drive API enabled
- An OAuth 2.0 Client ID for a web application
- Optional: a Google Analytics 4 measurement ID

### Quick Start

```bash
git clone https://github.com/tsilva/dedrive-web.git
cd dedrive-web
./setup.sh     # interactive: creates GCP project, enables Drive API, configures OAuth
npm run dev    # open http://localhost:3000, then use /app for the secure workflow
```

The setup script walks you through creating a GCP project, enabling the Drive API, configuring the OAuth consent screen, and generating a Client ID. It writes the credentials to `.env.local` automatically.

If you also want GA4 locally, add `NEXT_PUBLIC_GA_MEASUREMENT_ID` to `.env.local` yourself.

Optional verification env vars are also supported if you want to connect the site to Google Search Console, Bing Webmaster Tools, or Yandex later.

### Manual Setup

If you prefer to configure things yourself:

1. Create a Google Cloud project and enable the **Google Drive API**
2. Configure the **OAuth consent screen** (External, add both `https://www.googleapis.com/auth/drive.readonly` and `https://www.googleapis.com/auth/drive`)
3. Create an **OAuth 2.0 Client ID** (Web application) with `http://localhost:3000` as an authorized JavaScript origin
4. Create `.env.local` at the project root:

```
NEXT_PUBLIC_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
NEXT_PUBLIC_GA_MEASUREMENT_ID=G-XXXXXXXXXX
GOOGLE_SITE_VERIFICATION=your-google-token
BING_SITE_VERIFICATION=your-bing-token
YANDEX_SITE_VERIFICATION=your-yandex-token
```

5. Install and run:

```bash
npm install
npm run dev
```

## 🔄 How It Works

```
/ (public landing) → /app sign-in → Scan Drive → Review Duplicates → Request Write Access → Execute Moves
```

1. **Open `/app`** and sign in with your Google account using the read-only Drive scope
2. **Scan** fetches all your owned, non-trashed files from Google Drive, excluding Shared with me items
3. **Review** presents duplicate groups sorted by wasted space so you can choose which copy to keep by clicking its numbered badge
4. **Execute** asks for the full Drive scope only when you are ready to move the unchosen duplicates into `_dupes/`, preserving the original directory structure, and you can jump there before reviewing every group

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
  layout.js            # Root shell shared by every route
  (marketing)/         # Public landing page with analytics and SEO metadata
  (secure)/app/        # Secure Drive workflow at /app (noindex, no analytics)
  manifest.js          # Web app manifest
  icon.js              # Generated app icon
  apple-icon.js        # Generated Apple touch icon
  opengraph-image.js   # Generated social preview image
  globals.css          # All styles

components/
  App.js               # Main orchestrator — screen state, auth, scan flow
  Header.js            # Navigation header
  screens/             # One component per screen (Account, Scan, Review, Execute)
  FilePreview.js       # Image/PDF/text preview component
  PdfPreview.js        # PDF.js renderer

hooks/
  useDecisions.js      # In-memory keep decisions for the active tab
  useScanResults.js    # In-memory scan results for the active tab
  useSettings.js       # App settings from localStorage

lib/
  auth.js              # Google Identity Services token client with incremental scopes
  analytics.js         # GA4 helper for product events
  drive.js             # Drive API v3 client with retry + pagination
  dedup.js             # MD5 grouping, path resolution, stats
  preview.js           # Lazy file preview with in-memory cache
  state.js             # localStorage-backed non-sensitive settings
  utils.js             # formatSize, formatDate, debounce, pooledMap
```

## 📄 License

[ISC](LICENSE)

---

<div align="center">

⭐ **Found this useful? [Give it a star](https://github.com/tsilva/dedrive-web)** ⭐

</div>
