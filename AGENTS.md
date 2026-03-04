# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- `npm run dev` — start Next.js dev server on http://localhost:3000
- `npm run build` — production build
- `npm run start` — serve production build
- `./setup.sh` — interactive setup: creates GCP project, enables Drive API, configures OAuth, writes `.env.local`

No test runner or linter is configured.

## Environment

Requires `.env.local` with `NEXT_PUBLIC_GOOGLE_CLIENT_ID` (Google OAuth client ID). Created by `setup.sh`.

## Architecture

Next.js 16 app (App Router, JavaScript, no TypeScript) that finds and manages duplicate files in Google Drive. Runs entirely client-side — no backend/API routes. The single page (`app/page.js`) dynamically imports `components/App.js` with SSR disabled.

### Screen flow

`App.js` manages a `screen` state that cycles through four screens in `components/screens/`:

1. **AccountScreen** — Google sign-in, start scan
2. **ScanScreen** — progress while fetching all Drive files
3. **ReviewScreen** — review duplicate groups, mark which file to keep per group
4. **ExecuteScreen** — apply decisions (move duplicates to a `_dupes` folder)

### Key modules (`lib/`)

- **auth.js** — Google Identity Services (GIS) token client wrapper. Uses implicit grant flow (access tokens, not ID tokens). Token stored in module-level variable.
- **drive.js** — Google Drive REST API v3 client. Handles pagination, retry with exponential backoff for 429/403, and silent token refresh on 401.
- **dedup.js** — Groups files by `md5Checksum`, resolves full paths from parent chain, computes wasted-space stats. Skips Google Workspace native types (Docs, Sheets, etc.) since they have no md5.
- **preview.js** — Lazy file preview with in-memory cache. Supports images (thumbnail or download), PDFs (via pdfjs-dist), and text files (first 5KB). `clearPreviewCache()` revokes blob URLs on sign-out.
- **state.js** — Persistence layer. Settings and decisions in `localStorage` (prefixed `dedrive_`). Scan results in IndexedDB (`dedrive` DB, `scans` store) to handle large datasets.

### Hooks (`hooks/`)

- **useDecisions** — reads/writes per-group keep/skip decisions from localStorage
- **useScanResults** — loads/saves duplicate groups from IndexedDB
- **useKeyboardShortcuts** — keyboard navigation for the review screen
- **useSettings** — reads app settings from localStorage

### Path aliasing

`@/*` maps to project root via `jsconfig.json`.

## Important notes

- README.md must be kept up to date with any significant project changes.
