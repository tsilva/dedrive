# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- `pnpm dev` — start Next.js dev server on http://localhost:3000
- `pnpm build` — production build
- `pnpm start` — serve production build
- `./setup.sh` — interactive setup: creates GCP project, enables Drive API, configures OAuth, writes `.env.local`

No test runner or linter is configured.

## Command conventions

- When the user says only `push`, interpret it as: stage the relevant current changes, create an appropriate git commit, integrate upstream changes if the remote branch has advanced, then push.

## Environment

Requires `.env.local` with `NEXT_PUBLIC_GOOGLE_CLIENT_ID` (Google OAuth client ID). `NEXT_PUBLIC_SITE_URL` is optional and defaults to `https://dedrive.tsilva.eu` for metadata/canonical generation. `.env.local` is created by `setup.sh`.

## Architecture

Next.js 16 app (App Router, JavaScript, no TypeScript) that finds and manages duplicate files in Google Drive. It uses a public marketing route at `/` plus a secure client-rendered workflow at `/app`, with no backend/API routes.

### Screen flow

`components/App.js` manages a `screen` state that cycles through four screens in `components/screens/`:

1. **AccountScreen** — Google sign-in, start scan
2. **ScanScreen** — progress while fetching all Drive files
3. **ReviewScreen** — review duplicate groups and select copies to discard
4. **ExecuteScreen** — apply decisions (move duplicates to a `_dupes` folder)

### Key modules (`lib/`)

- **auth.js** — Google Identity Services (GIS) token client wrapper. Uses implicit grant flow (access tokens, not ID tokens). Token stored in module-level variable.
- **drive.js** — Google Drive REST API v3 client. Handles pagination, retry with exponential backoff for 429/403, and silent token refresh on 401.
- **dedup.js** — Groups files by `md5Checksum`, resolves full paths from parent chain, computes wasted-space stats. Skips Google Workspace native types (Docs, Sheets, etc.) since they have no md5.
- **preview.js** — Lazy file preview with in-memory cache. Supports images (thumbnail or download), PDFs (via pdfjs-dist), and text files (first 5KB). `clearPreviewCache()` revokes blob URLs on sign-out.
- **state.js** — Reads non-sensitive settings from `localStorage` and purges app-owned browser storage after execution. Scan results and review decisions remain in active-tab memory.

### Hooks (`hooks/`)

- **useDecisions** — holds per-group discard/skip decisions in active-tab memory
- **useKeyboardShortcuts** — keyboard navigation for the review screen

### Path aliasing

`@/*` maps to project root via `jsconfig.json`.

## Important notes

- README.md must be kept up to date with any significant project changes.
