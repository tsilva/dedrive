# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
uv sync

# Install as standalone CLI tool
uv tool install . --editable

# Login (opens browser, auto-creates profile from email)
dedrive login

# Logout
dedrive logout

# List profiles with login status
dedrive --list-profiles

# Launch the Gradio web UI (auto-detects logged-in profile)
dedrive

# Launch on a custom port
dedrive --port 8080

# Enable public sharing link
dedrive --share

# Enable verbose/debug logging
dedrive --verbose

# Write logs to file
dedrive --log-file debug.log

# Validate credentials without launching UI
dedrive --profile work --validate

# Backward-compatible: run via main.py
uv run main.py login
uv run main.py --list-profiles
```

**Note:** PDF preview in the web UI requires poppler: `brew install poppler` (macOS)

## Configuration

All settings can be configured via environment variables, `config.json`, or profiles. Precedence: profile config.yaml > ENV > config.json > defaults.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GDRIVE_CREDENTIALS_PATH` | `credentials.json` | Path to OAuth credentials file |
| `GDRIVE_TOKEN_PATH` | (next to credentials) | Path to OAuth token file |
| `GDRIVE_OUTPUT_DIR` | `.output` | Directory for output files |
| `GDRIVE_DUPES_FOLDER` | `/_dupes` | Folder name for duplicates in Drive |
| `GDRIVE_BATCH_SIZE` | `100` | Batch size for API operations |
| `GDRIVE_MAX_PREVIEW_MB` | `10` | Max file size for previews (MB) |
| `GDRIVE_EXCLUDE_PATHS` | (none) | Comma-separated paths to exclude |

### Config File

Create `config.json` in the project root:

```json
{
  "credentials_path": "~/.config/dedrive/credentials.json",
  "output_dir": "~/.local/share/dedrive",
  "dupes_folder": "/_dupes",
  "batch_size": 100,
  "max_preview_mb": 10,
  "exclude_paths": [
    "/Backup/Old",
    "/tmp"
  ]
}
```

Paths support `~` expansion for home directory.

### Exclude Paths

Folders can be excluded from scans using two methods (combined):

1. **Config file:** Add `exclude_paths` array to `config.json`
2. **Environment variable:** Set `GDRIVE_EXCLUDE_PATHS` (comma-separated)

Example `.env` file:
```
GDRIVE_EXCLUDE_PATHS=/documentor-puzzle/export,/Backup/Old
```

### Config File Fallback

`config.json` is checked in cwd first, then falls back to `~/.dedrive/config.json`.

### Credentials Fallback

`credentials.json` is checked in cwd first, then falls back to `~/.dedrive/credentials.json`.

### Profiles

Profiles allow targeting multiple Google Drive accounts. Each profile is a subfolder under `~/.dedrive/` with its own credentials, token, config, and output data. Profiles are auto-created on `dedrive login` using the Google account email as the profile name.

```
~/.dedrive/
  credentials.json     # Shared OAuth client credentials (fallback)
  config.json          # Shared config (fallback)
  user@gmail.com/
    config.yaml        # Profile settings (YAML)
    token.json         # OAuth token (auto-generated)
    .output/           # Scan results, decisions, logs
```

Example `config.yaml`:

```yaml
dupes_folder: /_dupes
batch_size: 100
max_preview_mb: 10
exclude_paths:
  - /Backup/Old
  - /tmp
```

When `--profile <name>` is used, `config.py` resolves credentials, token, and output paths from the profile directory. Profile `config.yaml` values slot into the precedence chain between CLI args and environment variables.

## Architecture

Installable CLI tool (`dedrive`) with a Gradio web UI for finding and managing duplicate files in Google Drive.

**Package structure:**
- `dedrive/cli.py` — CLI entry point with `login`, `logout` subcommands and Gradio launcher
- `dedrive/ui.py` — Gradio web UI (all UI code, dataclasses, helpers)
- `dedrive/drive.py` — Google Drive authentication, API fetch, path resolution
- `dedrive/dedup.py` — Duplicate detection logic
- `dedrive/config.py` — Configuration management with fallback chain
- `dedrive/profiles.py` — Profile management (profiles stored in `~/.dedrive/`)
- `main.py` — Thin wrapper for backward compatibility (`uv run main.py`)

**Features:**
- **CLI:** `login` (browser-based OAuth), `logout` (remove token), `--list-profiles`
- **Scan Tab:** Run scans with progress feedback
- **Review Tab:** Side-by-side file comparison with previews, make keep/skip decisions
- **Export Tab:** Preview and execute moves, export decisions.json
- **CLI flags:** Profile selection (`--profile`), credential validation (`--validate`), logging (`--verbose`, `--log-file`), Gradio options (`--port`, `--share`)

**Key design decisions:**
- Profiles auto-created on login using Google account email as name
- Profiles stored in `~/.dedrive/` (works when installed as standalone CLI)
- `login` subcommand opens browser for OAuth without importing Gradio
- Uses `drive` scope (full access for file moves)
- Fetches all files in one query then filters locally (faster than recursive folder traversal)
- Path resolution uses memoization (`path_cache`) for efficiency
- Files with same MD5 but different size marked as "uncertain"
- Google Workspace files (Docs, Sheets) skipped (no MD5 available)
- Decisions auto-save to `.output/decisions.json` (resume sessions)
- File previews cached in `.output/preview_cache/`

**Output:** `.output/scan_results.json` (scan results), `.output/decisions.json` (user decisions), `.output/execution_log.json` (move results)

### Moving Duplicates

Instead of deleting duplicates, files are moved to a `/_dupes` folder at the root of your Google Drive:

1. **Scan** your drive to find duplicates
2. **Review** and mark which files to keep
3. **Preview (Dry Run)** to see what would be moved
4. **Execute** to move duplicates to `/_dupes`

The original folder structure is preserved under `/_dupes`:
- `/Photos/2024/IMG.jpg` → `/_dupes/Photos/2024/IMG.jpg`

**Re-authentication required:** If you previously used this tool with read-only access, delete `token.json` and re-authenticate to grant move permissions.
