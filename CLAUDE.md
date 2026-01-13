# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
uv sync

# Run the web UI (Gradio-based deduplication manager)
uv run app.py

# Run the CLI deduplication scan
uv run main.py

# Scan specific folder (CLI)
uv run main.py --path "/Photos"

# Exclude folders from scan (CLI)
uv run main.py --exclude "/Backup/Old" --exclude "/tmp"

# Custom output file (CLI)
uv run main.py --output .output/custom.csv

# Use different credentials file (CLI)
uv run main.py --credentials path/to/creds.json
```

**Note:** PDF preview in the web UI requires poppler: `brew install poppler` (macOS)

## Configuration

### Exclude Paths

Folders can be excluded from scans using three methods (combined):

1. **CLI argument:** `--exclude "/path/to/exclude"` (can specify multiple times)
2. **Config file:** Create `config.json` with an `exclude_paths` array
3. **Environment variable:** Set `GDRIVE_EXCLUDE_PATHS` (comma-separated paths)

Example `config.json`:
```json
{
  "exclude_paths": [
    "/documentor-puzzle/export",
    "/Backup/Old",
    "/tmp"
  ]
}
```

Example `.env` file (recommended):
```
GDRIVE_EXCLUDE_PATHS=/documentor-puzzle/export,/Backup/Old
```

Or via shell environment variable:
```bash
export GDRIVE_EXCLUDE_PATHS="/documentor-puzzle/export,/Backup/Old"
```

## Architecture

Two interfaces for finding and managing duplicate files in Google Drive:

### CLI Tool (`main.py`)
Fast scanning tool that outputs duplicate pairs to CSV.

**Flow:**
1. OAuth authentication (cached in `token.json`)
2. Single paginated API call fetches all files with MD5 metadata
3. Build in-memory path lookup from parent IDs
4. Group files by MD5 checksum
5. Output CSV with all duplicate pairs

### Web UI (`app.py`)
Gradio-based interface for the full deduplication workflow.

**Features:**
- **Scan Tab:** Run scans with progress feedback
- **Review Tab:** Side-by-side file comparison with previews, make keep/skip decisions
- **Export Tab:** Preview and execute moves, export decisions.json

**Key design decisions:**
- Uses `drive` scope (full access for file moves)
- Fetches all files in one query then filters locally (faster than recursive folder traversal)
- Path resolution uses memoization (`path_cache`) for efficiency
- Files with same MD5 but different size marked as "uncertain"
- Google Workspace files (Docs, Sheets) skipped (no MD5 available)
- Decisions auto-save to `.output/decisions.json` (resume sessions)
- File previews cached in `.output/preview_cache/`

**Output:** `.output/duplicates.csv` (scan results), `.output/decisions.json` (user decisions), `.output/execution_log.json` (move results)

### Moving Duplicates

Instead of deleting duplicates, files are moved to a `/_dupes` folder at the root of your Google Drive:

1. **Scan** your drive to find duplicates
2. **Review** and mark which files to keep
3. **Preview (Dry Run)** to see what would be moved
4. **Execute** to move duplicates to `/_dupes`

The original folder structure is preserved under `/_dupes`:
- `/Photos/2024/IMG.jpg` → `/_dupes/Photos/2024/IMG.jpg`

**Re-authentication required:** If you previously used this tool with read-only access, delete `token.json` and re-authenticate to grant move permissions.
