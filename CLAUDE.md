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

# Validate credentials without scanning
uv run main.py --validate

# Enable verbose/debug logging
uv run main.py --verbose

# Write logs to file
uv run main.py --log-file debug.log

# Create a profile (for multiple Google accounts)
uv run main.py --init-profile work

# List profiles
uv run main.py --list-profiles

# Run scan with a profile
uv run main.py --profile work

# Profile with other flags
uv run main.py --profile work --path "/Photos" --verbose
```

**Note:** PDF preview in the web UI requires poppler: `brew install poppler` (macOS)

## Configuration

All settings can be configured via environment variables, `config.json`, CLI arguments, or profiles. Precedence: CLI > profile config.yaml > ENV > config.json > defaults.

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
  "credentials_path": "~/.config/gdrive-deduper/credentials.json",
  "output_dir": "~/.local/share/gdrive-deduper",
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

Folders can be excluded from scans using three methods (combined):

1. **CLI argument:** `--exclude "/path/to/exclude"` (can specify multiple times)
2. **Config file:** Add `exclude_paths` array to `config.json`
3. **Environment variable:** Set `GDRIVE_EXCLUDE_PATHS` (comma-separated)

Example `.env` file:
```
GDRIVE_EXCLUDE_PATHS=/documentor-puzzle/export,/Backup/Old
```

### Profiles

Profiles allow targeting multiple Google Drive accounts. Each profile is a subfolder under `./profiles/` with its own credentials, token, config, and output data.

```
profiles/
  work/
    config.yaml        # Profile settings (YAML)
    credentials.json   # OAuth client credentials
    token.json         # OAuth token (auto-generated)
    .output/           # Scan results, decisions, logs
```

Example `config.yaml`:

```yaml
# profiles/work/config.yaml
dupes_folder: /_dupes
batch_size: 100
max_preview_mb: 10
exclude_paths:
  - /Backup/Old
  - /tmp
```

When `--profile <name>` is used, `config.py` resolves credentials, token, and output paths from the profile directory. Profile `config.yaml` values slot into the precedence chain between CLI args and environment variables.

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
