<div align="center">
  <img src="logo.png" alt="gdrive-deduper" width="512"/>

  [![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
  [![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![Google Drive API](https://img.shields.io/badge/Google%20Drive-API%20v3-4285F4?logo=googledrive&logoColor=white)](https://developers.google.com/drive)

  **🔍 Find and manage duplicate files in Google Drive using MD5 checksums 🗑️**

  [Features](#features) · [Quick Start](#quick-start) · [Configuration](#configuration) · [Usage](#usage)
</div>

---

## Features

- **Fast MD5-based detection** - Identifies duplicates by comparing file checksums, not just names
- **Two interfaces** - CLI for quick scans, Web UI for interactive review with file previews
- **Non-destructive** - Moves duplicates to `/_dupes` folder instead of deleting them
- **Preserves structure** - Original folder hierarchy is maintained under the dupes folder
- **Resumable sessions** - Decisions auto-save and persist across sessions
- **Flexible filtering** - Scan specific paths and exclude folders from analysis
- **Multi-account profiles** - Target different Google Drive accounts with named profiles

## Quick Start

```bash
# Install with uv
uv sync

# Run a scan (CLI)
uv run main.py

# Or launch the web UI
uv run app.py
```

**First run:** A browser window will open for Google OAuth authentication. Grant access to your Google Drive.

## Installation

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) package manager
- Google Cloud OAuth credentials ([setup guide](#google-cloud-setup))

### Google Cloud Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a project (or select existing)
3. Enable the **Google Drive API**
4. Create **OAuth 2.0 Client ID** (choose "Desktop app")
5. Download the JSON file and save as `credentials.json` in the project root

## Usage

### CLI Tool

```bash
# Scan entire drive
uv run main.py

# Scan specific folder
uv run main.py --path "/Photos"

# Exclude folders
uv run main.py --exclude "/Backup/Old" --exclude "/tmp"

# Custom output location
uv run main.py --output results.csv

# Validate credentials
uv run main.py --validate

# Debug logging
uv run main.py --verbose --log-file debug.log

# Profiles (multiple Google accounts)
uv run main.py --init-profile work
uv run main.py --list-profiles
uv run main.py --profile work
```

### Web UI

```bash
uv run app.py
```

The web interface provides three tabs:

| Tab | Purpose |
|-----|---------|
| **Scan** | Run scans with path filtering and progress feedback |
| **Review** | Side-by-side comparison with file previews, make keep/skip decisions |
| **Export** | Preview moves (dry run), execute moves, export decisions to JSON |

**Note:** PDF preview requires poppler: `brew install poppler` (macOS)

### Moving Duplicates

Instead of deleting, duplicates are moved to `/_dupes` at Drive root:

```
/Photos/2024/IMG.jpg  →  /_dupes/Photos/2024/IMG.jpg
```

1. **Scan** - Find duplicates
2. **Review** - Mark which files to keep
3. **Preview** - Dry run to see what would move
4. **Execute** - Move duplicates to `/_dupes`

## Configuration

Settings can be configured via environment variables, `config.json`, or CLI arguments.

**Precedence:** CLI > Profile config.yaml > Environment > Config file > Defaults

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GDRIVE_CREDENTIALS_PATH` | `credentials.json` | OAuth credentials file |
| `GDRIVE_TOKEN_PATH` | (next to credentials) | OAuth token file |
| `GDRIVE_OUTPUT_DIR` | `.output` | Output directory |
| `GDRIVE_DUPES_FOLDER` | `/_dupes` | Folder for duplicates |
| `GDRIVE_BATCH_SIZE` | `100` | Batch size for API operations |
| `GDRIVE_MAX_PREVIEW_MB` | `10` | Max file size for previews |
| `GDRIVE_EXCLUDE_PATHS` | (none) | Comma-separated paths to exclude |

### Config File

Create `config.json` in the project root:

```json
{
  "credentials_path": "~/.config/gdrive-deduper/credentials.json",
  "output_dir": "~/.local/share/gdrive-deduper",
  "dupes_folder": "/_dupes",
  "batch_size": 100,
  "exclude_paths": ["/Backup/Old", "/tmp"]
}
```

### Profiles

Use profiles to manage multiple Google Drive accounts:

```bash
# Create a profile
uv run main.py --init-profile work

# Copy credentials into the profile
cp ~/Downloads/credentials.json profiles/work/

# Use the profile
uv run main.py --profile work
```

Each profile stores its own `credentials.json`, `token.json`, `config.yaml`, and `.output/` under `profiles/<name>/`.

## Output Files

| File | Description |
|------|-------------|
| `.output/duplicates.csv` | Scan results with duplicate pairs |
| `.output/decisions.json` | User decisions (auto-saved) |
| `.output/execution_log.json` | Move operation results |
| `.output/scan_results.json` | Cached scan data for session resume |

## How It Works

1. **OAuth authentication** - Cached in `token.json` after first login
2. **Single API call** - Fetches all files with MD5 metadata in one paginated request
3. **In-memory path resolution** - Builds paths from parent IDs with memoization
4. **MD5 grouping** - Groups files by checksum to identify duplicates
5. **Size validation** - Files with same MD5 but different sizes flagged as "uncertain"

**Note:** Google Workspace files (Docs, Sheets, Slides) are skipped as they don't have MD5 checksums.

## Re-authentication

If you previously used this tool with read-only access, delete `token.json` and re-authenticate to grant move permissions.

## License

MIT
