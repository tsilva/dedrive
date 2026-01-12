"""Configuration module for Google Drive Deduplication Tool."""

import json
import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env file if present
load_dotenv()

CONFIG_FILE = "config.json"
ENV_EXCLUDE_PATHS = "GDRIVE_EXCLUDE_PATHS"


def load_config() -> dict:
    """Load configuration from config file if it exists."""
    config_path = Path(CONFIG_FILE)
    if config_path.exists():
        try:
            with open(config_path) as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load {CONFIG_FILE}: {e}")
    return {}


def get_exclude_paths() -> list[str]:
    """Get exclude paths from config file and environment variable.

    Sources (combined):
    1. Config file: config.json with "exclude_paths" array
    2. Environment variable: GDRIVE_EXCLUDE_PATHS (comma-separated paths)

    Returns:
        List of paths to exclude from scans.
    """
    exclude_paths = []

    # Load from config file
    config = load_config()
    file_paths = config.get("exclude_paths", [])
    if isinstance(file_paths, list):
        exclude_paths.extend(file_paths)

    # Load from environment variable (comma-separated)
    env_paths = os.environ.get(ENV_EXCLUDE_PATHS, "")
    if env_paths:
        for path in env_paths.split(","):
            path = path.strip()
            if path:
                exclude_paths.append(path)

    # Normalize paths (ensure they start with / and don't end with /)
    normalized = []
    for path in exclude_paths:
        path = path.strip()
        if not path.startswith("/"):
            path = "/" + path
        path = path.rstrip("/")
        if path:
            normalized.append(path)

    return list(set(normalized))  # Remove duplicates


def create_default_config():
    """Create a default config file with example exclude paths."""
    default_config = {
        "exclude_paths": [
            "# Add paths to exclude from scans, e.g.:",
            "# /documentor-puzzle/export",
            "# /Backup/Old"
        ]
    }

    config_path = Path(CONFIG_FILE)
    if not config_path.exists():
        with open(config_path, "w") as f:
            json.dump(default_config, f, indent=2)
        print(f"Created default config file: {CONFIG_FILE}")
