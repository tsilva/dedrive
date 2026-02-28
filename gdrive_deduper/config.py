"""Configuration module for Google Drive Deduplication Tool."""

import json
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from gdrive_deduper.profiles import load_profile, get_profile_token_path, get_profile_output_dir, init_profile, PROFILES_DIR

# Load .env file if present
load_dotenv()

# Active profile (set via set_active_profile)
active_profile: str | None = None
_profile_config: dict = {}


def set_active_profile(name: str):
    """Activate a profile, loading its config.yaml."""
    global active_profile, _profile_config
    active_profile = name
    _profile_config = load_profile(name)


def set_active_profile_from_email(email: str) -> str:
    """Create (if needed) and activate a profile based on user email.

    Args:
        email: The user's email address, used as the profile name.

    Returns:
        The profile name (same as email).
    """
    init_profile(email)
    set_active_profile(email)
    return email


def clear_active_profile():
    """Reset the active profile to None."""
    global active_profile, _profile_config
    active_profile = None
    _profile_config = {}

# Default configuration values
DEFAULTS = {
    "credentials_path": "credentials.json",
    "token_path": "token.json",
    "output_dir": ".output",
    "dupes_folder": "/_dupes",
    "batch_size": 100,
    "max_preview_mb": 10,
    "exclude_paths": [],
}

# Environment variable names
ENV_VARS = {
    "credentials_path": "GDRIVE_CREDENTIALS_PATH",
    "token_path": "GDRIVE_TOKEN_PATH",
    "output_dir": "GDRIVE_OUTPUT_DIR",
    "dupes_folder": "GDRIVE_DUPES_FOLDER",
    "batch_size": "GDRIVE_BATCH_SIZE",
    "max_preview_mb": "GDRIVE_MAX_PREVIEW_MB",
    "exclude_paths": "GDRIVE_EXCLUDE_PATHS",
}

CONFIG_FILE = "config.json"


def expand_path(path: str) -> Path:
    """Expand ~ and environment variables in path."""
    return Path(os.path.expanduser(os.path.expandvars(path)))


def load_config() -> dict:
    """Load configuration from config file if it exists.

    Checks cwd config.json first, then falls back to ~/.gdrive-deduper/config.json.
    """
    for config_path in [Path(CONFIG_FILE), PROFILES_DIR / CONFIG_FILE]:
        if config_path.exists():
            try:
                with open(config_path) as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                print(f"Error: Invalid JSON in {config_path}: {e}")
                print(f"Please fix the syntax in {config_path} or delete it to use defaults.")
            except PermissionError:
                print(f"Error: Cannot read {config_path} - permission denied.")
            except Exception as e:
                print(f"Warning: Failed to load {config_path}: {e}")
    return {}


def get_config_value(key: str, cli_value: Any = None) -> Any:
    """Get configuration value with precedence: CLI > ENV > config file > default.

    Args:
        key: Configuration key (e.g., 'credentials_path')
        cli_value: Value from CLI argument (highest precedence if not None)

    Returns:
        Configuration value from highest precedence source.
    """
    # CLI argument has highest precedence
    if cli_value is not None:
        return cli_value

    # Profile config.yaml (when a profile is active)
    if active_profile and key in _profile_config:
        return _profile_config[key]

    # Environment variable
    env_var = ENV_VARS.get(key)
    if env_var:
        env_value = os.environ.get(env_var)
        if env_value is not None:
            # Handle type conversion
            if key == "batch_size":
                try:
                    return int(env_value)
                except ValueError:
                    print(f"Warning: Invalid {env_var} value '{env_value}', using default.")
            elif key == "max_preview_mb":
                try:
                    return int(env_value)
                except ValueError:
                    print(f"Warning: Invalid {env_var} value '{env_value}', using default.")
            else:
                return env_value

    # Config file
    config = load_config()
    if key in config:
        return config[key]

    # Default
    return DEFAULTS.get(key)


def get_credentials_path(cli_value: str = None) -> Path:
    """Get credentials file path.

    Falls back to ~/.gdrive-deduper/credentials.json when the default
    credentials.json doesn't exist in cwd.
    """
    path = get_config_value("credentials_path", cli_value)
    resolved = expand_path(path)
    if not resolved.exists() and path == DEFAULTS["credentials_path"]:
        fallback = PROFILES_DIR / "credentials.json"
        if fallback.exists():
            return fallback
    return resolved


def get_token_path(credentials_path: Path = None) -> Path:
    """Get token file path.

    By default, token.json is stored next to credentials.json.
    Can be overridden via GDRIVE_TOKEN_PATH or config file.
    """
    if active_profile:
        return get_profile_token_path(active_profile)

    explicit_path = get_config_value("token_path")

    # If explicitly set (not default), use that
    if explicit_path != DEFAULTS["token_path"]:
        return expand_path(explicit_path)

    # Otherwise, store next to credentials file
    if credentials_path:
        return credentials_path.parent / "token.json"

    return Path("token.json")


def get_output_dir() -> Path:
    """Get output directory path."""
    if active_profile:
        return get_profile_output_dir(active_profile)
    path = get_config_value("output_dir")
    return expand_path(path)


def get_dupes_folder() -> str:
    """Get the name of the dupes folder in Google Drive."""
    return get_config_value("dupes_folder")


def get_batch_size() -> int:
    """Get batch size for API operations."""
    return get_config_value("batch_size")


def get_max_preview_size() -> int:
    """Get max preview size in bytes."""
    mb = get_config_value("max_preview_mb")
    return mb * 1024 * 1024


def get_exclude_paths(cli_excludes: list[str] = None) -> list[str]:
    """Get exclude paths from CLI, config file, and environment variable.

    Sources (combined):
    1. CLI arguments (--exclude flags)
    2. Config file: config.json with "exclude_paths" array
    3. Environment variable: GDRIVE_EXCLUDE_PATHS (comma-separated paths)

    Returns:
        List of paths to exclude from scans.
    """
    exclude_paths = []

    # CLI arguments
    if cli_excludes:
        exclude_paths.extend(cli_excludes)

    # Profile config.yaml (when a profile is active)
    if active_profile and "exclude_paths" in _profile_config:
        profile_paths = _profile_config["exclude_paths"]
        if isinstance(profile_paths, list):
            exclude_paths.extend(profile_paths)

    # Load from config file
    config = load_config()
    file_paths = config.get("exclude_paths", [])
    if isinstance(file_paths, list):
        exclude_paths.extend(file_paths)

    # Load from environment variable (comma-separated)
    env_var = ENV_VARS.get("exclude_paths")
    env_paths = os.environ.get(env_var, "")
    if env_paths:
        for path in env_paths.split(","):
            path = path.strip()
            if path:
                exclude_paths.append(path)

    # Normalize paths (ensure they start with / and don't end with /)
    normalized = []
    for path in exclude_paths:
        path = path.strip()
        # Skip comment lines in config
        if path.startswith("#"):
            continue
        if not path.startswith("/"):
            path = "/" + path
        path = path.rstrip("/")
        if path:
            normalized.append(path)

    return list(set(normalized))  # Remove duplicates


def create_default_config():
    """Create a default config file with all available options."""
    default_config = {
        "# credentials_path": "~/.config/gdrive-deduper/credentials.json",
        "# token_path": "~/.config/gdrive-deduper/token.json",
        "# output_dir": ".output",
        "# dupes_folder": "/_dupes",
        "# batch_size": 100,
        "# max_preview_mb": 10,
        "exclude_paths": [
            "# Add paths to exclude from scans, e.g.:",
            "# /Backup/Old",
            "# /tmp"
        ]
    }

    config_path = Path(CONFIG_FILE)
    if not config_path.exists():
        with open(config_path, "w") as f:
            json.dump(default_config, f, indent=2)
        print(f"Created default config file: {CONFIG_FILE}")


def print_config():
    """Print current configuration for debugging."""
    print("Current configuration:")
    print(f"  credentials_path: {get_credentials_path()}")
    print(f"  token_path: {get_token_path(get_credentials_path())}")
    print(f"  output_dir: {get_output_dir()}")
    print(f"  dupes_folder: {get_dupes_folder()}")
    print(f"  batch_size: {get_batch_size()}")
    print(f"  max_preview_mb: {get_config_value('max_preview_mb')}")
    print(f"  exclude_paths: {get_exclude_paths()}")
