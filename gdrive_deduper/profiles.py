"""Profile management for targeting multiple Google Drive accounts."""

from pathlib import Path

import yaml

PROFILES_DIR = Path("profiles")

CONFIG_TEMPLATE = """\
# Profile configuration
# dupes_folder: /_dupes
# batch_size: 100
# max_preview_mb: 10
# exclude_paths:
#   - /Backup/Old
"""


def get_profile_dir(name: str) -> Path:
    """Return the profile directory, creating it if missing."""
    profile_dir = PROFILES_DIR / name
    profile_dir.mkdir(parents=True, exist_ok=True)
    return profile_dir


def load_profile(name: str) -> dict:
    """Read config.yaml for a profile, returning merged config with defaults."""
    config_path = get_profile_dir(name) / "config.yaml"
    if config_path.exists():
        with open(config_path) as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    return {}


def get_profile_credentials_path(name: str) -> Path:
    """Return the credentials.json path for a profile."""
    return get_profile_dir(name) / "credentials.json"


def get_profile_token_path(name: str) -> Path:
    """Return the token.json path for a profile."""
    return get_profile_dir(name) / "token.json"


def get_profile_output_dir(name: str) -> Path:
    """Return the .output directory for a profile."""
    output_dir = get_profile_dir(name) / ".output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def init_profile(name: str) -> Path:
    """Create a profile directory with a template config.yaml.

    Returns the profile directory path.
    """
    profile_dir = get_profile_dir(name)
    config_path = profile_dir / "config.yaml"
    if not config_path.exists():
        config_path.write_text(CONFIG_TEMPLATE)
    return profile_dir


def list_profiles() -> list[str]:
    """List all profile names (subdirectories of profiles/)."""
    if not PROFILES_DIR.exists():
        return []
    return sorted(
        d.name for d in PROFILES_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")
    )
