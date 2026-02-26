"""Google Drive Deduplication Tool - package API."""

from gdrive_deduper.drive import (
    SCOPES,
    setup_logging,
    authenticate,
    fetch_with_retry,
    fetch_all_files,
    build_lookups,
    get_path,
)
from gdrive_deduper.dedup import (
    filter_by_path,
    filter_excluded_paths,
    find_duplicates,
    write_csv,
    calculate_savings,
    format_size,
)
from gdrive_deduper.config import (
    get_exclude_paths,
    get_credentials_path,
    get_token_path,
    get_output_dir,
    get_dupes_folder,
    get_batch_size,
    get_max_preview_size,
    set_active_profile,
    create_default_config,
    print_config,
)
from gdrive_deduper.profiles import (
    init_profile,
    list_profiles,
)

__all__ = [
    # drive
    "SCOPES",
    "setup_logging",
    "authenticate",
    "fetch_with_retry",
    "fetch_all_files",
    "build_lookups",
    "get_path",
    # dedup
    "filter_by_path",
    "filter_excluded_paths",
    "find_duplicates",
    "write_csv",
    "calculate_savings",
    "format_size",
    # config
    "get_exclude_paths",
    "get_credentials_path",
    "get_token_path",
    "get_output_dir",
    "get_dupes_folder",
    "get_batch_size",
    "get_max_preview_size",
    "set_active_profile",
    "create_default_config",
    "print_config",
    # profiles
    "init_profile",
    "list_profiles",
]
