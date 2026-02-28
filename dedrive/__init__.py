"""Google Drive Deduplication Tool - package API."""

from dedrive.drive import (
    SCOPES,
    setup_logging,
    authenticate,
    create_oauth_flow,
    run_oauth_callback_server,
    save_token,
    load_existing_token,
    get_user_info,
    fetch_with_retry,
    fetch_all_files,
    build_lookups,
    get_path,
)
from dedrive.dedup import (
    filter_by_path,
    filter_excluded_paths,
    find_duplicates,
    write_csv,
    calculate_savings,
    format_size,
)
from dedrive.config import (
    get_exclude_paths,
    get_credentials_path,
    get_token_path,
    get_output_dir,
    get_dupes_folder,
    get_batch_size,
    get_max_preview_size,
    set_active_profile,
    set_active_profile_from_email,
    create_default_config,
    print_config,
)
from dedrive.profiles import (
    init_profile,
    list_profiles,
    delete_profile_token,
)

__all__ = [
    # drive
    "SCOPES",
    "setup_logging",
    "authenticate",
    "create_oauth_flow",
    "run_oauth_callback_server",
    "save_token",
    "load_existing_token",
    "get_user_info",
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
    "set_active_profile_from_email",
    "create_default_config",
    "print_config",
    # profiles
    "init_profile",
    "list_profiles",
    "delete_profile_token",
]
