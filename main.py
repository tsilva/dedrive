#!/usr/bin/env python3
"""Google Drive Deduplication Tool - Find duplicate files using MD5 checksums."""

import argparse
import logging
import sys
from pathlib import Path

from googleapiclient.discovery import build

from gdrive_deduper import (
    setup_logging,
    authenticate,
    fetch_all_files,
    build_lookups,
    get_path,
    find_duplicates,
    write_csv,
    calculate_savings,
    format_size,
    filter_by_path,
    filter_excluded_paths,
    get_exclude_paths,
    get_credentials_path,
    get_output_dir,
    set_active_profile,
    init_profile,
    list_profiles,
)

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Find duplicate files in Google Drive using MD5 checksums"
    )
    parser.add_argument(
        "--path", "-p", help="Scan specific path (default: all files)"
    )
    parser.add_argument(
        "--exclude",
        "-e",
        action="append",
        default=[],
        help="Exclude paths from scan (can be specified multiple times). "
        "Also reads from config.json and GDRIVE_EXCLUDE_PATHS env var.",
    )
    parser.add_argument(
        "--output", "-o", help="Output CSV file (default: <output_dir>/duplicates.csv)"
    )
    parser.add_argument(
        "--credentials",
        "-c",
        help="OAuth credentials file (default: credentials.json or GDRIVE_CREDENTIALS_PATH)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate credentials and exit without scanning",
    )
    parser.add_argument(
        "--profile", "-P",
        help="Use a named profile (reads config/credentials from profiles/<name>/)",
    )
    parser.add_argument(
        "--init-profile",
        metavar="NAME",
        help="Create a new profile with template config and exit",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available profiles and exit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--log-file",
        help="Write logs to file (in addition to console)",
    )
    args = parser.parse_args()

    # Handle profile management commands
    if args.list_profiles:
        profiles = list_profiles()
        if profiles:
            print("Available profiles:")
            for name in profiles:
                print(f"  {name}")
        else:
            print("No profiles found. Create one with --init-profile <name>")
        sys.exit(0)

    if args.init_profile:
        profile_dir = init_profile(args.init_profile)
        print(f"Profile '{args.init_profile}' created at {profile_dir}")
        print(f"  Copy your credentials.json into {profile_dir}/")
        print(f"  Edit {profile_dir / 'config.yaml'} to customize settings")
        sys.exit(0)

    # Activate profile if specified
    if args.profile:
        set_active_profile(args.profile)

    # Setup logging first
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    # Resolve paths using config system
    credentials_path = get_credentials_path(args.credentials)
    output_dir = get_output_dir()

    # Determine output file
    if args.output:
        output_file = Path(args.output)
    else:
        output_file = output_dir / "duplicates.csv"

    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Authenticating with Google Drive...")
    creds = authenticate(credentials_path)
    service = build("drive", "v3", credentials=creds)

    # Validate-only mode: test credentials and exit
    if args.validate:
        try:
            about = service.about().get(fields="user(displayName, emailAddress)").execute()
            user = about.get("user", {})
            email = user.get("emailAddress", "unknown")
            name = user.get("displayName", "")
            logger.info(f"Credentials valid. Connected as: {name} <{email}>")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Credential validation failed: {e}")
            sys.exit(1)

    logger.info("Fetching files from Google Drive...")
    files = fetch_all_files(service)
    logger.info(f"Found {len(files)} items total")

    logger.info("Building path index...")
    files_by_id, path_cache = build_lookups(files)

    if args.path:
        logger.info(f"Filtering to path: {args.path}")
        files = filter_by_path(files, args.path, files_by_id, path_cache)
        logger.info(f"Filtered to {len(files)} items")

    # Combine exclude paths from CLI args, config file, and env var
    exclude_paths = get_exclude_paths(args.exclude)
    if exclude_paths:
        logger.info(f"Excluding paths: {exclude_paths}")
        files = filter_excluded_paths(files, exclude_paths, files_by_id, path_cache)
        logger.info(f"After exclusions: {len(files)} items")

    logger.info("Finding duplicates...")
    duplicates, skipped = find_duplicates(files)

    if skipped > 0:
        logger.info(f"Skipped {skipped} Google Workspace files (Docs, Sheets, etc. - no MD5)")

    dup_count = sum(len(d["files"]) for d in duplicates)
    uncertain_count = sum(1 for d in duplicates if d["uncertain"])

    logger.info(f"Found {len(duplicates)} duplicate groups ({dup_count} files)")
    if uncertain_count > 0:
        logger.info(f"  {uncertain_count} groups flagged as uncertain (same MD5, different size)")

    logger.info(f"Writing results to {output_file}...")
    write_csv(duplicates, str(output_file), files_by_id, path_cache)

    savings = calculate_savings(duplicates)
    logger.info(f"")
    logger.info(f"Scan complete:")
    logger.info(f"  Total files scanned: {len(files):,}")
    logger.info(f"  Duplicate groups: {len(duplicates):,}")
    logger.info(f"  Total duplicate files: {dup_count:,}")
    logger.info(f"  Potential space savings: {format_size(savings)}")
    logger.info(f"  Output: {output_file}")


if __name__ == "__main__":
    main()
