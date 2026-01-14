#!/usr/bin/env python3
"""Google Drive Deduplication Tool - Find duplicate files using MD5 checksums."""

import argparse
import csv
import logging
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from config import get_exclude_paths, get_credentials_path, get_token_path, get_output_dir

# Setup logging
logger = logging.getLogger(__name__)

SCOPES = [
    "https://www.googleapis.com/auth/drive",  # Full access for move operations
]


def setup_logging(verbose: bool = False, log_file: str = None):
    """Configure logging for the application.

    Args:
        verbose: If True, set level to DEBUG; otherwise INFO.
        log_file: Optional path to write logs to a file.
    """
    level = logging.DEBUG if verbose else logging.INFO
    format_str = "%(asctime)s [%(levelname)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format=format_str,
        datefmt=date_format,
        handlers=handlers,
    )


def authenticate(credentials_path: Path) -> Credentials:
    """Handle OAuth authentication flow.

    Args:
        credentials_path: Path to the OAuth credentials JSON file.

    Returns:
        Valid Google OAuth credentials.

    Raises:
        SystemExit: If credentials file is missing.
    """
    creds = None
    token_path = get_token_path(credentials_path)

    if token_path.exists():
        logger.debug(f"Loading existing token from {token_path}")
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                logger.debug("Refreshing expired token")
                creds.refresh(Request())
            except RefreshError as e:
                logger.error(f"Failed to refresh OAuth token: {e}")
                logger.error("")
                logger.error("Your token may have been revoked or expired.")
                logger.error(f"Delete {token_path} and re-authenticate.")
                sys.exit(1)
        else:
            if not credentials_path.exists():
                logger.error(f"OAuth credentials not found at {credentials_path}")
                logger.error("")
                logger.error("To fix this:")
                logger.error("  1. Go to https://console.cloud.google.com/apis/credentials")
                logger.error("  2. Create a project (if you haven't already)")
                logger.error("  3. Enable the Google Drive API")
                logger.error("  4. Create OAuth 2.0 Client ID (choose 'Desktop app')")
                logger.error("  5. Download the JSON file")
                logger.error(f"  6. Save it as: {credentials_path}")
                logger.error("")
                logger.error("Or set GDRIVE_CREDENTIALS_PATH to use a different location.")
                sys.exit(1)

            logger.info("Starting OAuth flow (browser will open)...")
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), SCOPES)
            creds = flow.run_local_server(port=0)

        # Ensure token directory exists
        token_path.parent.mkdir(parents=True, exist_ok=True)

        with open(token_path, "w") as token:
            token.write(creds.to_json())

        # Set restrictive permissions (owner read/write only)
        os.chmod(token_path, 0o600)
        logger.debug(f"Token saved to {token_path}")

    return creds


def fetch_with_retry(service, **kwargs) -> dict:
    """Fetch with exponential backoff for rate limits."""
    max_retries = 5
    last_error = None

    for attempt in range(max_retries):
        try:
            return service.files().list(**kwargs).execute()
        except HttpError as e:
            last_error = e
            if e.resp.status == 401:
                logger.error("Authentication failed. Your token may have expired.")
                logger.error("Delete token.json and re-authenticate.")
                raise
            elif e.resp.status == 403:
                if "rate" in str(e).lower():
                    wait_time = 2**attempt
                    logger.warning(f"Rate limited, waiting {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    logger.error("Access denied. Check that you have permission to access Google Drive.")
                    raise
            elif e.resp.status == 429:
                wait_time = 2**attempt
                logger.warning(f"Rate limited, waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise

    raise HttpError(last_error.resp, last_error.content, "Max retries exceeded due to rate limiting")


def fetch_all_files(service) -> list[dict]:
    """Fetch all files from My Drive and Shared with me, with pagination."""
    all_files = []
    page_token = None
    page_count = 0

    fields = "nextPageToken, files(id, name, md5Checksum, size, parents, createdTime, modifiedTime, mimeType)"
    query = "trashed = false"

    while True:
        page_count += 1
        response = fetch_with_retry(
            service,
            q=query,
            pageSize=1000,
            fields=fields,
            pageToken=page_token,
            includeItemsFromAllDrives=False,
            supportsAllDrives=False,
        )

        files = response.get("files", [])
        all_files.extend(files)
        logger.info(f"  Page {page_count}: fetched {len(files)} items (total: {len(all_files)})")

        page_token = response.get("nextPageToken")
        if not page_token:
            break

    return all_files


def build_lookups(files: list[dict]) -> tuple[dict[str, dict], dict[str, str]]:
    """Build file ID lookup and initialize path cache."""
    files_by_id = {f["id"]: f for f in files}
    path_cache = {}
    return files_by_id, path_cache


def get_path(file_id: str, files_by_id: dict[str, dict], path_cache: dict[str, str]) -> str:
    """Recursively build full path for a file with memoization."""
    if file_id in path_cache:
        return path_cache[file_id]

    if file_id not in files_by_id:
        path_cache[file_id] = ""
        return ""

    file = files_by_id[file_id]
    parents = file.get("parents", [])

    if not parents:
        path = "/" + file["name"]
    else:
        parent_path = get_path(parents[0], files_by_id, path_cache)
        if parent_path:
            path = parent_path + "/" + file["name"]
        else:
            path = "/" + file["name"]

    path_cache[file_id] = path
    return path


def filter_by_path(
    files: list[dict], target_path: str, files_by_id: dict[str, dict], path_cache: dict[str, str]
) -> list[dict]:
    """Filter files whose paths start with target_path."""
    target_path = target_path.rstrip("/")
    result = []
    for file in files:
        path = get_path(file["id"], files_by_id, path_cache)
        if path.startswith(target_path + "/") or path == target_path:
            result.append(file)
    return result


def filter_excluded_paths(
    files: list[dict],
    exclude_paths: list[str],
    files_by_id: dict[str, dict],
    path_cache: dict[str, str],
) -> list[dict]:
    """Filter out files whose paths match any of the exclude patterns.

    Args:
        files: List of file dicts to filter
        exclude_paths: List of paths to exclude (e.g., ["/Backup/Old", "/tmp"])
        files_by_id: Lookup dict for file IDs
        path_cache: Cache for resolved paths

    Returns:
        Files that don't match any exclude path.
    """
    if not exclude_paths:
        return files

    # Normalize exclude paths
    normalized_excludes = []
    for ep in exclude_paths:
        ep = ep.rstrip("/")
        if ep:
            normalized_excludes.append(ep)

    result = []
    excluded_count = 0
    for file in files:
        path = get_path(file["id"], files_by_id, path_cache)
        excluded = False
        for exclude in normalized_excludes:
            if path.startswith(exclude + "/") or path == exclude:
                excluded = True
                excluded_count += 1
                break
        if not excluded:
            result.append(file)

    if excluded_count > 0:
        logger.info(f"Excluded {excluded_count} files matching exclude patterns")

    return result


def find_duplicates(files: list[dict]) -> tuple[list[dict], int]:
    """Group files by MD5 and identify duplicates."""
    files_by_md5 = defaultdict(list)
    skipped_count = 0

    for file in files:
        mime_type = file.get("mimeType", "")
        if mime_type.startswith("application/vnd.google-apps."):
            skipped_count += 1
            continue
        if mime_type == "application/vnd.google-apps.folder":
            continue

        md5 = file.get("md5Checksum")
        if md5:
            files_by_md5[md5].append(file)

    duplicates = []
    for md5, file_list in files_by_md5.items():
        if len(file_list) > 1:
            sizes = {f.get("size") for f in file_list}
            uncertain = len(sizes) > 1
            duplicates.append({"md5": md5, "files": file_list, "uncertain": uncertain})

    return duplicates, skipped_count


def write_csv(
    duplicates: list[dict],
    output_file: str,
    files_by_id: dict[str, dict],
    path_cache: dict[str, str],
):
    """Write duplicates to CSV file."""
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["filename", "path1", "path2", "date1", "date2", "md5", "size", "status"]
        )

        for dup in duplicates:
            file_list = dup["files"]
            md5 = dup["md5"]
            status = "uncertain" if dup["uncertain"] else "duplicate"

            for i, file1 in enumerate(file_list):
                for file2 in file_list[i + 1 :]:
                    writer.writerow(
                        [
                            file1["name"],
                            get_path(file1["id"], files_by_id, path_cache),
                            get_path(file2["id"], files_by_id, path_cache),
                            file1.get("modifiedTime", ""),
                            file2.get("modifiedTime", ""),
                            md5,
                            file1.get("size", "N/A"),
                            status,
                        ]
                    )


def calculate_savings(duplicates: list[dict]) -> int:
    """Calculate potential space savings by keeping one copy of each duplicate."""
    total_savings = 0

    for dup in duplicates:
        if dup["uncertain"]:
            continue

        file_list = dup["files"]
        sizes = [int(f.get("size", 0)) for f in file_list]

        if sizes:
            total_savings += sum(sizes) - max(sizes)

    return total_savings


def format_size(size_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"


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
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--log-file",
        help="Write logs to file (in addition to console)",
    )
    args = parser.parse_args()

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
