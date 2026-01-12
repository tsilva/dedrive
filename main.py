#!/usr/bin/env python3
"""Google Drive Deduplication Tool - Find duplicate files using MD5 checksums."""

import argparse
import csv
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from config import get_exclude_paths

SCOPES = [
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
]
TOKEN_FILE = "token.json"
CREDENTIALS_FILE = "credentials.json"


def authenticate(credentials_file: str) -> Credentials:
    """Handle OAuth authentication flow."""
    creds = None
    token_path = Path(credentials_file).parent / TOKEN_FILE

    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not Path(credentials_file).exists():
                print(f"Error: {credentials_file} not found.")
                print("Download OAuth credentials from Google Cloud Console:")
                print("  1. Go to https://console.cloud.google.com/apis/credentials")
                print("  2. Create OAuth 2.0 Client ID (Desktop app)")
                print("  3. Download JSON and save as credentials.json")
                sys.exit(1)

            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)

        with open(token_path, "w") as token:
            token.write(creds.to_json())

    return creds


def fetch_with_retry(service, **kwargs) -> dict:
    """Fetch with exponential backoff for rate limits."""
    max_retries = 5
    for attempt in range(max_retries):
        try:
            return service.files().list(**kwargs).execute()
        except HttpError as e:
            if e.resp.status in (429, 403) and "rate" in str(e).lower():
                wait_time = 2**attempt
                print(f"Rate limited, waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise
    raise Exception("Max retries exceeded due to rate limiting")


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
        print(f"  Page {page_count}: fetched {len(files)} items (total: {len(all_files)})")

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
        print(f"Excluded {excluded_count} files matching exclude patterns")

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
        "--output", "-o", default=".output/duplicates.csv", help="Output CSV file"
    )
    parser.add_argument(
        "--credentials",
        "-c",
        default=CREDENTIALS_FILE,
        help="OAuth credentials file",
    )
    args = parser.parse_args()

    print("Authenticating with Google Drive...")
    creds = authenticate(args.credentials)
    service = build("drive", "v3", credentials=creds)

    print("Fetching files from Google Drive...")
    files = fetch_all_files(service)
    print(f"Found {len(files)} items total")

    print("Building path index...")
    files_by_id, path_cache = build_lookups(files)

    if args.path:
        print(f"Filtering to path: {args.path}")
        files = filter_by_path(files, args.path, files_by_id, path_cache)
        print(f"Filtered to {len(files)} items")

    # Combine exclude paths from CLI args, config file, and env var
    exclude_paths = list(args.exclude) + get_exclude_paths()
    if exclude_paths:
        print(f"Excluding paths: {exclude_paths}")
        files = filter_excluded_paths(files, exclude_paths, files_by_id, path_cache)
        print(f"After exclusions: {len(files)} items")

    print("Finding duplicates...")
    duplicates, skipped = find_duplicates(files)

    if skipped > 0:
        print(f"Skipped {skipped} Google Workspace files (Docs, Sheets, etc. - no MD5)")

    dup_count = sum(len(d["files"]) for d in duplicates)
    uncertain_count = sum(1 for d in duplicates if d["uncertain"])

    print(f"Found {len(duplicates)} duplicate groups ({dup_count} files)")
    if uncertain_count > 0:
        print(f"  {uncertain_count} groups flagged as uncertain (same MD5, different size)")

    print(f"Writing results to {args.output}...")
    write_csv(duplicates, args.output, files_by_id, path_cache)

    savings = calculate_savings(duplicates)
    print(f"\nPotential space savings: {format_size(savings)}")
    print("Done!")


if __name__ == "__main__":
    main()
