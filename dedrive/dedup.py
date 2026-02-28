"""Duplicate detection, filtering, and formatting."""

import csv
import logging
from collections import defaultdict

from dedrive.drive import get_path

# Setup logging
logger = logging.getLogger(__name__)


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
