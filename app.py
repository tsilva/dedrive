#!/usr/bin/env python3
"""Gradio-based Google Drive Deduplication Manager."""

import io
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import gradio as gr
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

# Import from main.py
from main import (
    SCOPES,
    authenticate,
    fetch_all_files,
    build_lookups,
    get_path,
    find_duplicates,
    calculate_savings,
    format_size,
    filter_by_path,
    filter_excluded_paths,
)
from config import (
    get_exclude_paths,
    get_credentials_path,
    get_output_dir,
    get_dupes_folder,
    get_batch_size,
    get_max_preview_size,
)

# Derived paths (computed at runtime from config)
def get_output_paths():
    """Get output directory paths from config."""
    output_dir = get_output_dir()
    return {
        "output_dir": output_dir,
        "preview_cache": output_dir / "preview_cache",
        "decisions_file": output_dir / "decisions.json",
        "scan_results_file": output_dir / "scan_results.json",
        "execution_log_file": output_dir / "execution_log.json",
    }


@dataclass
class FileInfo:
    """File information for display."""
    id: str
    name: str
    path: str
    size: int
    modified_time: str
    mime_type: str


@dataclass
class DuplicateGroup:
    """A group of duplicate files sharing the same MD5."""
    md5: str
    files: list[FileInfo]
    uncertain: bool


@dataclass
class Decision:
    """A decision made for a duplicate group."""
    md5: str
    action: str  # "keep_specific", "skip"
    keep_file_id: Optional[str] = None
    delete_file_ids: list[str] = field(default_factory=list)
    decided_at: str = ""


@dataclass
class AppState:
    """Application state."""
    # Google Drive service
    service: object = None

    # Scan data
    all_files: list[dict] = field(default_factory=list)
    files_by_id: dict = field(default_factory=dict)
    path_cache: dict = field(default_factory=dict)
    duplicate_groups: list[DuplicateGroup] = field(default_factory=list)

    # Navigation
    current_index: int = 0
    filtered_indices: list[int] = field(default_factory=list)
    filter_status: str = "pending"
    search_term: str = ""

    # Decisions
    decisions: dict[str, Decision] = field(default_factory=dict)


# Global state
state = AppState()


def ensure_dirs():
    """Ensure output directories exist."""
    paths = get_output_paths()
    paths["output_dir"].mkdir(parents=True, exist_ok=True)
    paths["preview_cache"].mkdir(parents=True, exist_ok=True)


def load_decisions() -> dict[str, Decision]:
    """Load decisions from JSON file."""
    decisions_file = get_output_paths()["decisions_file"]

    if not decisions_file.exists():
        return {}

    try:
        with open(decisions_file) as f:
            data = json.load(f)

        decisions = {}
        for md5, d in data.get("decisions", {}).items():
            decisions[md5] = Decision(
                md5=d["md5"],
                action=d["action"],
                keep_file_id=d.get("keep_file_id"),
                delete_file_ids=d.get("delete_file_ids", []),
                decided_at=d.get("decided_at", ""),
            )
        return decisions
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in decisions file: {e}")
        return {}
    except Exception as e:
        print(f"Error loading decisions: {e}")
        return {}


def save_decisions(decisions: dict[str, Decision], scan_info: dict = None):
    """Save decisions to JSON file."""
    ensure_dirs()
    decisions_file = get_output_paths()["decisions_file"]

    # Calculate statistics
    decided = sum(1 for d in decisions.values() if d.action != "skip")
    skipped = sum(1 for d in decisions.values() if d.action == "skip")
    files_to_delete = sum(len(d.delete_file_ids) for d in decisions.values() if d.action != "skip")

    data = {
        "version": "1.0",
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "scan_info": scan_info or {},
        "statistics": {
            "decided": decided,
            "skipped": skipped,
            "pending": len(state.duplicate_groups) - len(decisions),
            "files_to_delete": files_to_delete,
        },
        "decisions": {md5: asdict(d) for md5, d in decisions.items()},
    }

    with open(decisions_file, "w") as f:
        json.dump(data, f, indent=2)


def save_scan_results(duplicate_groups: list[DuplicateGroup], all_files: list[dict], scan_path: str = None):
    """Save scan results to JSON file for reuse across sessions."""
    ensure_dirs()
    scan_results_file = get_output_paths()["scan_results_file"]

    data = {
        "version": "1.0",
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "scan_path": scan_path,
        "total_files": len(all_files),
        "duplicate_groups": [
            {
                "md5": g.md5,
                "uncertain": g.uncertain,
                "files": [asdict(f) for f in g.files],
            }
            for g in duplicate_groups
        ],
        "files_by_id": {f["id"]: f for f in all_files},
    }

    with open(scan_results_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Scan results saved to {scan_results_file}")


def load_scan_results() -> bool:
    """Load scan results from JSON file. Returns True if loaded successfully."""
    scan_results_file = get_output_paths()["scan_results_file"]

    if not scan_results_file.exists():
        return False

    try:
        with open(scan_results_file) as f:
            data = json.load(f)

        # Restore duplicate groups
        state.duplicate_groups = []
        for g in data.get("duplicate_groups", []):
            files = [FileInfo(**f) for f in g["files"]]
            state.duplicate_groups.append(DuplicateGroup(
                md5=g["md5"],
                files=files,
                uncertain=g["uncertain"],
            ))

        # Restore files_by_id for preview downloads
        state.files_by_id = data.get("files_by_id", {})
        state.all_files = list(state.files_by_id.values())
        state.path_cache = {}  # Will be rebuilt as needed

        # Apply default filter
        state.filter_status = "pending"
        state.search_term = ""
        state.current_index = 0
        apply_filter()

        print(f"Loaded {len(state.duplicate_groups)} duplicate groups from {scan_results_file}")
        return True

    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in scan results file: {e}")
        return False
    except Exception as e:
        print(f"Error loading scan results: {e}")
        return False


def convert_to_file_info(file_dict: dict, files_by_id: dict, path_cache: dict) -> FileInfo:
    """Convert raw file dict to FileInfo."""
    return FileInfo(
        id=file_dict["id"],
        name=file_dict["name"],
        path=get_path(file_dict["id"], files_by_id, path_cache),
        size=int(file_dict.get("size", 0)),
        modified_time=file_dict.get("modifiedTime", ""),
        mime_type=file_dict.get("mimeType", ""),
    )


def apply_filter():
    """Apply current filter to duplicate groups."""
    state.filtered_indices = []

    for i, group in enumerate(state.duplicate_groups):
        # Status filter
        decision = state.decisions.get(group.md5)

        if state.filter_status == "pending" and decision is not None:
            continue
        elif state.filter_status == "decided" and (decision is None or decision.action == "skip"):
            continue
        elif state.filter_status == "skipped" and (decision is None or decision.action != "skip"):
            continue

        # Search filter
        if state.search_term:
            term = state.search_term.lower()
            match = any(
                term in f.path.lower() or term in f.name.lower()
                for f in group.files
            )
            if not match:
                continue

        state.filtered_indices.append(i)

    # Reset to first item if current is out of bounds
    if state.current_index >= len(state.filtered_indices):
        state.current_index = 0


def get_current_group() -> Optional[DuplicateGroup]:
    """Get the current duplicate group based on navigation."""
    if not state.filtered_indices:
        return None
    if state.current_index >= len(state.filtered_indices):
        return None
    idx = state.filtered_indices[state.current_index]
    return state.duplicate_groups[idx]


def ensure_service():
    """Ensure Google Drive service is authenticated."""
    if state.service:
        return True
    try:
        credentials_path = get_credentials_path()
        creds = authenticate(credentials_path)
        state.service = build("drive", "v3", credentials=creds)
        return True
    except SystemExit:
        # authenticate() calls sys.exit on missing credentials
        return False
    except FileNotFoundError as e:
        print(f"Credentials file not found: {e}")
        return False
    except PermissionError as e:
        print(f"Cannot read credentials file: {e}")
        return False
    except Exception as e:
        print(f"Authentication failed: {type(e).__name__}: {e}")
        return False


def download_file(file_id: str) -> Optional[Path]:
    """Download a file from Google Drive and cache it."""
    from googleapiclient.errors import HttpError

    # Check cache first (before authentication)
    cache_path = get_output_paths()["preview_cache"] / file_id
    if cache_path.exists():
        return cache_path

    # Ensure we're authenticated
    if not ensure_service():
        return None

    try:
        request = state.service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)

        done = False
        while not done:
            _, done = downloader.next_chunk()

        ensure_dirs()
        cache_path.write_bytes(fh.getvalue())
        return cache_path
    except HttpError as e:
        if e.resp.status == 404:
            print(f"File not found: {file_id}")
        elif e.resp.status == 403:
            print(f"Access denied to file: {file_id}")
        else:
            print(f"HTTP error downloading file {file_id}: {e.resp.status}")
        return None
    except IOError as e:
        print(f"Error saving file to cache: {e}")
        return None
    except Exception as e:
        print(f"Error downloading file {file_id}: {type(e).__name__}: {e}")
        return None


def get_preview(file_info: FileInfo) -> tuple[str, any]:
    """Get preview for a file. Returns (type, content)."""
    max_preview_size = get_max_preview_size()
    if file_info.size > max_preview_size:
        return ("text", f"File too large for preview ({format_size(file_info.size)})")

    mime = file_info.mime_type

    # Download file
    cache_path = download_file(file_info.id)
    if not cache_path:
        return ("text", "Failed to download file for preview")

    try:
        if mime.startswith("image/"):
            return ("image", str(cache_path))

        elif mime == "application/pdf":
            # Try to convert PDF to image
            try:
                from pdf2image import convert_from_path
                preview_path = cache_path.with_suffix(".preview.png")
                if not preview_path.exists():
                    images = convert_from_path(str(cache_path), first_page=1, last_page=1, dpi=150)
                    if images:
                        images[0].save(str(preview_path), "PNG")
                if preview_path.exists():
                    return ("image", str(preview_path))
                else:
                    return ("text", "PDF preview failed - install poppler: brew install poppler")
            except ImportError:
                return ("text", "PDF preview requires pdf2image and poppler")
            except Exception as e:
                return ("text", f"PDF preview error: {e}")

        elif mime.startswith("text/") or mime in ("application/json", "application/xml", "application/javascript"):
            content = cache_path.read_text(errors="replace")[:5000]
            return ("code", content)

        elif mime.startswith("video/"):
            return ("video", str(cache_path))

        else:
            return ("text", f"Preview not available for {mime}")

    except Exception as e:
        return ("text", f"Preview error: {e}")


# =============================================================================
# Scan Tab Functions
# =============================================================================

def run_scan(path_filter: str, progress=gr.Progress()):
    """Run the duplicate scan."""
    from googleapiclient.errors import HttpError

    ensure_dirs()

    progress(0, desc="Authenticating...")
    try:
        credentials_path = get_credentials_path()
        creds = authenticate(credentials_path)
        state.service = build("drive", "v3", credentials=creds)
    except SystemExit:
        return "Authentication failed: credentials.json not found. See terminal for setup instructions.", "", ""
    except FileNotFoundError:
        return "Authentication failed: credentials file not found.", "", ""
    except Exception as e:
        return f"Authentication failed: {type(e).__name__}: {e}", "", ""

    progress(0.1, desc="Fetching files from Google Drive...")
    try:
        state.all_files = fetch_all_files(state.service)
    except HttpError as e:
        if e.resp.status == 401:
            return "Session expired. Delete token.json and restart.", "", ""
        elif e.resp.status == 403:
            return "Access denied. Check your Google Drive permissions.", "", ""
        return f"Google Drive API error: {e.resp.status} - {e.error_details}", "", ""
    except Exception as e:
        return f"Failed to fetch files: {type(e).__name__}: {e}", "", ""

    progress(0.5, desc="Building path index...")
    state.files_by_id, state.path_cache = build_lookups(state.all_files)

    # Filter by path if specified
    files_to_scan = state.all_files
    if path_filter and path_filter.strip():
        progress(0.6, desc=f"Filtering to path: {path_filter}")
        files_to_scan = filter_by_path(files_to_scan, path_filter.strip(), state.files_by_id, state.path_cache)

    # Apply exclude paths from config file and env var
    exclude_paths = get_exclude_paths()
    if exclude_paths:
        progress(0.65, desc=f"Applying {len(exclude_paths)} exclude path(s)...")
        files_to_scan = filter_excluded_paths(files_to_scan, exclude_paths, state.files_by_id, state.path_cache)

    progress(0.7, desc="Finding duplicates...")
    raw_duplicates, skipped = find_duplicates(files_to_scan)

    # Convert to DuplicateGroup objects
    state.duplicate_groups = []
    for dup in raw_duplicates:
        files = [convert_to_file_info(f, state.files_by_id, state.path_cache) for f in dup["files"]]
        state.duplicate_groups.append(DuplicateGroup(
            md5=dup["md5"],
            files=files,
            uncertain=dup["uncertain"],
        ))

    progress(0.9, desc="Loading existing decisions...")
    state.decisions = load_decisions()

    # Apply filter
    state.filter_status = "pending"
    state.search_term = ""
    apply_filter()

    # Save scan results for reuse
    progress(0.95, desc="Saving scan results...")
    save_scan_results(state.duplicate_groups, state.all_files, path_filter.strip() if path_filter else None)

    progress(1.0, desc="Done!")

    # Calculate stats
    total_files = len(files_to_scan)
    total_groups = len(state.duplicate_groups)
    total_pairs = sum(len(g.files) * (len(g.files) - 1) // 2 for g in state.duplicate_groups)
    savings = calculate_savings(raw_duplicates)
    uncertain = sum(1 for g in state.duplicate_groups if g.uncertain)

    status = f"Scan complete! Found {total_files:,} files."

    # Build exclude paths info for summary
    exclude_info = ""
    if exclude_paths:
        exclude_list = ", ".join([f"`{p}`" for p in exclude_paths])
        exclude_info = f"\n- **Excluded paths:** {exclude_list}"

    summary = f"""### Results Summary

- **Total files scanned:** {total_files:,}
- **Duplicate groups:** {total_groups:,}
- **Duplicate pairs:** {total_pairs:,}
- **Uncertain groups:** {uncertain:,} (same MD5, different size)
- **Potential savings:** {format_size(savings)}
- **Skipped:** {skipped:,} Google Workspace files (no MD5){exclude_info}
"""

    decided = len(state.decisions)
    pending = total_groups - decided
    decisions_info = f"**Decisions loaded:** {decided:,} | **Pending:** {pending:,}"

    return status, summary, decisions_info


# =============================================================================
# Review Tab Functions
# =============================================================================

def format_file_metadata(file_info: FileInfo) -> str:
    """Format file metadata as markdown."""
    return f"""**Name:** {file_info.name}

**Path:** `{file_info.path}`

**Size:** {format_size(file_info.size)}

**Modified:** {file_info.modified_time[:19].replace('T', ' ') if file_info.modified_time else 'N/A'}

**Type:** {file_info.mime_type}

**ID:** `{file_info.id[:20]}...`
"""


def get_drive_link(file_id: str) -> str:
    """Get Google Drive link for a file."""
    return f"https://drive.google.com/file/d/{file_id}/view"


def format_preview_outputs(preview_type: str, preview_content: str):
    """Format preview outputs for image and code components."""
    if preview_type == "image":
        return (
            gr.update(value=preview_content, visible=True),  # image
            gr.update(value="", visible=False),  # code
        )
    elif preview_type in ("text", "code"):
        return (
            gr.update(value=None, visible=False),  # image
            gr.update(value=preview_content[:2000], visible=True),  # code
        )
    else:
        # No preview available
        return (
            gr.update(value=None, visible=False),  # image
            gr.update(value=preview_content if preview_content else "No preview available", visible=True),  # code
        )


def update_review_display():
    """Update the review display with current group."""
    group = get_current_group()

    if not group:
        empty_state = "No duplicates to review."
        return (
            empty_state,  # header
            "", "",  # paths
            gr.update(value=None, visible=False), gr.update(value="", visible=False),  # preview A (img, code)
            gr.update(value=None, visible=False), gr.update(value="", visible=False),  # preview B (img, code)
            "", "",  # metadata
            "", "",  # links
            gr.update(interactive=False),  # keep left
            gr.update(interactive=False),  # keep right
            gr.update(visible=False, choices=[("None", "none")], value="none"),  # multi-file selector
        )

    # Check if this group has a decision
    decision = state.decisions.get(group.md5)
    decision_text = ""
    if decision:
        if decision.action == "skip":
            decision_text = " [SKIPPED]"
        else:
            kept_id = decision.keep_file_id
            kept_file = next((f for f in group.files if f.id == kept_id), None)
            if kept_file:
                decision_text = f" [KEEPING: {kept_file.name}]"

    # Header
    position = state.current_index + 1
    total = len(state.filtered_indices)
    header = f"### Group {position:,} of {total:,} | MD5: `{group.md5[:16]}...` | {len(group.files)} files{decision_text}"
    if group.uncertain:
        header += "\n\n**Warning:** Same MD5 but different sizes - review carefully!"

    # For groups with 2 files, show side-by-side
    if len(group.files) == 2:
        file_a, file_b = group.files[0], group.files[1]

        # Get previews
        preview_a_type, preview_a_content = get_preview(file_a)
        preview_b_type, preview_b_content = get_preview(file_b)

        # Format preview outputs (image and code for each side)
        preview_img_a, preview_code_a = format_preview_outputs(preview_a_type, preview_a_content)
        preview_img_b, preview_code_b = format_preview_outputs(preview_b_type, preview_b_content)

        meta_a = format_file_metadata(file_a)
        meta_b = format_file_metadata(file_b)

        link_a = get_drive_link(file_a.id)
        link_b = get_drive_link(file_b.id)

        return (
            header,
            file_a.path, file_b.path,  # paths
            preview_img_a, preview_code_a,  # preview A
            preview_img_b, preview_code_b,  # preview B
            meta_a, meta_b,
            link_a, link_b,
            gr.update(interactive=True),  # keep left
            gr.update(interactive=True),  # keep right
            gr.update(visible=False, choices=[("None", "none")], value="none"),  # multi-file selector
        )

    # For groups with 3+ files, show selector on right side
    else:
        choices = [(f.path, f.id) for f in group.files]

        # Default selected file (first one)
        selected_file = group.files[0]
        preview_type, preview_content = get_preview(selected_file)
        preview_img_b, preview_code_b = format_preview_outputs(preview_type, preview_content)

        # Left side: show all files in the group
        all_files_list = "\n".join([f"- `{f.path}`" for f in group.files])
        meta_a = f"**All duplicate files ({len(group.files)}):**\n\n{all_files_list}"

        # Right side: preview of selected file
        meta_b = format_file_metadata(selected_file)
        link_b = get_drive_link(selected_file.id)

        return (
            header,
            f"Select file to keep →", selected_file.path,  # paths
            gr.update(value=None, visible=False), gr.update(value="", visible=False),  # preview A (hidden)
            preview_img_b, preview_code_b,  # preview B (selected file)
            meta_a, meta_b,
            "", link_b,
            gr.update(interactive=False),  # keep left (disabled for multi)
            gr.update(interactive=True),  # keep right (keeps selected)
            gr.update(visible=True, choices=choices, value=choices[0][1] if choices else "none"),  # multi-file selector
        )


def on_search(search: str):
    """Handle search changes. Always filters to pending (undecided) items."""
    state.filter_status = "pending"
    state.search_term = search
    state.current_index = 0
    apply_filter()
    return update_review_display()


def on_navigate(direction: str):
    """Navigate to next/previous group."""
    if direction == "next" and state.current_index < len(state.filtered_indices) - 1:
        state.current_index += 1
    elif direction == "prev" and state.current_index > 0:
        state.current_index -= 1
    return update_review_display()


def on_jump_to(index: int):
    """Jump to specific index."""
    if 1 <= index <= len(state.filtered_indices):
        state.current_index = index - 1
    return update_review_display()


def make_decision(action: str, keep_file_id: str = None):
    """Record a decision for the current group."""
    group = get_current_group()
    if not group:
        return update_review_display()

    if action == "skip":
        decision = Decision(
            md5=group.md5,
            action="skip",
            decided_at=datetime.utcnow().isoformat() + "Z",
        )
    else:
        # Determine which file to keep
        if action == "keep_left":
            keep_id = group.files[0].id
        elif action == "keep_right":
            keep_id = group.files[1].id
        else:  # keep_specific
            keep_id = keep_file_id

        delete_ids = [f.id for f in group.files if f.id != keep_id]

        decision = Decision(
            md5=group.md5,
            action="keep_specific",
            keep_file_id=keep_id,
            delete_file_ids=delete_ids,
            decided_at=datetime.utcnow().isoformat() + "Z",
        )

    state.decisions[group.md5] = decision
    save_decisions(state.decisions)

    # Auto-advance to next
    if state.current_index < len(state.filtered_indices) - 1:
        state.current_index += 1

    return update_review_display()


def on_keep_left():
    return make_decision("keep_left")


def on_keep_right(selected_id: str = None):
    """Keep the right file. For multi-file groups, uses the selected ID from dropdown."""
    group = get_current_group()
    if not group:
        return update_review_display()

    # For multi-file groups, use the selected ID; otherwise use files[1]
    if len(group.files) > 2 and selected_id:
        return make_decision("keep_specific", selected_id)
    else:
        return make_decision("keep_right")


def on_multi_file_select(selected_id: str):
    """Update preview when a file is selected in multi-file mode (shown on right/B side)."""
    group = get_current_group()
    if not group or not selected_id:
        return "", gr.update(value=None, visible=False), gr.update(value="", visible=False), ""

    selected_file = next((f for f in group.files if f.id == selected_id), None)
    if not selected_file:
        return "", gr.update(value=None, visible=False), gr.update(value="", visible=False), ""

    preview_type, preview_content = get_preview(selected_file)
    preview_img, preview_code = format_preview_outputs(preview_type, preview_content)

    meta = format_file_metadata(selected_file)

    return selected_file.path, preview_img, preview_code, meta


def get_stats_display():
    """Get statistics display for review tab."""
    total = len(state.duplicate_groups)
    decided = len(state.decisions)
    pending = total - decided

    return f"**Pending:** {pending:,} | **Decided:** {decided:,} | **Total:** {total:,}"


# =============================================================================
# Export Tab Functions
# =============================================================================

def get_export_summary():
    """Get summary of decisions for export tab."""
    if not state.duplicate_groups:
        return "No scan data. Run a scan first.", "", []

    decided = [d for d in state.decisions.values() if d.action != "skip"]
    skipped = [d for d in state.decisions.values() if d.action == "skip"]

    # Calculate space to recover
    total_delete_size = 0
    delete_files = []

    for decision in decided:
        for file_id in decision.delete_file_ids:
            if file_id in state.files_by_id:
                file = state.files_by_id[file_id]
                size = int(file.get("size", 0))
                total_delete_size += size
                path = get_path(file_id, state.files_by_id, state.path_cache)
                delete_files.append({
                    "id": file_id,
                    "name": file["name"],
                    "path": path,
                    "size": size,
                })

    summary = f"""### Decision Summary

- **Groups with decisions:** {len(decided):,}
- **Groups skipped:** {len(skipped):,}
- **Groups pending:** {len(state.duplicate_groups) - len(state.decisions):,}
- **Files to delete:** {len(delete_files):,}
- **Space to recover:** {format_size(total_delete_size)}
"""

    # Preview of files to delete
    preview_lines = []
    for f in delete_files[:50]:
        preview_lines.append(f"DELETE: `{f['path']}` ({format_size(f['size'])})")

    if len(delete_files) > 50:
        preview_lines.append(f"\n... and {len(delete_files) - 50} more files")

    preview = "\n".join(preview_lines) if preview_lines else "No files marked for deletion."

    return summary, preview, delete_files


def export_decisions():
    """Export decisions and return the file path."""
    if not state.decisions:
        return "No decisions to export.", None

    decisions_file = get_output_paths()["decisions_file"]
    scan_info = {
        "total_files": len(state.all_files),
        "duplicate_groups": len(state.duplicate_groups),
    }
    save_decisions(state.decisions, scan_info)

    return f"Decisions exported to: `{decisions_file}`", str(decisions_file)


# =============================================================================
# Move to _dupes Functions
# =============================================================================

def get_or_create_dupes_folder(service) -> str:
    """Get or create the root dupes folder. Returns folder ID."""
    dupes_folder = get_dupes_folder()
    # Remove leading slash if present
    folder_name = dupes_folder.lstrip("/")

    # Search for existing dupes folder at root
    escaped_name = folder_name.replace("\\", "\\\\").replace("'", "\\'")
    query = f"name = '{escaped_name}' and mimeType = 'application/vnd.google-apps.folder' and 'root' in parents and trashed = false"
    results = service.files().list(q=query, fields="files(id, name)").execute()

    if results.get("files"):
        return results["files"][0]["id"]

    # Create dupes folder at root
    file_metadata = {
        "name": folder_name,
        "mimeType": "application/vnd.google-apps.folder",
    }
    folder = service.files().create(body=file_metadata, fields="id").execute()
    return folder.get("id")


def ensure_folder_path(service, path: str, dupes_root_id: str, folder_cache: dict) -> str:
    """Ensure folder structure exists under _dupes mirroring the original path.

    For path /Photos/2024/January/IMG.jpg, creates:
    /_dupes/Photos/2024/January

    Uses folder_cache to avoid repeated API calls for same paths.
    Returns the target folder ID.
    """
    # Remove filename, keep only directory path
    parts = path.split("/")
    parent_path = "/".join(parts[:-1])  # e.g., /Photos/2024

    if not parent_path or parent_path == "/":
        # File is at root, move directly to _dupes
        return dupes_root_id

    if parent_path in folder_cache:
        return folder_cache[parent_path]

    # Build path components (skip empty string from leading /)
    components = [c for c in parent_path.split("/") if c]

    current_parent_id = dupes_root_id
    current_path = ""

    for component in components:
        current_path = f"{current_path}/{component}"

        if current_path in folder_cache:
            current_parent_id = folder_cache[current_path]
            continue

        # Search for existing folder
        # Properly escape special characters for Google Drive query syntax
        # Backslash must be escaped first, then single quotes
        escaped_name = component.replace("\\", "\\\\").replace("'", "\\'")
        query = f"name = '{escaped_name}' and mimeType = 'application/vnd.google-apps.folder' and '{current_parent_id}' in parents and trashed = false"
        results = service.files().list(q=query, fields="files(id)").execute()

        if results.get("files"):
            folder_id = results["files"][0]["id"]
        else:
            # Create folder
            file_metadata = {
                "name": component,
                "mimeType": "application/vnd.google-apps.folder",
                "parents": [current_parent_id],
            }
            folder = service.files().create(body=file_metadata, fields="id").execute()
            folder_id = folder.get("id")

        folder_cache[current_path] = folder_id
        current_parent_id = folder_id

    folder_cache[parent_path] = current_parent_id
    return current_parent_id


def batch_get_parents(service, file_ids: list[str]) -> dict[str, str]:
    """Batch fetch parent IDs for multiple files.

    Returns: dict mapping file_id -> comma-separated parent IDs (or empty string if orphaned)
    """
    from googleapiclient.errors import HttpError
    import time

    batch_size = get_batch_size()
    results = {}
    errors = {}

    def callback(request_id, response, exception):
        file_id = request_id
        if exception is not None:
            errors[file_id] = str(exception)
            results[file_id] = ""  # Treat as orphaned on error
        else:
            parents = response.get("parents", [])
            results[file_id] = ",".join(parents)

    # Process in chunks
    for i in range(0, len(file_ids), batch_size):
        chunk = file_ids[i : i + batch_size]

        max_retries = 3
        for attempt in range(max_retries):
            try:
                batch = service.new_batch_http_request(callback=callback)
                for file_id in chunk:
                    batch.add(
                        service.files().get(fileId=file_id, fields="parents"),
                        request_id=file_id,
                    )
                batch.execute()
                break  # Success, exit retry loop
            except HttpError as e:
                if e.resp.status in (429, 403) and "rate" in str(e).lower():
                    wait_time = 2**attempt
                    time.sleep(wait_time)
                else:
                    # Non-rate-limit error, mark all in chunk as failed
                    for file_id in chunk:
                        if file_id not in results:
                            errors[file_id] = str(e)
                            results[file_id] = ""
                    break

    return results


def batch_move_files(
    service,
    move_requests: list[tuple[str, str, str]],
) -> dict[str, dict]:
    """Batch move multiple files to their target folders.

    Args:
        service: Google Drive API service
        move_requests: List of (file_id, target_folder_id, previous_parents) tuples

    Returns: dict mapping file_id -> {"success": bool, "error": str or None}
    """
    from googleapiclient.errors import HttpError
    import time

    batch_size = get_batch_size()
    results = {}

    def callback(request_id, response, exception):
        file_id = request_id
        if exception is not None:
            results[file_id] = {"success": False, "error": str(exception)}
        else:
            results[file_id] = {"success": True, "error": None}

    # Process in chunks
    for i in range(0, len(move_requests), batch_size):
        chunk = move_requests[i : i + batch_size]

        max_retries = 3
        for attempt in range(max_retries):
            try:
                batch = service.new_batch_http_request(callback=callback)
                for file_id, target_folder_id, previous_parents in chunk:
                    if previous_parents:
                        batch.add(
                            service.files().update(
                                fileId=file_id,
                                addParents=target_folder_id,
                                removeParents=previous_parents,
                                fields="id, parents",
                            ),
                            request_id=file_id,
                        )
                    else:
                        # Orphaned file, just add new parent
                        batch.add(
                            service.files().update(
                                fileId=file_id,
                                addParents=target_folder_id,
                                fields="id, parents",
                            ),
                            request_id=file_id,
                        )
                batch.execute()
                break  # Success, exit retry loop
            except HttpError as e:
                if e.resp.status in (429, 403) and "rate" in str(e).lower():
                    wait_time = 2**attempt
                    time.sleep(wait_time)
                else:
                    # Non-rate-limit error, mark all in chunk as failed
                    for file_id, _, _ in chunk:
                        if file_id not in results:
                            results[file_id] = {"success": False, "error": str(e)}
                    break

    return results


def move_file_to_dupes(service, file_id: str, target_folder_id: str) -> dict:
    """Move a file to the target folder in _dupes.

    Returns: {"success": bool, "error": str or None}
    """
    from googleapiclient.errors import HttpError
    import time

    max_retries = 5
    for attempt in range(max_retries):
        try:
            # Get current parents
            file = service.files().get(fileId=file_id, fields="parents").execute()
            previous_parents = ",".join(file.get("parents", []))

            if not previous_parents:
                # File has no parent (orphaned), just add new parent
                service.files().update(
                    fileId=file_id,
                    addParents=target_folder_id,
                    fields="id, parents",
                ).execute()
            else:
                # Move file
                service.files().update(
                    fileId=file_id,
                    addParents=target_folder_id,
                    removeParents=previous_parents,
                    fields="id, parents",
                ).execute()

            return {"success": True, "error": None}
        except HttpError as e:
            if e.resp.status in (429, 403) and "rate" in str(e).lower():
                wait_time = 2 ** attempt
                time.sleep(wait_time)
            else:
                return {"success": False, "error": str(e)}
    return {"success": False, "error": "Max retries exceeded due to rate limiting"}


def prepare_execution_plan(delete_files: list[dict]) -> list[dict]:
    """Prepare execution plan showing source -> destination mapping.

    Returns list of:
    {
        "file_id": str,
        "name": str,
        "source_path": str,
        "dest_path": str,  # Under dupes folder
        "size": int
    }
    """
    dupes_folder = get_dupes_folder()
    # Ensure folder starts with / for path matching
    if not dupes_folder.startswith("/"):
        dupes_folder = "/" + dupes_folder

    plan = []
    for f in delete_files:
        source_path = f["path"]
        # Skip files already in dupes folder
        if source_path.startswith(dupes_folder + "/") or source_path.startswith(dupes_folder.rstrip("/") + "/"):
            continue
        # Destination mirrors source under dupes folder
        dest_path = f"{dupes_folder}{source_path}"
        plan.append({
            "file_id": f["id"],
            "name": f["name"],
            "source_path": source_path,
            "dest_path": dest_path,
            "size": f["size"],
        })
    return plan


def save_execution_log(results: list[dict], dry_run: bool):
    """Save execution results to JSON for audit."""
    ensure_dirs()
    execution_log_file = get_output_paths()["execution_log_file"]

    data = {
        "executed_at": datetime.utcnow().isoformat() + "Z",
        "dry_run": dry_run,
        "total_files": len(results),
        "successful": sum(1 for r in results if r["status"] == "moved"),
        "failed": sum(1 for r in results if r["status"] == "failed"),
        "skipped": sum(1 for r in results if r["status"] == "skipped"),
        "results": results,
    }

    with open(execution_log_file, "w") as f:
        json.dump(data, f, indent=2)


def execute_moves(dry_run: bool, progress=gr.Progress()) -> tuple[str, list]:
    """Execute the move operation.

    If dry_run=True, only prepares and displays the plan.
    If dry_run=False, actually performs the moves.

    Returns: (status_message, table_data)
    """
    # Get files to move from decisions
    _, _, delete_files = get_export_summary()

    if not delete_files:
        return "No files to move.", []

    # Prepare plan
    plan = prepare_execution_plan(delete_files)

    if not plan:
        return "No files to move (all already in _dupes or no valid files).", []

    if dry_run:
        # Format dry-run output as table data
        table_data = []
        for item in plan:
            table_data.append([
                "PENDING",
                item["source_path"],
                item["dest_path"],
                format_size(item["size"]),
            ])

        total_size = sum(f["size"] for f in plan)
        status = f"**Dry run complete.** {len(plan)} files ({format_size(total_size)}) would be moved. Review the table below, then click Execute to move files."
        return status, table_data

    # Actual execution
    if not ensure_service():
        return "Authentication failed. Please check credentials.json.", ""

    progress(0, desc="Creating _dupes folder...")
    try:
        dupes_folder_id = get_or_create_dupes_folder(state.service)
    except Exception as e:
        return f"Failed to create _dupes folder: {e}", ""

    folder_cache = {}
    results = []
    successful = 0
    failed = 0
    skipped = 0

    # Filter out files already in dupes folder
    dupes_folder = get_dupes_folder()
    if not dupes_folder.startswith("/"):
        dupes_folder = "/" + dupes_folder
    dupes_prefix = dupes_folder.rstrip("/") + "/"

    files_to_move = []
    for item in plan:
        if item["source_path"].startswith(dupes_prefix):
            skipped += 1
            results.append({"path": item["source_path"], "status": "skipped", "reason": f"already in {dupes_folder}"})
        else:
            files_to_move.append(item)

    if not files_to_move:
        save_execution_log(results, dry_run=False)
        return f"All {skipped} files already in _dupes.", []

    # Phase 1: Pre-create all target folders
    progress(0.1, desc="Creating target folders...")
    for i, item in enumerate(files_to_move):
        try:
            target_folder_id = ensure_folder_path(
                state.service,
                item["source_path"],
                dupes_folder_id,
                folder_cache
            )
            item["target_folder_id"] = target_folder_id
        except Exception as e:
            failed += 1
            results.append({"path": item["source_path"], "status": "failed", "error": f"Folder creation failed: {e}"})
            item["target_folder_id"] = None

    # Filter out files where folder creation failed
    files_ready = [f for f in files_to_move if f.get("target_folder_id")]

    if not files_ready:
        save_execution_log(results, dry_run=False)
        return f"Failed to create target folders for all files. Skipped: {skipped}, Failed: {failed}", []

    # Phase 2: Batch fetch all parent IDs
    progress(0.3, desc=f"Fetching parent info for {len(files_ready)} files...")
    file_ids = [item["file_id"] for item in files_ready]
    parent_map = batch_get_parents(state.service, file_ids)

    # Phase 3: Batch move all files
    progress(0.5, desc=f"Moving {len(files_ready)} files in batches...")
    move_requests = []
    file_id_to_item = {}
    for item in files_ready:
        file_id = item["file_id"]
        target_folder_id = item["target_folder_id"]
        previous_parents = parent_map.get(file_id, "")
        move_requests.append((file_id, target_folder_id, previous_parents))
        file_id_to_item[file_id] = item

    move_results = batch_move_files(state.service, move_requests)

    # Process results
    progress(0.9, desc="Processing results...")
    for file_id, result in move_results.items():
        item = file_id_to_item[file_id]
        if result["success"]:
            successful += 1
            results.append({"path": item["source_path"], "dest": item["dest_path"], "status": "moved"})
        else:
            failed += 1
            results.append({"path": item["source_path"], "status": "failed", "error": result["error"]})

    # Save execution log
    save_execution_log(results, dry_run=False)

    # Format results as table data
    execution_log_file = get_output_paths()["execution_log_file"]
    status = f"Execution complete. **Moved:** {successful} | **Failed:** {failed} | **Skipped:** {skipped} | Log saved to: `{execution_log_file}`"

    table_data = []
    for r in results:
        if r["status"] == "moved":
            table_data.append(["MOVED", r["path"], r.get("dest", ""), ""])
        elif r["status"] == "skipped":
            table_data.append(["SKIPPED", r["path"], "", r.get("reason", "")])
        else:
            table_data.append(["FAILED", r["path"], "", r.get("error", "Unknown error")])

    return status, table_data


# =============================================================================
# Gradio UI
# =============================================================================

def create_ui():
    """Create the Gradio interface."""

    with gr.Blocks(title="Google Drive Deduplication Manager") as app:
        gr.Markdown("# Google Drive Deduplication Manager")

        with gr.Tabs():
            # =================================================================
            # Tab 1: Scan
            # =================================================================
            with gr.Tab("Scan"):
                gr.Markdown("### Scan Google Drive for Duplicates")

                with gr.Row():
                    path_input = gr.Textbox(
                        label="Path Filter (optional)",
                        placeholder="/Photos or leave empty for all files",
                        scale=3,
                    )
                    scan_btn = gr.Button("Run Scan", variant="primary", scale=1)

                scan_status = gr.Textbox(label="Status", interactive=False)
                scan_summary = gr.Markdown()
                decisions_info = gr.Markdown()

            # =================================================================
            # Tab 2: Review Duplicates
            # =================================================================
            with gr.Tab("Review Duplicates"):
                # Stats row
                stats_display = gr.Markdown(value=get_stats_display)

                # Search
                with gr.Row():
                    search_input = gr.Textbox(
                        label="Search (path or filename)",
                        placeholder="Enter search term...",
                        scale=3,
                    )
                    search_btn = gr.Button("Search", scale=1)

                # Navigation
                with gr.Row():
                    prev_btn = gr.Button("< Previous", scale=1)
                    next_btn = gr.Button("Next >", scale=1)

                # Header
                group_header = gr.Markdown("Run a scan to see duplicates.")

                # Multi-file selector (hidden by default)
                multi_file_selector = gr.Radio(
                    label="Select file to KEEP",
                    choices=[],
                    visible=False,
                )

                # Side-by-side comparison
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### FILE A")
                        path_a = gr.Textbox(show_label=False, interactive=False)
                        preview_img_a = gr.Image(label="Preview", height=300, visible=True)
                        preview_code_a = gr.Code(label="Preview", language="json", visible=False, lines=12)
                        metadata_a = gr.Markdown()
                        link_a = gr.Markdown()

                    with gr.Column():
                        gr.Markdown("### FILE B")
                        path_b = gr.Textbox(show_label=False, interactive=False)
                        preview_img_b = gr.Image(label="Preview", height=300, visible=True)
                        preview_code_b = gr.Code(label="Preview", language="json", visible=False, lines=12)
                        metadata_b = gr.Markdown()
                        link_b = gr.Markdown()

                # Action buttons
                with gr.Row():
                    keep_left_btn = gr.Button("Keep Left (A)", variant="primary", scale=1)
                    keep_right_btn = gr.Button("Keep Right (B)", variant="primary", scale=1)

                # Define outputs for review updates
                review_outputs = [
                    group_header,
                    path_a, path_b,
                    preview_img_a, preview_code_a,
                    preview_img_b, preview_code_b,
                    metadata_a, metadata_b,
                    link_a, link_b,
                    keep_left_btn, keep_right_btn,
                    multi_file_selector,
                ]

                # Wire up events
                scan_btn.click(
                    fn=run_scan,
                    inputs=[path_input],
                    outputs=[scan_status, scan_summary, decisions_info],
                ).then(
                    fn=update_review_display,
                    outputs=review_outputs,
                ).then(fn=get_stats_display, outputs=[stats_display])

                search_btn.click(
                    fn=on_search,
                    inputs=[search_input],
                    outputs=review_outputs,
                ).then(fn=get_stats_display, outputs=[stats_display])

                prev_btn.click(
                    fn=lambda: on_navigate("prev"),
                    outputs=review_outputs,
                ).then(fn=get_stats_display, outputs=[stats_display])

                next_btn.click(
                    fn=lambda: on_navigate("next"),
                    outputs=review_outputs,
                ).then(fn=get_stats_display, outputs=[stats_display])

                keep_left_btn.click(
                    fn=on_keep_left,
                    outputs=review_outputs,
                ).then(fn=get_stats_display, outputs=[stats_display])

                keep_right_btn.click(
                    fn=on_keep_right,
                    inputs=[multi_file_selector],
                    outputs=review_outputs,
                ).then(fn=get_stats_display, outputs=[stats_display])

                multi_file_selector.change(
                    fn=on_multi_file_select,
                    inputs=[multi_file_selector],
                    outputs=[path_b, preview_img_b, preview_code_b, metadata_b],
                )

            # =================================================================
            # Tab 3: Export
            # =================================================================
            with gr.Tab("Export Decisions"):
                gr.Markdown("### Export Decision Plan")

                refresh_btn = gr.Button("Refresh Summary")

                export_summary = gr.Markdown()
                export_preview = gr.Markdown()

                gr.Markdown("---")
                gr.Markdown("### Move Duplicates to _dupes Folder")
                gr.Markdown("Files will be moved to `/_dupes/` preserving their original folder structure. This is a non-destructive operation - files can be restored by moving them back.")

                with gr.Row():
                    dry_run_btn = gr.Button("Preview (Dry Run)", variant="secondary", scale=1)
                    execute_btn = gr.Button("Execute Moves", variant="primary", scale=1)

                confirm_checkbox = gr.Checkbox(
                    label="I understand this will move files in my Google Drive",
                    value=False,
                )

                execution_status = gr.Markdown()
                execution_results = gr.Dataframe(
                    headers=["Status", "Source Path", "Destination Path", "Details"],
                    datatype=["str", "str", "str", "str"],
                    interactive=False,
                )

                gr.Markdown("---")
                gr.Markdown("### Export Decisions to JSON")
                export_btn = gr.Button("Export to JSON")
                export_status = gr.Markdown()
                export_file = gr.File(label="Download", visible=False)

                def refresh_export():
                    summary, preview, _ = get_export_summary()
                    return summary, preview

                refresh_btn.click(
                    fn=refresh_export,
                    outputs=[export_summary, export_preview],
                )

                # Dry run - shows preview without moving
                dry_run_btn.click(
                    fn=lambda: execute_moves(dry_run=True),
                    outputs=[execution_status, execution_results],
                )

                # Execute - requires confirmation
                def execute_with_confirmation(confirmed: bool):
                    if not confirmed:
                        return "Please check the confirmation box before executing.", []
                    return execute_moves(dry_run=False)

                execute_btn.click(
                    fn=execute_with_confirmation,
                    inputs=[confirm_checkbox],
                    outputs=[execution_status, execution_results],
                ).then(
                    fn=lambda: gr.update(value=False),
                    outputs=[confirm_checkbox],
                )

                export_btn.click(
                    fn=export_decisions,
                    outputs=[export_status, export_file],
                )

        # Tip
        gr.Markdown("---")
        gr.Markdown("*Tip: Previous scan results are automatically loaded on startup. Rescan to refresh data.*")

        # Load initial display on startup if scan results exist
        app.load(
            fn=update_review_display,
            outputs=review_outputs,
        ).then(fn=get_stats_display, outputs=[stats_display])

    return app


if __name__ == "__main__":
    ensure_dirs()
    # Load previous scan results if available
    if load_scan_results():
        print("Previous scan results loaded. You can continue reviewing duplicates.")
    state.decisions = load_decisions()
    app = create_ui()
    app.launch(share=False)
