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
)

# Constants
OUTPUT_DIR = Path(".output")
PREVIEW_CACHE_DIR = OUTPUT_DIR / "preview_cache"
DECISIONS_FILE = OUTPUT_DIR / "decisions.json"
SCAN_RESULTS_FILE = OUTPUT_DIR / "scan_results.json"
MAX_PREVIEW_SIZE = 10 * 1024 * 1024  # 10MB


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
    OUTPUT_DIR.mkdir(exist_ok=True)
    PREVIEW_CACHE_DIR.mkdir(exist_ok=True)


def load_decisions() -> dict[str, Decision]:
    """Load decisions from JSON file."""
    if not DECISIONS_FILE.exists():
        return {}

    try:
        with open(DECISIONS_FILE) as f:
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
    except Exception as e:
        print(f"Error loading decisions: {e}")
        return {}


def save_decisions(decisions: dict[str, Decision], scan_info: dict = None):
    """Save decisions to JSON file."""
    ensure_dirs()

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

    with open(DECISIONS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def save_scan_results(duplicate_groups: list[DuplicateGroup], all_files: list[dict], scan_path: str = None):
    """Save scan results to JSON file for reuse across sessions."""
    ensure_dirs()

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

    with open(SCAN_RESULTS_FILE, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Scan results saved to {SCAN_RESULTS_FILE}")


def load_scan_results() -> bool:
    """Load scan results from JSON file. Returns True if loaded successfully."""
    if not SCAN_RESULTS_FILE.exists():
        return False

    try:
        with open(SCAN_RESULTS_FILE) as f:
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

        print(f"Loaded {len(state.duplicate_groups)} duplicate groups from {SCAN_RESULTS_FILE}")
        return True

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
        creds = authenticate("credentials.json")
        state.service = build("drive", "v3", credentials=creds)
        return True
    except Exception as e:
        print(f"Authentication failed: {e}")
        return False


def download_file(file_id: str) -> Optional[Path]:
    """Download a file from Google Drive and cache it."""
    # Check cache first (before authentication)
    cache_path = PREVIEW_CACHE_DIR / file_id
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
    except Exception as e:
        print(f"Error downloading file {file_id}: {e}")
        return None


def get_preview(file_info: FileInfo) -> tuple[str, any]:
    """Get preview for a file. Returns (type, content)."""
    if file_info.size > MAX_PREVIEW_SIZE:
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
    ensure_dirs()

    progress(0, desc="Authenticating...")
    try:
        creds = authenticate("credentials.json")
        state.service = build("drive", "v3", credentials=creds)
    except Exception as e:
        return f"Authentication failed: {e}", "", ""

    progress(0.1, desc="Fetching files from Google Drive...")
    try:
        state.all_files = fetch_all_files(state.service)
    except Exception as e:
        return f"Failed to fetch files: {e}", "", ""

    progress(0.5, desc="Building path index...")
    state.files_by_id, state.path_cache = build_lookups(state.all_files)

    # Filter by path if specified
    files_to_scan = state.all_files
    if path_filter and path_filter.strip():
        progress(0.6, desc=f"Filtering to path: {path_filter}")
        files_to_scan = filter_by_path(files_to_scan, path_filter.strip(), state.files_by_id, state.path_cache)

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

    summary = f"""### Results Summary

- **Total files scanned:** {total_files:,}
- **Duplicate groups:** {total_groups:,}
- **Duplicate pairs:** {total_pairs:,}
- **Uncertain groups:** {uncertain:,} (same MD5, different size)
- **Potential savings:** {format_size(savings)}
- **Skipped:** {skipped:,} Google Workspace files (no MD5)
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
        choices = [(f"{f.name} ({f.path})", f.id) for f in group.files]

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

    scan_info = {
        "total_files": len(state.all_files),
        "duplicate_groups": len(state.duplicate_groups),
    }
    save_decisions(state.decisions, scan_info)

    return f"Decisions exported to: `{DECISIONS_FILE}`", str(DECISIONS_FILE)


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

                scan_btn.click(
                    fn=run_scan,
                    inputs=[path_input],
                    outputs=[scan_status, scan_summary, decisions_info],
                )

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

                # Paths side-by-side (prominent display)
                with gr.Row():
                    path_a = gr.Textbox(label="Path A", interactive=False, scale=1)
                    path_b = gr.Textbox(label="Path B", interactive=False, scale=1)

                # Side-by-side comparison
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### File A")
                        preview_img_a = gr.Image(label="Preview", height=300, visible=True)
                        preview_code_a = gr.Code(label="Preview", language="json", visible=False, lines=12)
                        metadata_a = gr.Markdown()
                        link_a = gr.Markdown()

                    with gr.Column():
                        gr.Markdown("### File B")
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

                export_btn = gr.Button("Export to JSON", variant="primary")
                export_status = gr.Markdown()
                export_file = gr.File(label="Download", visible=False)

                def refresh_export():
                    summary, preview, _ = get_export_summary()
                    return summary, preview

                refresh_btn.click(
                    fn=refresh_export,
                    outputs=[export_summary, export_preview],
                )

                export_btn.click(
                    fn=export_decisions,
                    outputs=[export_status, export_file],
                )

        # Tip
        gr.Markdown("---")
        gr.Markdown("*Tip: Previous scan results are automatically loaded on startup. Rescan to refresh data.*")

    return app


if __name__ == "__main__":
    ensure_dirs()
    # Load previous scan results if available
    if load_scan_results():
        print("Previous scan results loaded. You can continue reviewing duplicates.")
    state.decisions = load_decisions()
    app = create_ui()
    app.launch(share=False)
