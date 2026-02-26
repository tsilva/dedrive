"""Google Drive authentication, API fetch, and path resolution."""

import logging
import os
import sys
import time
from pathlib import Path

from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.errors import HttpError

from gdrive_deduper.config import get_token_path

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
