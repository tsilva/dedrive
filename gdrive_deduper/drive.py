"""Google Drive authentication, API fetch, and path resolution."""

import logging
import os
import socket
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


def _find_available_port() -> int:
    """Find an available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def save_token(creds: Credentials, token_path: Path):
    """Save OAuth credentials to a token file.

    Args:
        creds: Google OAuth credentials to save.
        token_path: Path to write the token file.
    """
    token_path.parent.mkdir(parents=True, exist_ok=True)
    with open(token_path, "w") as token:
        token.write(creds.to_json())
    os.chmod(token_path, 0o600)
    logger.debug(f"Token saved to {token_path}")


def load_existing_token(token_path: Path) -> Credentials | None:
    """Load and refresh an existing token if possible.

    Args:
        token_path: Path to the token file.

    Returns:
        Valid Credentials if token exists and is valid/refreshable, None otherwise.
    """
    if not token_path.exists():
        return None

    logger.debug(f"Loading existing token from {token_path}")
    creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

    if creds and creds.valid:
        return creds

    if creds and creds.expired and creds.refresh_token:
        try:
            logger.debug("Refreshing expired token")
            creds.refresh(Request())
            save_token(creds, token_path)
            return creds
        except RefreshError as e:
            logger.warning(f"Token refresh failed: {e}")
            token_path.unlink(missing_ok=True)

    return None


def create_oauth_flow(credentials_path: Path) -> tuple[str, InstalledAppFlow, int]:
    """Create an OAuth flow and return the authorization URL without blocking.

    Args:
        credentials_path: Path to the OAuth credentials JSON file.

    Returns:
        Tuple of (auth_url, flow, port).

    Raises:
        FileNotFoundError: If credentials file is missing.
    """
    if not credentials_path.exists():
        raise FileNotFoundError(f"OAuth credentials not found at {credentials_path}")

    port = _find_available_port()
    flow = InstalledAppFlow.from_client_secrets_file(
        str(credentials_path),
        SCOPES,
        redirect_uri=f"http://localhost:{port}/",
    )
    auth_url, _ = flow.authorization_url(prompt="consent")
    return auth_url, flow, port


def run_oauth_callback_server(flow: InstalledAppFlow, port: int, timeout: int = 300) -> Credentials:
    """Run a minimal server to handle the OAuth redirect callback.

    Blocks until the user completes auth or timeout expires.
    Intended to be run in a background thread.

    Args:
        flow: The InstalledAppFlow from create_oauth_flow.
        port: The port to listen on (must match redirect_uri).
        timeout: Max seconds to wait for callback.

    Returns:
        Valid Google OAuth Credentials.

    Raises:
        TimeoutError: If no callback received within timeout.
        Exception: If token exchange fails.
    """
    from wsgiref.simple_server import make_server, WSGIRequestHandler
    import urllib.parse

    result = {"creds": None, "error": None}

    class QuietHandler(WSGIRequestHandler):
        def log_message(self, format, *args):
            pass  # Suppress server logs

    def app(environ, start_response):
        query = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        code = query.get("code", [None])[0]
        error = query.get("error", [None])[0]

        if error:
            result["error"] = error
            body = b"<html><body><h2>Authentication failed.</h2><p>You can close this tab.</p></body></html>"
        elif code:
            try:
                flow.fetch_token(code=code)
                result["creds"] = flow.credentials
                body = b"<html><body><h2>Authentication successful!</h2><p>You can close this tab and return to the app.</p></body></html>"
            except Exception as e:
                result["error"] = str(e)
                body = b"<html><body><h2>Authentication failed.</h2><p>You can close this tab.</p></body></html>"
        else:
            body = b"<html><body><p>Waiting for authentication...</p></body></html>"

        start_response("200 OK", [("Content-Type", "text/html")])
        return [body]

    server = make_server("localhost", port, app, handler_class=QuietHandler)
    server.timeout = timeout

    # Handle one request (the OAuth redirect)
    server.handle_request()
    server.server_close()

    if result["error"]:
        raise Exception(f"OAuth error: {result['error']}")
    if result["creds"] is None:
        raise TimeoutError("No OAuth callback received")

    return result["creds"]


def get_user_info(service) -> dict:
    """Get the authenticated user's info from Google Drive.

    Args:
        service: Google Drive API service instance.

    Returns:
        Dict with 'email' and 'name' keys.
    """
    about = service.about().get(fields="user(displayName, emailAddress)").execute()
    user = about.get("user", {})
    return {
        "email": user.get("emailAddress", "unknown"),
        "name": user.get("displayName", ""),
    }


def authenticate(credentials_path: Path) -> Credentials:
    """Handle OAuth authentication flow.

    Args:
        credentials_path: Path to the OAuth credentials JSON file.

    Returns:
        Valid Google OAuth credentials.

    Raises:
        SystemExit: If credentials file is missing.
    """
    token_path = get_token_path(credentials_path)

    creds = load_existing_token(token_path)
    if creds:
        return creds

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
        logger.error(f"     Or save it to: ~/.gdrive-deduper/credentials.json")
        logger.error("")
        logger.error("Or set GDRIVE_CREDENTIALS_PATH to use a different location.")
        sys.exit(1)

    logger.info("Starting OAuth flow (browser will open)...")
    flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), SCOPES)
    creds = flow.run_local_server(port=0)

    save_token(creds, token_path)

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
    """Fetch all owned files from Google Drive, with pagination.

    Excludes files shared with the user since they don't count towards
    the user's storage quota.
    """
    all_files = []
    page_token = None
    page_count = 0

    fields = "nextPageToken, files(id, name, md5Checksum, size, parents, createdTime, modifiedTime, mimeType)"
    query = "trashed = false and 'me' in owners"
    logger.info("Fetching owned files only (excluding shared files)")

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
