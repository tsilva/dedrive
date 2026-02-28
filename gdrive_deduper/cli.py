"""CLI entry point for gdrive-deduper."""

import argparse
import logging
import sys
import webbrowser

from gdrive_deduper.config import (
    get_credentials_path,
    get_token_path,
    set_active_profile,
    set_active_profile_from_email,
)
from gdrive_deduper.drive import (
    create_oauth_flow,
    run_oauth_callback_server,
    save_token,
    load_existing_token,
    get_user_info,
    setup_logging,
    authenticate,
)
from gdrive_deduper.profiles import (
    list_profiles,
    get_profile_token_path,
    delete_profile_token,
    PROFILES_DIR,
)


def cmd_login(args):
    """Handle the login subcommand."""
    credentials_path = get_credentials_path()

    try:
        auth_url, flow, port = create_oauth_flow(credentials_path)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print()
        print("To fix this:")
        print("  1. Go to https://console.cloud.google.com/apis/credentials")
        print("  2. Create a project (if you haven't already)")
        print("  3. Enable the Google Drive API")
        print("  4. Create OAuth 2.0 Client ID (choose 'Desktop app')")
        print("  5. Download the JSON file")
        print(f"  6. Save it as: {credentials_path}")
        print(f"     Or save it to: {PROFILES_DIR / 'credentials.json'}")
        sys.exit(1)

    print(f"Opening browser for Google sign-in...")
    print(f"If the browser doesn't open, visit: {auth_url}")
    webbrowser.open(auth_url)

    print("Waiting for authentication...")
    try:
        creds = run_oauth_callback_server(flow, port)
    except TimeoutError:
        print("Error: Authentication timed out.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Authentication failed: {e}")
        sys.exit(1)

    # Build service to get user info
    from googleapiclient.discovery import build
    service = build("drive", "v3", credentials=creds)
    user_info = get_user_info(service)
    email = user_info["email"]
    name = user_info["name"]

    # Create/activate profile based on email
    profile_name = set_active_profile_from_email(email)

    # Save token to profile
    token_path = get_token_path()
    save_token(creds, token_path)

    display_name = f"{name} ({email})" if name else email
    print(f"Logged in as {display_name}")
    print(f"Profile: {profile_name}")
    print(f"Token saved to: {token_path}")


def cmd_logout(args):
    """Handle the logout subcommand."""
    profile = args.profile

    if not profile:
        # Auto-detect: find profiles with tokens
        logged_in = []
        for name in list_profiles():
            token_path = get_profile_token_path(name)
            if token_path.exists():
                logged_in.append(name)

        if not logged_in:
            print("No logged-in profiles found.")
            sys.exit(0)
        elif len(logged_in) == 1:
            profile = logged_in[0]
        else:
            print("Multiple logged-in profiles found. Specify one with --profile:")
            for name in logged_in:
                print(f"  gdrive-deduper logout --profile {name}")
            sys.exit(1)

    deleted = delete_profile_token(profile)
    if deleted:
        print(f"Logged out from profile: {profile}")
    else:
        print(f"Profile '{profile}' was not logged in.")


def cmd_list_profiles(args):
    """Handle --list-profiles."""
    profiles = list_profiles()
    if not profiles:
        print("No profiles found. Run 'gdrive-deduper login' to create one.")
        return

    print("Profiles:")
    for name in profiles:
        token_path = get_profile_token_path(name)
        status = " (logged in)" if token_path.exists() else ""
        print(f"  {name}{status}")


def cmd_ui(args):
    """Handle the default command (launch Gradio UI)."""
    if not args.profile:
        profiles = list_profiles()
        if not profiles:
            print("No profiles found. Run 'gdrive-deduper login' first.")
            sys.exit(1)

        logged_in = [
            name for name in profiles
            if get_profile_token_path(name).exists()
        ]

        if len(logged_in) == 1:
            args.profile = logged_in[0]
            print(f"Using profile: {args.profile}")
        else:
            display = logged_in if logged_in else profiles
            print("Select a profile:")
            for i, name in enumerate(display, 1):
                status = " (logged in)" if name in logged_in else ""
                print(f"  {i}) {name}{status}")
            print()
            try:
                choice = input("Enter number: ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(display):
                    args.profile = display[idx]
                else:
                    print("Invalid selection.")
                    sys.exit(1)
            except (ValueError, EOFError, KeyboardInterrupt):
                print()
                sys.exit(1)

    set_active_profile(args.profile)

    setup_logging(verbose=args.verbose, log_file=args.log_file)

    if args.validate:
        logger = logging.getLogger(__name__)
        credentials_path = get_credentials_path()
        try:
            from googleapiclient.discovery import build
            creds = authenticate(credentials_path)
            service = build("drive", "v3", credentials=creds)
            user_info = get_user_info(service)
            logger.info(f"Credentials valid. Connected as: {user_info['name']} <{user_info['email']}>")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Credential validation failed: {e}")
            sys.exit(1)

    from gdrive_deduper.ui import create_ui
    from gdrive_deduper.config import get_output_dir
    app = create_ui()
    app.launch(share=args.share, server_port=args.port, allowed_paths=[str(get_output_dir())])


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="gdrive-deduper",
        description="Google Drive Deduplication Manager",
    )
    parser.add_argument(
        "--profile", "-P",
        help="Use a named profile",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available profiles and exit",
    )

    subparsers = parser.add_subparsers(dest="command")

    # login subcommand
    login_parser = subparsers.add_parser("login", help="Authenticate with Google (opens browser)")
    login_parser.add_argument("--profile", "-P", default=argparse.SUPPRESS, help="Use a named profile")

    # logout subcommand
    logout_parser = subparsers.add_parser("logout", help="Remove saved authentication token")
    logout_parser.add_argument("--profile", "-P", default=argparse.SUPPRESS, help="Use a named profile")

    # UI flags (only apply when no subcommand)
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate credentials and exit without launching the UI",
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
    parser.add_argument(
        "--port",
        type=int,
        default=7860,
        help="Gradio server port (default: 7860)",
    )
    parser.add_argument(
        "--share",
        action="store_true",
        help="Enable Gradio public sharing link",
    )

    args = parser.parse_args()

    # Handle --list-profiles
    if args.list_profiles:
        cmd_list_profiles(args)
        sys.exit(0)

    # Handle subcommands
    if args.command == "login":
        if args.profile:
            set_active_profile(args.profile)
        cmd_login(args)
    elif args.command == "logout":
        cmd_logout(args)
    else:
        cmd_ui(args)


if __name__ == "__main__":
    main()
