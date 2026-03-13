#!/usr/bin/env bash
set -euo pipefail

# ─── Colors & Prefixes ───────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ─── Phase 0: Prerequisites ──────────────────────────────────────────────────

info "Checking prerequisites..."

if ! command -v gcloud &>/dev/null; then
  error "'gcloud' CLI not found."
  echo "  Install it from: https://cloud.google.com/sdk/docs/install"
  exit 1
fi
ok "gcloud CLI found"

if ! gcloud auth print-access-token &>/dev/null; then
  error "Not authenticated with gcloud."
  echo "  Run:  gcloud auth login"
  exit 1
fi
ok "gcloud authenticated"

if ! command -v node &>/dev/null; then
  error "'node' not found. Install Node.js: https://nodejs.org"
  exit 1
fi
ok "node $(node -v) found"

if ! command -v npm &>/dev/null; then
  error "'npm' not found. It should come with Node.js."
  exit 1
fi
ok "npm $(npm -v) found"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "$SCRIPT_DIR/package.json" ]]; then
  error "package.json not found. Run this script from the project root."
  exit 1
fi
cd "$SCRIPT_DIR"
ok "Running from project root: $SCRIPT_DIR"

echo ""

# ─── Phase 1: User Input ─────────────────────────────────────────────────────

info "Google Cloud project setup"
echo ""

read -rp "Enter Google Cloud Project ID (e.g. my-dedrive-app): " PROJECT_ID

if [[ ! "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{5,29}$ ]]; then
  error "Invalid project ID. Must start with a lowercase letter, contain only"
  echo "  lowercase letters, digits, and hyphens, and be 6-30 characters long."
  exit 1
fi
ok "Project ID: $PROJECT_ID"

echo ""
read -rp "Production domain (leave blank to skip, e.g. dedrive.example.com): " PROD_DOMAIN

if [[ -n "$PROD_DOMAIN" ]]; then
  ok "Production domain: $PROD_DOMAIN"
else
  info "No production domain — only localhost origins will be configured."
fi

echo ""

# ─── Phase 2: Create/Select GCP Project ──────────────────────────────────────

info "Setting up GCP project '$PROJECT_ID'..."

if gcloud projects describe "$PROJECT_ID" &>/dev/null; then
  ok "Project '$PROJECT_ID' already exists"
else
  info "Creating project '$PROJECT_ID'..."
  if gcloud projects create "$PROJECT_ID" --name="dedrive-web"; then
    ok "Project created"
  else
    error "Failed to create project. Check your permissions or billing account."
    exit 1
  fi
fi

gcloud config set project "$PROJECT_ID" 2>/dev/null
ok "Active project set to '$PROJECT_ID'"

echo ""

# ─── Phase 3: Enable Drive API ───────────────────────────────────────────────

info "Checking Google Drive API..."

if gcloud services list --enabled --filter="name:drive.googleapis.com" --format="value(name)" 2>/dev/null | grep -q "drive.googleapis.com"; then
  ok "Drive API already enabled"
else
  info "Enabling Drive API..."
  if gcloud services enable drive.googleapis.com; then
    ok "Drive API enabled"
  else
    error "Failed to enable Drive API."
    echo "  This usually means billing is not enabled on the project."
    echo "  Visit: https://console.cloud.google.com/billing/linkedaccount?project=$PROJECT_ID"
    exit 1
  fi
fi

echo ""

# ─── Phase 4: OAuth Consent Screen ───────────────────────────────────────────

info "OAuth consent screen setup"
echo ""

echo "────────────────────────────────────────────────────────────────────────"
warn "MANUAL STEP REQUIRED — Configure the OAuth consent screen:"
echo ""
echo "  1. Open: https://console.cloud.google.com/apis/credentials/consent?project=$PROJECT_ID"
echo "  2. Set User Type to 'External' (if prompted)"
echo "  3. Fill in the required fields (App name: dedrive-web, support email)"
echo "  4. On the Scopes page, add:"
echo "       - https://www.googleapis.com/auth/drive.readonly"
echo "       - https://www.googleapis.com/auth/drive"
echo "  5. If the app is in 'Testing' status, add your Google account as a test user"
echo "  6. Save and continue through the remaining steps"
echo ""
echo "────────────────────────────────────────────────────────────────────────"
echo ""
read -rp "↳ Press Enter once you have completed the consent screen setup... "
ok "Consent screen configured"

echo ""

# ─── Phase 5: OAuth Client ID ────────────────────────────────────────────────

info "OAuth Client ID setup"
echo ""

ORIGINS="http://localhost:3000"
if [[ -n "$PROD_DOMAIN" ]]; then
  ORIGINS="$ORIGINS, https://$PROD_DOMAIN"
fi

echo "────────────────────────────────────────────────────────────────────────"
warn "MANUAL STEP REQUIRED — Create an OAuth 2.0 Client ID:"
echo ""
echo "  1. Open: https://console.cloud.google.com/apis/credentials?project=$PROJECT_ID"
echo "  2. Click '+ CREATE CREDENTIALS' → 'OAuth client ID'"
echo "  3. Application type: 'Web application'"
echo "  4. Name: dedrive-web"
echo "  5. Authorized JavaScript origins:"
echo "       - http://localhost:3000"
if [[ -n "$PROD_DOMAIN" ]]; then
  echo "       - https://$PROD_DOMAIN"
fi
echo "  6. Click 'Create' and copy the Client ID"
echo ""
echo "────────────────────────────────────────────────────────────────────────"
echo ""

while true; do
  read -rp "Paste the Client ID here: " CLIENT_ID

  if [[ -z "$CLIENT_ID" ]]; then
    warn "Client ID cannot be empty. Please try again."
    continue
  fi

  if [[ "$CLIENT_ID" =~ ^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$ ]]; then
    break
  else
    warn "That doesn't look like a valid Client ID."
    echo "  Expected format: 123456789-abcdef.apps.googleusercontent.com"
    read -rp "Use it anyway? (y/N): " USE_ANYWAY
    if [[ "$USE_ANYWAY" =~ ^[Yy]$ ]]; then
      break
    fi
  fi
done

ok "Client ID: $CLIENT_ID"

echo ""

# ─── Phase 6: Finalize ───────────────────────────────────────────────────────

info "Writing .env.local..."

ENV_FILE="$SCRIPT_DIR/.env.local"
KEY="NEXT_PUBLIC_GOOGLE_CLIENT_ID"

if [[ -f "$ENV_FILE" ]]; then
  if grep -q "^${KEY}=" "$ENV_FILE"; then
    # Update existing key — portable approach (no sed -i)
    grep -v "^${KEY}=" "$ENV_FILE" > "$ENV_FILE.tmp"
    echo "${KEY}=${CLIENT_ID}" >> "$ENV_FILE.tmp"
    mv "$ENV_FILE.tmp" "$ENV_FILE"
    ok "Updated $KEY in .env.local"
  else
    echo "${KEY}=${CLIENT_ID}" >> "$ENV_FILE"
    ok "Added $KEY to .env.local"
  fi
else
  echo "${KEY}=${CLIENT_ID}" > "$ENV_FILE"
  ok "Created .env.local with $KEY"
fi

echo ""
info "Installing dependencies..."
npm install
ok "Dependencies installed"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}  Setup complete!${NC}"
echo ""
echo "  Project:   $PROJECT_ID"
echo "  Client ID: $CLIENT_ID"
echo "  Origins:   $ORIGINS"
echo ""
echo "  Start the dev server:"
echo "    npm run dev"
echo ""
echo "  Then open http://localhost:3000"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
