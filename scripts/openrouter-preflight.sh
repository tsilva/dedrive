#!/usr/bin/env bash
set -euo pipefail

OPENROUTER_ENV_FILE="${HOME}/.config/repologogen/.env"

load_openrouter_key() {
  if [[ -n "${OPENROUTER_API_KEY:-}" ]]; then
    return
  fi

  if [[ ! -f "$OPENROUTER_ENV_FILE" ]]; then
    return
  fi

  local key
  key="$(grep -E '^OPENROUTER_API_KEY=' "$OPENROUTER_ENV_FILE" | tail -n 1 | cut -d '=' -f 2- || true)"
  key="${key%\"}"
  key="${key#\"}"
  key="${key%\'}"
  key="${key#\'}"

  if [[ -n "$key" ]]; then
    export OPENROUTER_API_KEY="$key"
  fi
}

load_openrouter_key

if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "OpenRouter preflight failed: OPENROUTER_API_KEY is not set."
  echo "Set it in the environment or in ${OPENROUTER_ENV_FILE}."
  exit 1
fi

response_file="$(mktemp)"
trap 'rm -f "$response_file"' EXIT

status_code="$(
  curl -sS \
    -o "$response_file" \
    -w '%{http_code}' \
    -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    -H 'Accept: application/json' \
    -H 'HTTP-Referer: https://dedrive.tsilva.eu' \
    -H 'X-Title: dedrive branding preflight' \
    https://openrouter.ai/api/v1/credits
)"

if [[ "$status_code" != 2* ]]; then
  echo "OpenRouter preflight failed: authenticated request returned HTTP ${status_code}."
  sed -n '1,20p' "$response_file"
  exit 1
fi

echo "OpenRouter preflight passed."
