#!/usr/bin/env bash
set +x
set -euo pipefail

# Compatibility filename; upstream account credentials belong to AgentBridge.
dedrive_gateway_key="${AGENTBRIDGE_API_KEY:-}"
export -n dedrive_gateway_key
unset AGENTBRIDGE_API_KEY
if [[ "$dedrive_gateway_key" =~ [[:cntrl:]] ]]; then
  echo 'AGENTBRIDGE_API_KEY must not contain control characters.' >&2
  exit 1
fi
gateway_url="${AGENTBRIDGE_BASE_URL:-http://127.0.0.1:8082/api/v1}"
case "$gateway_url" in
  http://openrouter.ai*|https://openrouter.ai*)
    echo 'Configure an AgentBridge endpoint.' >&2; exit 1 ;;
  http://*|https://*) ;;
  *) echo 'AGENTBRIDGE_BASE_URL must be an HTTP(S) URL.' >&2; exit 1 ;;
esac
gateway_authority="${gateway_url#*://}"
gateway_authority="${gateway_authority%%/*}"
if [[ "$gateway_url" =~ [[:cntrl:]] || "$gateway_url" == *\?* ||
      "$gateway_url" == *\#* || "$gateway_authority" == *@* ||
      -z "$gateway_authority" ]]; then
  echo 'Use an AgentBridge base URL without credentials, query or fragment.' >&2
  exit 1
fi

curl_args=(-q -s -o /dev/null -w '%{http_code}' -H 'Accept: application/json')
if [[ -n "$dedrive_gateway_key" ]]; then
  curl_args+=(--header @-)
fi
if ! status_code="$(
  {
    if [[ -n "$dedrive_gateway_key" ]]; then
      printf 'Authorization: Bearer %s\n' "$dedrive_gateway_key"
    fi
  } | curl "${curl_args[@]}" "${gateway_url%/}/openrouter/credits" 2>/dev/null
)"; then
  echo 'AgentBridge preflight failed: transport error.' >&2
  exit 1
fi
case "$status_code" in
  2[0-9][0-9]) ;;
  [0-9][0-9][0-9])
    echo "AgentBridge preflight failed: HTTP ${status_code}." >&2
    exit 1 ;;
  *)
    echo 'AgentBridge preflight failed: invalid HTTP status.' >&2
    exit 1 ;;
esac

echo 'AgentBridge account preflight passed.'
