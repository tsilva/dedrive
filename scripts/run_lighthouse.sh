#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "Usage: $0 <url> [mobile|desktop] [output-dir]" >&2
  exit 1
fi

url="$1"
strategy="${2:-mobile}"
output_dir="${3:-.lighthouse}"
preset_arg=""

case "$strategy" in
  mobile)
    ;;
  desktop)
    preset_arg="--preset=desktop"
    ;;
  *)
    echo "Invalid strategy: $strategy" >&2
    echo "Expected 'mobile' or 'desktop'." >&2
    exit 1
    ;;
esac

mkdir -p "$output_dir"
timestamp="$(date +%Y%m%d-%H%M%S)"
report_path="${output_dir}/${strategy}-${timestamp}.json"

npx --yes lighthouse \
  "$url" \
  --quiet \
  --chrome-flags='--headless=new' \
  --only-categories=performance,accessibility,best-practices,seo \
  ${preset_arg:+$preset_arg} \
  --output=json \
  --output-path="$report_path"

node - "$report_path" "$url" "$strategy" <<'NODE'
const fs = require('fs');

const [reportPath, url, strategy] = process.argv.slice(2);
const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
const categories = Object.fromEntries(
  Object.entries(report.categories).map(([id, category]) => [id, Math.round(category.score * 100)])
);

console.log(JSON.stringify({
  url,
  strategy,
  reportPath,
  categories,
}, null, 2));
NODE
