#!/usr/bin/env bash
# scripts/convert_reports.sh
# Find the most recent HTML report under nmap_results and convert it to PDF.
# Usage:
#   ./scripts/convert_reports.sh [input_dir] [output_dir]
# Defaults:
#   input_dir: ./nmap_results
#   output_dir: ./nmap_results/reports

set -euo pipefail

INPUT_DIR="${1:-./nmap_results}"
OUTPUT_DIR="${2:-${INPUT_DIR}/reports}"

mkdir -p "$OUTPUT_DIR"

# Find the most recent .html file under INPUT_DIR (searching depth 3)
LATEST_HTML=$(find "$INPUT_DIR" -type f -iname '*.html' -print0 | xargs -0 ls -1 -t 2>/dev/null | head -n1 || true)

if [ -z "$LATEST_HTML" ]; then
  echo "No HTML reports found under $INPUT_DIR"
  exit 1
fi

BASENAME=$(basename "$LATEST_HTML" .html)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_PDF="$OUTPUT_DIR/${BASENAME}_${TIMESTAMP}.pdf"

echo "Converting $LATEST_HTML -> $OUTPUT_PDF"

# Prefer wkhtmltopdf if available
if command -v wkhtmltopdf >/dev/null 2>&1; then
  wkhtmltopdf "$LATEST_HTML" "$OUTPUT_PDF"
  echo "Saved PDF: $OUTPUT_PDF"
  exit 0
fi

# Fallback to Chromium/Chrome headless
CHROME_BIN=""
for cmd in chromium chromium-browser google-chrome google-chrome-stable chrome; do
  if command -v "$cmd" >/dev/null 2>&1; then
    CHROME_BIN=$(command -v "$cmd")
    break
  fi
done

if [ -n "$CHROME_BIN" ]; then
  # Chromium expects an absolute path
  ABS_HTML=$(readlink -f "$LATEST_HTML")
  docker run --rm -v "$(dirname "$ABS_HTML")":/reports -v "$OUTPUT_DIR":/out --entrypoint "$CHROME_BIN" --network host zenika/alpine-chrome:with-node sh -c "\
    $CHROME_BIN --headless --disable-gpu --no-sandbox --print-to-pdf=/out/$(basename "$OUTPUT_PDF") file:///reports/$(basename "$ABS_HTML")"
  echo "Saved PDF: $OUTPUT_PDF"
  exit 0
fi

echo "Neither wkhtmltopdf nor Chromium available. Install one of them or run conversion inside the WebMap container."
exit 2
