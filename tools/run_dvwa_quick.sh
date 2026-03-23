#!/usr/bin/env bash
set -euo pipefail

TARGET="http://127.0.0.1/"
ALLOWED_DOMAIN="127.0.0.1"
MODE="attack"
MAX_DEPTH=10
LOGIN_URL="/login.php"
USERNAME="admin"
PASSWORD="password"
REPORT_DIR="reports"
XSS_MAX_TARGETS=50

usage() {
  cat <<'EOF'
Usage: run_dvwa_quick.sh [options]

Options:
  --target URL              Target URL (default: http://127.0.0.1/)
  --allowed-domain DOMAIN   Allowed crawler domain (default: 127.0.0.1)
  --mode MODE               Scanner mode: detect|test|attack (default: attack)
  --max-depth N             Crawler max depth (default: 10)
  --login-url URL           Login URL path (default: /login.php)
  --username USER           Login username (default: admin)
  --password PASS           Login password (default: password)
  --report-dir DIR          Report base directory (default: reports)
  --xss-max-targets N       XSS plugin max targets override (default: 50)
  -h, --help                Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --allowed-domain)
      ALLOWED_DOMAIN="$2"
      shift 2
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    --max-depth)
      MAX_DEPTH="$2"
      shift 2
      ;;
    --login-url)
      LOGIN_URL="$2"
      shift 2
      ;;
    --username)
      USERNAME="$2"
      shift 2
      ;;
    --password)
      PASSWORD="$2"
      shift 2
      ;;
    --report-dir)
      REPORT_DIR="$2"
      shift 2
      ;;
    --xss-max-targets)
      XSS_MAX_TARGETS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

timestamp="$(date +"%Y%m%d-%H%M%S")"
out_dir="$REPORT_DIR/dvwa-quick-$timestamp"
mkdir -p "$out_dir"

json_report="$out_dir/risk-report.json"
md_report="$out_dir/risk-report.md"
html_report="$out_dir/risk-report.html"

echo "[vmp] Running DVWA full pipeline..."
echo "[vmp] Profile: full DVWA vulnerabilities"
echo "[vmp] Target: $TARGET"
echo "[vmp] Output: $out_dir"

if ! uv run main.py \
  --target "$TARGET" \
  --mode "$MODE" \
  --max-depth "$MAX_DEPTH" \
  --allowed-domain "$ALLOWED_DOMAIN" \
  --auto-login \
  --auth-login-url "$LOGIN_URL" \
  --auth-username "$USERNAME" \
  --auth-password "$PASSWORD" \
  --auth-submit-field Login \
  --auth-submit-value Login \
  --auth-success-keyword logout.php \
  --auth-extra security=low \
  --plugin-max-targets "xss_reflected=$XSS_MAX_TARGETS" \
  --report-json "$json_report" \
  --report-markdown "$md_report" \
  --report-html "$html_report" \
  --log-level INFO; then
  code=$?
  echo "vmp-scanner failed with exit code $code" >&2
  exit "$code"
fi

echo
echo "[vmp] Done. Reports generated:"
echo "  JSON: $json_report"
echo "  Markdown: $md_report"
echo "  HTML: $html_report"
echo

echo "[vmp] Open HTML report quickly:"
if [[ "${OSTYPE:-}" == darwin* ]]; then
  echo "  open \"$html_report\""
else
  echo "  xdg-open \"$html_report\""
fi
