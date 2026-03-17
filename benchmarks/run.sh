#!/usr/bin/env bash
set -euo pipefail

# ── Usage ───────────────────────────────────────────────────────────────
# ./scripts/benchmark.sh --nvd-api-key YOUR_KEY
#
NVD_FLAG=""
NVD_KEY=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --nvd-api-key)
      NVD_KEY="$2"
      NVD_FLAG="--nvd-api-key $2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

echo ""
if [ -n "$NVD_KEY" ]; then
  echo "NVD API key: set (${#NVD_KEY} chars) — rate: 50 req/30s (0.6s delay)"
else
  echo "NVD API key: NOT SET — rate: 5 req/30s (6s delay)"
  echo "  Hint: ./scripts/benchmark.sh --nvd-api-key YOUR_KEY"
fi
echo ""

# ── Config ──────────────────────────────────────────────────────────────
IMAGES=(
  # ── Older versions (realistic — teams lag behind) ──
  nginx:1.23
  nginx:1.25
  redis:7.0
  postgres:14
  postgres:15
  node:18
  node:20
  python:3.10
  python:3.11
  httpd:2.4.57
  mysql:8.0
  mongo:6.0
  rabbitmq:3.11
  mariadb:10.11
  golang:1.20
  golang:1.21
  ruby:3.1
  php:8.1
  ubuntu:22.04
  debian:bullseye
  wordpress:6.3
  grafana/grafana:9.5.0
  grafana/grafana:10.0.0
  prom/prometheus:v2.45.0
  traefik:v2.10

  # ── Latest (for comparison) ──
  nginx:latest
  redis:latest
  postgres:latest
  python:latest
  node:latest
)

OUTDIR="$(pwd)/benchmark-results"
SARIF_DIR="$OUTDIR/sarif"
SIEVE_DIR="$OUTDIR/cvesieve"
SUMMARY="$OUTDIR/summary.csv"

mkdir -p "$SARIF_DIR" "$SIEVE_DIR"

# ── CSV header ──────────────────────────────────────────────────────────
echo "image,raw_cves,high_critical,block,warn,suppress,reduction_from_raw_pct,reduction_from_high_pct" > "$SUMMARY"

# ── Scan loop ───────────────────────────────────────────────────────────
for image in "${IMAGES[@]}"; do
  safe_name="${image//[:\/]/_}"
  sarif_file="$SARIF_DIR/${safe_name}.sarif.json"
  sieve_file="$SIEVE_DIR/${safe_name}.json"

  echo ""
  echo "────────────────────────────────────────"
  echo "Scanning: $image"
  echo "────────────────────────────────────────"

  # 1. Trivy scan → SARIF (skip if SARIF already exists to allow resume)
  if [ -f "$sarif_file" ] && [ -s "$sarif_file" ]; then
    echo "  Using cached SARIF: $sarif_file"
  else
    if ! trivy image --format sarif --output "$sarif_file" --quiet "$image" 2>/dev/null; then
      echo "  SKIP: trivy failed for $image"
      continue
    fi
  fi

  # Count raw CVEs from SARIF
  raw_total=$(jq '[.runs[].results[]] | length' "$sarif_file" 2>/dev/null || echo 0)

  # Count HIGH/CRITICAL CVEs from SARIF (by matching rule tags)
  high_crit=$(jq '
    [.runs[0].tool.driver.rules[] | select(.properties.tags | index("HIGH") or index("CRITICAL")) | .id] as $ids |
    [.runs[0].results[] | select(.ruleId as $r | $ids | index($r))] | length
  ' "$sarif_file" 2>/dev/null || echo 0)

  echo "  Raw CVEs from scanner: $raw_total (HIGH/CRITICAL: $high_crit)"

  if [ "$raw_total" -eq 0 ]; then
    echo "  SKIP: no CVEs found"
    echo "$image,0,0,0,0,0,100.0,100.0" >> "$SUMMARY"
    continue
  fi

  # 2. Run cvesieve (exit code 1 = has BLOCKs, not an error)
  cvesieve \
    --epss-threshold 0.01 \
    --min-severity high \
    --min-block-severity high \
    --min-nvd-severity critical \
    --age-threshold 14 \
    --age-gate-floor 0.001 \
    $NVD_FLAG \
    --format json \
    --output "$sieve_file" \
    "$sarif_file" || true

  # 3. Parse counts from cvesieve JSON output
  if [ ! -f "$sieve_file" ]; then
    echo "  SKIP: cvesieve produced no output"
    continue
  fi

  block=$(jq '.summary.block' "$sieve_file" 2>/dev/null || echo 0)
  warn=$(jq '.summary.warn' "$sieve_file" 2>/dev/null || echo 0)
  suppress=$(jq '.summary.suppress' "$sieve_file" 2>/dev/null || echo 0)

  # Noise reduction from raw = % of all CVEs that aren't BLOCK
  if [ "$raw_total" -gt 0 ]; then
    reduction_raw=$(echo "scale=1; 100 - ($block * 100 / $raw_total)" | bc)
  else
    reduction_raw="100.0"
  fi

  # Noise reduction from HIGH/CRITICAL = % of HIGH+ that aren't BLOCK
  if [ "$high_crit" -gt 0 ]; then
    reduction_high=$(echo "scale=1; 100 - ($block * 100 / $high_crit)" | bc)
  else
    reduction_high="100.0"
  fi

  echo ""
  echo "  ┌─────────────────────────────────────"
  echo "  │ Raw CVEs (all):      $raw_total"
  echo "  │ HIGH/CRITICAL:       $high_crit"
  echo "  │ cvesieve BLOCK:      $block"
  echo "  │ cvesieve WARN:       $warn"
  echo "  │ cvesieve SUPPRESS:   $suppress"
  echo "  │ Reduction (raw):     ${reduction_raw}%"
  echo "  │ Reduction (HIGH+):   ${reduction_high}%"
  echo "  └─────────────────────────────────────"

  echo "$image,$raw_total,$high_crit,$block,$warn,$suppress,$reduction_raw,$reduction_high" >> "$SUMMARY"
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "BENCHMARK COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Results saved to:"
echo "  SARIF files:    $SARIF_DIR/"
echo "  CVESieve JSON:  $SIEVE_DIR/"
echo "  Summary CSV:    $SUMMARY"
echo ""
echo "Summary:"
echo ""
column -t -s',' "$SUMMARY"

# ── Totals ──────────────────────────────────────────────────────────────
echo ""
total_raw=$(awk -F',' 'NR>1 {sum+=$2} END {print sum}' "$SUMMARY")
total_high=$(awk -F',' 'NR>1 {sum+=$3} END {print sum}' "$SUMMARY")
total_block=$(awk -F',' 'NR>1 {sum+=$4} END {print sum}' "$SUMMARY")
total_warn=$(awk -F',' 'NR>1 {sum+=$5} END {print sum}' "$SUMMARY")
total_suppress=$(awk -F',' 'NR>1 {sum+=$6} END {print sum}' "$SUMMARY")
if [ "$total_raw" -gt 0 ]; then
  overall_reduction_raw=$(echo "scale=1; 100 - ($total_block * 100 / $total_raw)" | bc)
else
  overall_reduction_raw="100.0"
fi
if [ "$total_high" -gt 0 ]; then
  overall_reduction_high=$(echo "scale=1; 100 - ($total_block * 100 / $total_high)" | bc)
else
  overall_reduction_high="100.0"
fi
echo "────────────────────────────────────────"
echo "TOTALS"
echo "  Raw CVEs (all severities):   $total_raw"
echo "  HIGH/CRITICAL only:          $total_high"
echo "  BLOCK:                       $total_block"
echo "  WARN:                        $total_warn"
echo "  SUPPRESS:                    $total_suppress"
echo "  Reduction (from raw):        ${overall_reduction_raw}%"
echo "  Reduction (from HIGH+):      ${overall_reduction_high}%"
echo "────────────────────────────────────────"
