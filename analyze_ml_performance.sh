#!/bin/bash

# ML Performance Calculator
# Analyzes experiment results and calculates ML performance metrics

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERFORMANCE_SCRIPT="$SCRIPT_DIR/utils/calculate_ml_performance.py"

print_usage() {
    echo "Usage: $0 <experiment_results_file> [output_file]"
    echo ""
    echo "Examples:"
    echo "  $0 archive/experiment_results_20250918_174025.txt"
    echo "  $0 archive/experiment_results_20250918_174025.txt performance_report.txt"
    echo ""
    echo "Available experiment files:"
    ls -1 archive/experiment_results_*.txt 2>/dev/null | head -5 || echo "  No experiment files found in archive/"
}

if [ $# -eq 0 ]; then
    print_usage
    exit 1
fi

RESULTS_FILE="$1"
OUTPUT_FILE="${2:-}"

# Check if results file exists
if [ ! -f "$RESULTS_FILE" ]; then
    echo "❌ Error: Results file '$RESULTS_FILE' not found"
    echo ""
    print_usage
    exit 1
fi

echo "🔍 Analyzing ML performance from: $RESULTS_FILE"
echo ""

# Run the performance calculator
if [ -n "$OUTPUT_FILE" ]; then
    python3 "$PERFORMANCE_SCRIPT" "$RESULTS_FILE" --output "$OUTPUT_FILE"
else
    python3 "$PERFORMANCE_SCRIPT" "$RESULTS_FILE"
fi
