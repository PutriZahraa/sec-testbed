#!/bin/bash
set -euo pipefail

# Dataset Generation Pipeline for Security Testbed
# Generates separate attack and benign datasets for ML training

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
CAPTURE_DURATION="${1:-600}"  # Get from command line argument or default to 10 minutes
DATASET_DIR="$PROJECT_ROOT/data/labeled_datasets"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] ✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] ⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ❌ $1${NC}"
}

# Create dataset directory
mkdir -p "$DATASET_DIR"

log "🎯 Starting Dataset Generation Pipeline"
log "Capture Duration: ${CAPTURE_DURATION} seconds ($((CAPTURE_DURATION / 60)) minutes) per session"
log "Output Directory: $DATASET_DIR"

# Check if testbed is running
if ! docker ps | grep -q "sec_monitor\|sec_victim\|sec_attacker"; then
    log_error "Security testbed is not running. Please start it first with ./start_testbed.sh"
    exit 1
fi

log_success "Security testbed is running"

# Step 1: Generate benign dataset
echo "Step 1: Generating benign dataset..."
"$SCRIPT_DIR/generate_benign_dataset_simple.sh" "$CAPTURE_DURATION" "$TIMESTAMP"

# Wait a bit between sessions
log "⏳ Waiting 30 seconds before next session..."
sleep 30

# Step 2: Generate attack dataset
echo "Step 2: Generating attack dataset..."
"$SCRIPT_DIR/generate_attack_dataset_simple.sh" "$CAPTURE_DURATION" "$TIMESTAMP"

# Step 3: Process and Label Datasets
log "🔧 Step 3: Processing and labeling datasets..."
"$SCRIPT_DIR/process_and_label_datasets.sh" "$TIMESTAMP"

# Step 4: Merge and Shuffle Final Dataset
log "🔀 Step 4: Merging and shuffling final dataset..."
if [ -f "$DATASET_DIR/benign_dataset_${TIMESTAMP}.csv" ] && [ -f "$DATASET_DIR/attack_dataset_${TIMESTAMP}.csv" ]; then
    python3 "$SCRIPT_DIR/merge_datasets.py" \
        "$DATASET_DIR/benign_dataset_${TIMESTAMP}.csv" \
        "$DATASET_DIR/attack_dataset_${TIMESTAMP}.csv" \
        "$DATASET_DIR/final_xss_dataset_${TIMESTAMP}.csv"
    log_success "Final dataset merged and shuffled successfully"
else
    log_error "Individual datasets not found for merging"
    exit 1
fi

log_success "🎉 Dataset generation pipeline completed!"
log "📁 Final dataset available at: $DATASET_DIR/final_xss_dataset_${TIMESTAMP}.csv"
log "📊 Individual datasets also saved for reference"
