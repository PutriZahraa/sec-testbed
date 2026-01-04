#!/bin/bash

# Custom Experiment Runner for Security Testbed
set -euo pipefail

log() { echo "[$(date +'%H:%M:%S')] $1"; }

echo "==============================================="
echo "🚀 Starting Custom Security Experiment"
echo "==============================================="
echo

# Check if testbed is running
if ! docker compose ps | grep -q "sec_monitor.*Up"; then
    echo "❌ Error: Security testbed is not running"
    echo "Please start it first with: ./start_testbed.sh"
    exit 1
fi

log "📋 Experiment Configuration:"
log "   Fixed requests: 200 requests per iteration"
log "   Attack ratio: 40-59% (randomized 50/50 probability)"
echo

# Step 1: Clear logs
log "🧹 Clearing Suricata logs for clean test run..."
docker exec sec_monitor sh -c "truncate -s 0 /captures/eve.json 2>/dev/null || touch /captures/eve.json"
log "   Cleared /captures/eve.json"

# Wait a moment for log clearing to take effect
sleep 2

# Step 2: Generate traffic
log "🌐 Starting custom mixed traffic generation..."
echo "   Executing custom_mixed_traffic-v2.sh in sec_attacker container"
echo

# Run the custom traffic script and capture its output for ground truth
TRAFFIC_OUTPUT=$(docker exec sec_attacker bash /attack_scenarios/custom_mixed_traffic.sh 2>&1)
echo "$TRAFFIC_OUTPUT"

# Extract ground truth data from traffic output
TOTAL_REQUESTS=$(echo "$TRAFFIC_OUTPUT" | grep "Total requests sent:" | awk '{print $NF}')
ATTACK_REQUESTS=$(echo "$TRAFFIC_OUTPUT" | grep "XSS attacks:" | awk '{print $NF}')
BENIGN_REQUESTS=$(echo "$TRAFFIC_OUTPUT" | grep "Normal requests:" | awk '{print $NF}')
ATTACK_PERCENTAGE=$(echo "$TRAFFIC_OUTPUT" | grep "Attack ratio:" | awk '{print $NF}' | tr -d '%')

echo
log "✅ Traffic generation completed"

# Step 3: Archive old data (after traffic generation)
log "📁 Archiving Suricata logs from this experiment..."
BACKUP_FILENAME="eve.json.bak-$(date +"%Y%m%d_%H%M%S")"

# Wait a moment for all logs to be written
log "⏳ Waiting for logs to be flushed..."
sleep 5

# Check if eve.json exists in the container and copy it
if docker exec sec_monitor test -f /captures/eve.json; then
    docker cp sec_monitor:/captures/eve.json "./data/captures/${BACKUP_FILENAME}"
    log "   Backed up eve.json to data/captures/${BACKUP_FILENAME}"
else
    log "   No eve.json found to backup"
fi

# Step 4: Analyze results
log "📊 Analyzing detection results..."
echo

# Check if eve.json has data
if ! docker exec sec_monitor test -s /captures/eve.json; then
    log "⚠️  Warning: eve.json appears to be empty. Results may be incomplete."
fi

# Run the analysis script and capture its output
ANALYSIS_OUTPUT=$(docker exec sec_monitor python3 /scripts/analyze_consolidated_detection.py /captures/eve.json 2>&1)
echo "$ANALYSIS_OUTPUT"

# Extract detection results from analysis output - more precise extraction
MODE1_DETECTIONS=$(echo "$ANALYSIS_OUTPUT" | sed -n '/MODE 1 (Official Suricata Rules):/,/MODE 2 (ML Detection):/p' | grep "XSS Detections:" | head -1 | awk '{print $NF}')
MODE1_RATIO=$(echo "$ANALYSIS_OUTPUT" | sed -n '/MODE 1 (Official Suricata Rules):/,/MODE 2 (ML Detection):/p' | grep "Detected Attack Ratio:" | head -1 | awk '{print $NF}' | tr -d '%')
MODE2_DETECTIONS=$(echo "$ANALYSIS_OUTPUT" | sed -n '/MODE 2 (ML Detection):/,/MODE COMPARISON SUMMARY/p' | grep "XSS Detections:" | head -1 | awk '{print $NF}')
MODE2_RATIO=$(echo "$ANALYSIS_OUTPUT" | sed -n '/MODE 2 (ML Detection):/,/MODE COMPARISON SUMMARY/p' | grep "Detected Attack Ratio:" | head -1 | awk '{print $NF}' | tr -d '%')

echo
echo "==============================================="
log "🎉 Custom Security Experiment Complete!"
echo "==============================================="
echo
echo "📋 EXPERIMENT SUMMARY:"
echo "   ═══════════════════════════════════════════"
echo "   🎯 GROUND TRUTH (Traffic Generation):"
echo "      Total HTTP Requests: ${TOTAL_REQUESTS:-N/A}"
echo "      Attack Requests: ${ATTACK_REQUESTS:-N/A}"
echo "      Benign Requests: ${BENIGN_REQUESTS:-N/A}"
echo "      Actual Attack Rate: ${ATTACK_PERCENTAGE:-N/A}%"
echo
echo "   🛡️  DETECTION RESULTS:"
echo "      Mode 1 (Official Rules): ${MODE1_DETECTIONS:-N/A} detections (${MODE1_RATIO:-N/A}%)"
echo "      Mode 2 (ML Detection): ${MODE2_DETECTIONS:-N/A} detections (${MODE2_RATIO:-N/A}%)"
echo
echo "   💾 DATA ARCHIVE:"
echo "      Backup saved: data/captures/${BACKUP_FILENAME}"
echo "      Fresh eve.json ready for next experiment"
echo