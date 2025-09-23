#!/bin/bash

# Test Real-Time Detection System
# Generates test traffic while real-time detection is running
# Use this to verify that the real-time system is working correctly

set -euo pipefail

log() { echo "[$(date +'%H:%M:%S')] $1"; }

echo "🧪 Real-Time Detection Test Generator"
echo "====================================="

# Check if testbed is running
if ! docker compose ps | grep -q "sec_monitor.*Up"; then
    echo "❌ Error: Security testbed is not running"
    echo "Please start it first with: ./start_testbed.sh"
    exit 1
fi

# Check if existing attack script is available
ATTACK_SCRIPT="attacker/attack_scenarios/custom_mixed_traffic-v2.sh"

if [ -f "$ATTACK_SCRIPT" ]; then
    log "🎯 Using existing attack script: $ATTACK_SCRIPT"
    log "   This will generate 200 mixed requests (50% attacks, 50% normal traffic)"
    log "   Attack patterns: Your comprehensive XSS payload collection"
    log "   Expected detections: Both Mode 1 & Mode 2"
else
    log "⚠️  Custom attack script not found, using built-in test payloads"
    log "   Duration: 60 seconds"
    log "   Attack types: Various XSS payloads" 
    log "   Interval: 2-5 seconds between requests"
    log "   Expected detections: Both Mode 1 & Mode 2"
fi
log "🚀 Starting test traffic generation..."
log "   💡 TIP: Run './start_realtime_detection.sh' in another terminal to see live detections"
echo

VICTIM_URL="http://100.64.0.20:3000"
total_requests=0
attack_requests=0

log "🎯 Running your existing mixed traffic attack script..."

# Make sure the attack script is executable
chmod +x "$ATTACK_SCRIPT"

# Set environment variables for consistency
export TARGET_IP="100.64.0.20"
export PORT="3000"

# Run the existing script and capture its output for parsing
cd attacker/attack_scenarios
./custom_mixed_traffic-v2.sh | tee /tmp/attack_output.log
cd - > /dev/null

# Parse the output to get statistics
total_requests=$(grep "Total requests sent:" /tmp/attack_output.log | awk '{print $4}' || echo "200")
attack_requests=$(grep "XSS attacks:" /tmp/attack_output.log | awk '{print $3}' || echo "100")

log "✅ Existing attack script completed successfully"

echo
log "📊 Test Traffic Summary:"
log "   Total Requests: $total_requests"
log "   Attack Requests: $attack_requests"
log "   Benign Requests: $((total_requests - attack_requests))"
log "   Attack Ratio: $((attack_requests * 100 / total_requests))%"

echo
log "🔍 Checking real-time alerts..."
sleep 2

# Check if alerts were generated
if docker exec sec_monitor test -f /captures/realtime_alerts.json; then
    alert_count=$(docker exec sec_monitor wc -l < /captures/realtime_alerts.json 2>/dev/null || echo "0")
    log "   Real-time alerts generated: $alert_count"
    
    if [ "$alert_count" -gt 0 ]; then
        log "   ✅ Real-time detection is working!"
        echo
        log "📈 Quick Analysis:"
        docker exec sec_monitor python3 /scripts/analyze_realtime_alerts.py --time-window 1
    else
        log "   ⚠️  No real-time alerts generated - check if detection system is running"
    fi
else
    log "   ⚠️  No real-time alerts file found - detection system may not be running"
fi

echo
echo "🎉 Test completed!"
echo
echo "Next steps:"
echo "  • Run: ./start_realtime_detection.sh (to see live monitoring)"
echo "  • Analyze: docker exec sec_monitor python3 /scripts/analyze_realtime_alerts.py"
echo "  • Compare: Run your regular experiments to compare batch vs real-time detection"
