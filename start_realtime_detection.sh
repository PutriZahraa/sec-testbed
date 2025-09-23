#!/bin/bash

# Real-Time XSS Detection Dashboard Launcher
# Starts the real-time monitoring system for XSS attacks

set -euo pipefail

log() { echo "[$(date +'%H:%M:%S')] $1"; }

echo "🚨 Real-Time XSS Detection System"
echo "=================================="

# Check if testbed is running
if ! docker compose ps | grep -q "sec_monitor.*Up"; then
    echo "❌ Error: Security testbed is not running"
    echo "Please start it first with: ./start_testbed.sh"
    exit 1
fi

echo
log "🔧 System Check:"

# Check if Suricata is running and generating events
if docker exec sec_monitor pgrep suricata >/dev/null; then
    log "   ✅ Suricata is running"
else
    log "   ⚠️  Suricata not detected - starting it now"
    docker exec sec_monitor bash -c "pkill -f suricata 2>/dev/null || true"
    sleep 2
    docker exec sec_monitor suricata -c /etc/suricata/suricata.yaml -i eth0 --runmode=autofp -D
    sleep 3
    log "   ✅ Suricata started"
fi

# Check if eve.json exists
if docker exec sec_monitor test -f /captures/eve.json; then
    log "   ✅ eve.json file exists"
    
    # Show current eve.json stats
    http_count=$(docker exec sec_monitor grep -c '"event_type":"http"' /captures/eve.json 2>/dev/null || echo "0")
    alert_count=$(docker exec sec_monitor grep -c '"event_type":"alert"' /captures/eve.json 2>/dev/null || echo "0")
    log "   📊 Current eve.json: ${http_count} HTTP events, ${alert_count} alerts"
else
    log "   ⚠️  eve.json not found - will be created by Suricata"
    docker exec sec_monitor touch /captures/eve.json
fi

echo
log "🎯 Starting Real-Time Detection:"
log "   • Mode 1: Suricata XSS rules (real-time alerts)"
log "   • Mode 2: ML pattern detection (real-time analysis)"
log "   • Dashboard: Live statistics every 5 seconds"
log "   • Alerts: Saved to /captures/realtime_alerts.json"
echo

echo "🚀 Launching Real-Time XSS Detector..."
echo "   Use Ctrl+C to stop monitoring"
echo "   Generate traffic to see detections in action!"
echo

# Start the real-time detector inside the monitor container
docker exec -it sec_monitor python3 /scripts/realtime_xss_detector.py
