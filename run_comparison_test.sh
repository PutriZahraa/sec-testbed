#!/bin/bash

# Comprehensive Mode 1 vs Mode 2 Comparison Test
# Purpose: Compare Suricata rule-based detection vs ML-based detection
# Note: This script runs from the host system

set -euo pipefail

echo "========================================"
echo "   SECURITY DETECTION COMPARISON TEST"
echo "========================================"
echo "1. Mode 1 (Suricata rules) + XSS attacks for 2 minutes"
echo "2. Mode 2 (ML detection) + XSS attacks for 2 minutes"
echo "========================================"

# Test duration (2 minutes)
TEST_DURATION=120
VICTIM_IP="100.64.0.20"

# Function to cleanup processes
cleanup() {
    echo "🧹 Cleaning up processes..."
    docker exec sec_monitor pkill -f suricata || true
    docker exec sec_attacker pkill -f xss_attack || true
    docker exec sec_monitor pkill -f start_mode || true
    sleep 2
}

# Function to run XSS attacks
run_xss_attacks() {
    local mode=$1
    echo "🔥 Starting XSS attacks for $mode..."
    
    # Start XSS attack in background
    docker exec sec_attacker /xss_attack.sh $VICTIM_IP &
    XSS_PID=$!
    
    # Let it run for test duration
    sleep $TEST_DURATION
    
    # Stop attacks
    docker exec sec_attacker pkill -f xss_attack || true
    wait $XSS_PID 2>/dev/null || true
    
    echo "✅ XSS attacks completed for $mode"
}

# Function to analyze results
analyze_results() {
    echo ""
    echo "📊 ANALYSIS RESULTS:"
    echo "===================="
    
    # Mode 1 Results
    echo "Mode 1 (Suricata Rules) Results:"
    docker exec sec_monitor bash -c '
        if [ -d "/captures/mode1_http_alerts" ]; then
            echo "  - Events directory: /captures/mode1_http_alerts/"
            
            # Count alert files
            ALERT_COUNT=$(find /captures/mode1_http_alerts -name "*.json" 2>/dev/null | wc -l)
            echo "  - Alert files generated: $ALERT_COUNT"
            
            # Check if Suricata log exists
            if [ -f "/captures/mode1_http_alerts/suricata.log" ]; then
                SURICATA_EVENTS=$(wc -l < /captures/mode1_http_alerts/suricata.log)
                echo "  - Suricata events logged: $SURICATA_EVENTS"
            fi
            
            # Check for eve.json
            if [ -f "/captures/mode1_http_alerts/eve.json" ]; then
                EVE_EVENTS=$(wc -l < /captures/mode1_http_alerts/eve.json)
                echo "  - Eve.json events: $EVE_EVENTS"
            fi
            
            # List captured files
            echo "  - Captured files:"
            ls -la /captures/mode1_http_alerts/ 2>/dev/null | head -10
        else
            echo "  - No output directory found"
        fi
    '
    
    echo ""
    
    # Mode 2 Results  
    echo "Mode 2 (ML Detection) Results:"
    docker exec sec_monitor bash -c '
        if [ -d "/captures/mode2_http_only" ]; then
            echo "  - Events directory: /captures/mode2_http_only/"
            
            # Count detection files
            DETECTION_COUNT=$(find /captures/mode2_http_only -name "*.json" 2>/dev/null | wc -l)
            echo "  - Detection files generated: $DETECTION_COUNT"
            
            # Check for ML predictions
            if [ -f "/captures/mode2_http_only/ml_predictions.json" ]; then
                ML_PREDICTIONS=$(wc -l < /captures/mode2_http_only/ml_predictions.json)
                echo "  - ML predictions: $ML_PREDICTIONS"
            fi
            
            # Check for HTTP events
            if [ -f "/captures/mode2_http_only/http_events.json" ]; then
                HTTP_EVENTS=$(wc -l < /captures/mode2_http_only/http_events.json)
                echo "  - HTTP events captured: $HTTP_EVENTS"
            fi
            
            # List captured files
            echo "  - Captured files:"
            ls -la /captures/mode2_http_only/ 2>/dev/null | head -10
        else
            echo "  - No output directory found"
        fi
    '
    
    echo ""
    echo "📁 Raw data locations:"
    echo "  - Mode 1: /captures/mode1_http_alerts/"
    echo "  - Mode 2: /captures/mode2_http_only/"
    echo "  - Analysis: /analysis/"
}

# Main execution
main() {
    echo "🚀 Starting comparison test..."
    
    # Initial cleanup
    cleanup
    
    # ===== MODE 1 TEST =====
    echo ""
    echo "🔍 Phase 1: Mode 1 (Suricata Rules) Testing"
    echo "============================================"
    
    echo "Starting Mode 1 (Suricata rules + HTTP alerts) monitoring..."
    docker exec sec_monitor /start_mode1_http_alerts.sh &
    MODE1_PID=$!
    
    # Wait for Suricata to start
    echo "Waiting for Suricata to initialize..."
    sleep 5
    
    # Check if Suricata is running
    if ! docker exec sec_monitor pgrep -f suricata > /dev/null; then
        echo "ERROR: Suricata failed to start in Mode 1"
        exit 1
    fi
    
    echo "✅ Mode 1 monitoring started successfully"
    
    # Run XSS attacks for 2 minutes
    run_xss_attacks "Mode 1"
    
    # Stop Mode 1
    echo "Stopping Mode 1 monitoring..."
    kill $MODE1_PID 2>/dev/null || true
    cleanup
    
    echo "✅ Mode 1 test completed"
    
    # ===== MODE 2 TEST =====
    echo ""
    echo "🤖 Phase 2: Mode 2 (ML Detection) Testing"
    echo "========================================="
    
    echo "Starting Mode 2 (HTTP only + ML detection) monitoring..."
    docker exec sec_monitor /start_mode2_http_only.sh &
    MODE2_PID=$!
    
    # Wait for Suricata to start
    echo "Waiting for Suricata to initialize..."
    sleep 5
    
    # Check if Suricata is running
    if ! docker exec sec_monitor pgrep -f suricata > /dev/null; then
        echo "ERROR: Suricata failed to start in Mode 2"
        exit 1
    fi
    
    echo "✅ Mode 2 monitoring started successfully"
    
    # Run XSS attacks for 2 minutes
    run_xss_attacks "Mode 2"
    
    # Stop Mode 2
    echo "Stopping Mode 2 monitoring..."
    kill $MODE2_PID 2>/dev/null || true
    cleanup
    
    echo "✅ Mode 2 test completed"
    
    # ===== ANALYSIS =====
    echo ""
    echo "📊 Analyzing results..."
    analyze_results
    
    echo ""
    echo "🎉 Comparison test completed successfully!"
    echo "📋 Review the analysis above and check the output directories for detailed results."
}

# Run main function
main "$@"
