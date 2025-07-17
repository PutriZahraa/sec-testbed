#!/bin/bash

# Real-time XSS Attack Monitor
# Filters eve.json for HTTP and Alert events only
# Optimized for XSS detection and ML training

echo "🎯 Starting Real-time XSS Attack Monitor"
echo "Filtering for HTTP and Alert events only..."

# Create focused output directory
mkdir -p data/captures/focused

# Function to filter and extract XSS-relevant events
filter_xss_events() {
    tail -F data/captures/eve.json | while read -r line; do
        # Check if line contains HTTP or Alert event
        if echo "$line" | grep -q '"event_type":"http"'; then
            # Extract XSS indicators from HTTP events
            url=$(echo "$line" | jq -r '.http.url // ""' 2>/dev/null)
            if [[ "$url" =~ (script|alert\(|onerror|onload|javascript:|svg|iframe|form.*action) ]]; then
                echo "[XSS-HTTP] $(date '+%H:%M:%S') - $url"
                echo "$line" >> data/captures/focused/xss_http_events.json
            fi
            
            # Also save all HTTP events for comparison
            echo "$line" >> data/captures/focused/http_events.json
            
        elif echo "$line" | grep -q '"event_type":"alert"'; then
            # Save all alert events
            echo "[ALERT] $(date '+%H:%M:%S') - $(echo "$line" | jq -r '.alert.signature // ""' 2>/dev/null)"
            echo "$line" >> data/captures/focused/alert_events.json
        fi
    done
}

# Start the filtering process
echo "📊 Real-time monitoring started..."
echo "🔍 XSS HTTP events: data/captures/focused/xss_http_events.json"
echo "📝 All HTTP events: data/captures/focused/http_events.json"  
echo "🚨 Alert events: data/captures/focused/alert_events.json"
echo ""

filter_xss_events
