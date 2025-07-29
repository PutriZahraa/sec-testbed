#!/bin/bash
set -euo pipefail

# Simplified Attack Dataset Generation - Just capture with existing Suricata

DURATION="${1:-60}"
TIMESTAMP="${2:-$(date +"%Y%m%d_%H%M%S")}"

# Colors
RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')] [ATTACK] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] [ATTACK] ✅ $1${NC}"
}

# Wait a moment for any previous processes to clear
sleep 5

# Clear previous capture
log "🗑️ Clearing eve.json for attack capture..."
docker exec sec_monitor bash -c "
cd /captures
> eve.json  # Clear the file
echo 'Cleared eve.json for attack capture'
"

# Run XSS attacks
log "🚨 Starting XSS attack generation for ${DURATION} seconds..."
log "⚡ Using existing attack script with configurable duration"

# Run the attack script
docker exec sec_attacker bash -c "
export TARGET_IP=100.64.0.20
export PORT=3000
export DURATION_SECONDS=$DURATION

echo '[ATTACK] Starting XSS attack session...'
/attack_scenarios/xss_attack.sh > /tmp/attack_output_${TIMESTAMP}.log 2>&1 &
ATTACK_PID=\$!

# Wait for attacks to complete
sleep $((DURATION + 5))

# Show attack summary
echo '[ATTACK] Attack session completed'
if [ -f /tmp/attack_output_${TIMESTAMP}.log ]; then
    echo \"Total attack lines: \$(wc -l < /tmp/attack_output_${TIMESTAMP}.log)\"
    echo \"Sample attacks:\"
    grep 'Attack [0-9]' /tmp/attack_output_${TIMESTAMP}.log | head -3 || echo 'No attack patterns found'
fi
"

# Save the attack capture
log "💾 Saving attack capture data..."
docker exec sec_monitor bash -c "
if [ -f /captures/eve.json ] && [ -s /captures/eve.json ]; then
    cp /captures/eve.json /captures/attack_eve_${TIMESTAMP}.json
    echo \"Attack capture saved: /captures/attack_eve_${TIMESTAMP}.json\"
    echo \"Attack events captured: \$(wc -l < /captures/attack_eve_${TIMESTAMP}.json)\"
    echo \"HTTP events: \$(grep -c '\"event_type\":\"http\"' /captures/attack_eve_${TIMESTAMP}.json || echo 0)\"
    echo \"XSS patterns: \$(grep -c -i 'script\\|alert\\|onerror' /captures/attack_eve_${TIMESTAMP}.json || echo 0)\"
else
    echo \"Warning: eve.json is empty or missing\"
    touch /captures/attack_eve_${TIMESTAMP}.json
fi
"

log_success "✅ Attack dataset generation completed!"
log "📁 Attack capture saved as: attack_eve_${TIMESTAMP}.json"
