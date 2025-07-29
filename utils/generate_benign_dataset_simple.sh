#!/bin/bash
set -euo pipefail

# Simplified Benign Dataset Generation - Just capture with existing Suricata

DURATION="${1:-60}"
TIMESTAMP="${2:-$(date +"%Y%m%d_%H%M%S")}"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')] [BENIGN] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] [BENIGN] ✅ $1${NC}"
}

log "🌐 Starting benign traffic generation for ${DURATION} seconds..."

# Clear previous capture
log "🗑️ Clearing eve.json for fresh capture..."
docker exec sec_monitor bash -c "
cd /captures
> eve.json  # Clear the file
echo 'Cleared eve.json for benign capture'
"

# Generate benign traffic
log "📝 Simulating normal Juice Shop browsing behavior..."

# Start benign traffic generation
docker exec sec_attacker bash -c "
#!/bin/bash
TARGET_IP=100.64.0.20
PORT=3000
JUICE_URL=\"http://\${TARGET_IP}:\${PORT}\"
END_TIME=\$(( \$(date +%s) + $DURATION ))
INTERVAL=3  # Slow interval for benign traffic

echo \"[BENIGN] Starting normal browsing simulation...\"
echo \"[BENIGN] Target: \$JUICE_URL\"
echo \"[BENIGN] Duration: $DURATION seconds\"

request_count=0

while [ \"\$(date +%s)\" -lt \"\$END_TIME\" ]; do
    # Normal homepage visits
    echo \"[BENIGN] Homepage visit (\$request_count)\"
    curl -s \"\${JUICE_URL}/\" -o /dev/null
    ((request_count++))
    sleep \$INTERVAL

    # Browse products
    echo \"[BENIGN] Products API (\$request_count)\"
    curl -s \"\${JUICE_URL}/api/Products\" -o /dev/null
    ((request_count++))
    sleep \$INTERVAL

    # Legitimate searches
    legitimate_searches=(\"apple\" \"juice\" \"banana\" \"orange\" \"healthy\")
    search_term=\${legitimate_searches[\$RANDOM % \${#legitimate_searches[@]}]}
    echo \"[BENIGN] Search: \$search_term (\$request_count)\"
    curl -s \"\${JUICE_URL}/?q=\${search_term}\" -o /dev/null
    ((request_count++))
    sleep \$INTERVAL

    # API calls
    apis=(\"Challenges\" \"Users\" \"Baskets\")
    api=\${apis[\$RANDOM % \${#apis[@]}]}
    echo \"[BENIGN] API: \$api (\$request_count)\"
    curl -s \"\${JUICE_URL}/api/\${api}\" -o /dev/null 2>/dev/null || true
    ((request_count++))
    sleep \$INTERVAL
done

echo \"[BENIGN] Completed \$request_count benign requests\"
"

log "⏳ Waiting ${DURATION} seconds for benign traffic to complete..."
sleep $((DURATION + 5))

# Save the benign capture
log "💾 Saving benign capture data..."
docker exec sec_monitor bash -c "
if [ -f /captures/eve.json ] && [ -s /captures/eve.json ]; then
    cp /captures/eve.json /captures/benign_eve_${TIMESTAMP}.json
    echo \"Benign capture saved: /captures/benign_eve_${TIMESTAMP}.json\"
    echo \"Benign events captured: \$(wc -l < /captures/benign_eve_${TIMESTAMP}.json)\"
    echo \"HTTP events: \$(grep -c '\"event_type\":\"http\"' /captures/benign_eve_${TIMESTAMP}.json || echo 0)\"
else
    echo \"Warning: eve.json is empty or missing\"
    touch /captures/benign_eve_${TIMESTAMP}.json
fi
"

log_success "✅ Benign dataset generation completed!"
log "📁 Benign capture saved as: benign_eve_${TIMESTAMP}.json"
