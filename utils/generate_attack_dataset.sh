#!/bin/bash
set -euo pipefail

# Generate Attack Dataset - XSS attacks using the existing attack script

DURATION="${1:-600}"
TIMESTAMP="${2:-$(date +"%Y%m%d_%H%M%S")}"
DATASET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/data/labeled_datasets"

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

log_error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] [ATTACK] ❌ $1${NC}"
}

# Disable Suricata rules for clean capture (same as benign)
log "🛡️ Disabling Suricata detection rules for clean capture..."
docker exec sec_monitor bash -c "
# Use the same no-alerts config as benign capture
if [ ! -f /etc/suricata/suricata_noalerts.yaml ]; then
    echo 'Creating no-alerts config...'
    cat > /etc/suricata/suricata_noalerts.yaml << 'EOF'
%YAML 1.1
---
# Minimal Suricata config for traffic capture only (no alerts)
vars:
  address-groups:
    HOME_NET: \"[100.64.0.0/24,!100.64.0.1]\"
    EXTERNAL_NET: \"![\$HOME_NET]\"
  port-groups:
    HTTP_PORTS: \"80\"
    SHELLCODE_PORTS: \"!80\"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000

default-log-dir: /var/log/suricata/

stats:
  enabled: yes
  interval: 8

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - http:
            extended: yes
        - stats:
            totals: yes
            threads: no
            deltas: no
        - flow
        - tcp

detect-engine:
  - profile: high
  - custom-values:
      toclient-groups: 3
      toserver-groups: 25
  - sgh-mpm-context: auto
  - inspection-recursion-limit: 3000

default-rule-path: /tmp/empty_rules
rule-files: []

logging:
  default-log-level: warning
  default-output-filter:
  outputs:
  - console:
      enabled: no
  - file:
      enabled: yes
      level: info
      filename: /var/log/suricata/suricata.log

stream:
  memcap: 64mb
  checksum-validation: yes
  inline: auto
  reassembly:
    memcap: 256mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

host-os-policy:
  windows: [0.0.0.0/0]
  bsd: []
  bsd-right: []
  old-linux: []
  linux: []
  old-solaris: []
  solaris: []
  hpux10: []
  hpux11: []
  irix: []
  macos: []
  vista: []
  windows2k3: []

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

app-layer:
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-minimal-inspect-size: 32kb
          request-body-inspect-window: 4kb
          response-body-minimal-inspect-size: 40kb
          response-body-inspect-window: 16kb
          response-body-decompress-layer-limit: 2
          http-body-inline: auto
          swf-decompression:
            enabled: yes
            type: both
            compress-depth: 0
            decompress-depth: 0
          double-decode-path: no
          double-decode-query: no
EOF
fi

mkdir -p /tmp/empty_rules
touch /tmp/empty_rules/empty.rules
"

# Clear previous capture
log "🗑️ Clearing previous capture data..."
docker exec sec_monitor rm -f /captures/eve.json /captures/attack_eve_${TIMESTAMP}.json

# Restart Suricata with no-alert config
log "🔄 Restarting Suricata in capture-only mode..."
docker exec sec_monitor bash -c "
pkill -f suricata || true
sleep 3
cd /captures
suricata -c /etc/suricata/suricata_noalerts.yaml -i eth0 -l /captures --pidfile /var/run/suricata/suricata.pid -D
sleep 5
"

log_success "Suricata restarted in capture-only mode"

# Modify the existing XSS attack script to run for the specified duration
log "🎯 Preparing XSS attack script for ${DURATION} seconds..."

# Create a temporary modified version of the attack script
docker exec sec_attacker bash -c "
cp /attack_scenarios/xss_attack.sh /tmp/xss_attack_timed.sh

# Modify the duration in the script
sed -i 's/DURATION_SECONDS=600/DURATION_SECONDS=$DURATION/' /tmp/xss_attack_timed.sh

# Make it executable
chmod +x /tmp/xss_attack_timed.sh
"

# Run the XSS attack script
log "🚨 Starting XSS attack generation for ${DURATION} seconds..."
log "⚡ Using the existing attack script: /attack_scenarios/xss_attack.sh"

# Run the attack script in the background and capture its output
docker exec sec_attacker bash -c "
export TARGET_IP=100.64.0.20
export PORT=3000
export DURATION_SECONDS=$DURATION

# Run the modified attack script
/tmp/xss_attack_timed.sh > /tmp/attack_output_${TIMESTAMP}.log 2>&1
" &

ATTACK_PID=$!

# Wait for attack to complete
log "⏳ Running XSS attacks for ${DURATION} seconds..."
sleep $((DURATION + 10))  # Add 10 seconds buffer

# Ensure attack process is complete
wait $ATTACK_PID 2>/dev/null || true

log "🛑 Stopping Suricata capture..."
docker exec sec_monitor pkill -f suricata || true
sleep 3

# Save the attack capture
log "💾 Saving attack capture data..."
docker exec sec_monitor bash -c "
if [ -f /captures/eve.json ]; then
    cp /captures/eve.json /captures/attack_eve_${TIMESTAMP}.json
    echo \"Attack capture saved: /captures/attack_eve_${TIMESTAMP}.json\"
    echo \"Attack events captured: \$(wc -l < /captures/attack_eve_${TIMESTAMP}.json)\"
    
    # Show some attack statistics
    echo \"HTTP events in attack capture: \$(grep -c '\"event_type\":\"http\"' /captures/attack_eve_${TIMESTAMP}.json || echo 0)\"
    echo \"XSS patterns detected: \$(grep -c -i 'script\\|alert\\|onerror\\|onload' /captures/attack_eve_${TIMESTAMP}.json || echo 0)\"
else
    echo \"Warning: No eve.json file found\"
fi
"

# Show attack summary
log "📊 Attack session summary:"
docker exec sec_attacker bash -c "
if [ -f /tmp/attack_output_${TIMESTAMP}.log ]; then
    echo \"Total attacks executed: \$(grep -c 'Attack [0-9]' /tmp/attack_output_${TIMESTAMP}.log || echo 0)\"
    echo \"Attack duration: ${DURATION} seconds\"
    echo \"Sample attacks:\"
    grep 'Attack [0-9]' /tmp/attack_output_${TIMESTAMP}.log | head -5 || echo 'No attack log found'
fi
"

# Restore original Suricata config (ready for normal operation)
log "🔄 Restoring original Suricata configuration..."
docker exec sec_monitor bash -c "
if [ -f /etc/suricata/suricata.yaml.backup ]; then
    mv /etc/suricata/suricata.yaml.backup /etc/suricata/suricata.yaml
fi
"

log_success "✅ Attack dataset generation completed!"
log "📁 Attack capture saved as: attack_eve_${TIMESTAMP}.json"
