#!/bin/bash
set -euo pipefail

# Generate Benign Dataset - Normal Juice Shop browsing without attacks

DURATION="${1:-600}"
TIMESTAMP="${2:-$(date +"%Y%m%d_%H%M%S")}"
DATASET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/data/labeled_datasets"

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

# Disable Suricata rules for clean capture
log "🛡️ Disabling Suricata detection rules for clean capture..."
docker exec sec_monitor bash -c "
# Backup current rules
cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup 2>/dev/null || true

# Create minimal config without detection rules
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

# Global stats configuration
stats:
  enabled: yes
  interval: 8

# Configure outputs - eve.json only, no alerts
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
        # Disable alerts for benign capture
        # - alert

# Disable all detection
detect-engine:
  - profile: high
  - custom-values:
      toclient-groups: 3
      toserver-groups: 25
  - sgh-mpm-context: auto
  - inspection-recursion-limit: 3000

# Disable rule loading
default-rule-path: /tmp/empty_rules
rule-files: []

# Logging configuration
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

# Basic stream configuration
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

# Host OS policy
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

# Configure af-packet
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

# Basic app layer configuration
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

# Create empty rules directory
mkdir -p /tmp/empty_rules
touch /tmp/empty_rules/empty.rules
"

# Clear previous capture
log "🗑️ Clearing previous capture data..."
docker exec sec_monitor rm -f /captures/eve.json /captures/benign_eve_${TIMESTAMP}.json

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

# Generate benign traffic
log "🌐 Starting benign traffic generation for ${DURATION} seconds..."
log "📝 Simulating normal Juice Shop browsing behavior..."

# Start benign traffic in background
docker exec sec_attacker bash -c "
#!/bin/bash
TARGET_IP=100.64.0.20
PORT=3000
JUICE_URL=\"http://\${TARGET_IP}:\${PORT}\"
END_TIME=\$(( \$(date +%s) + $DURATION ))
INTERVAL=5  # Slower interval for benign traffic

ts() { date +\"%Y-%m-%dT%H:%M:%S.%3N%:z\"; }

echo \"[BENIGN] Starting normal browsing simulation...\"
echo \"[BENIGN] Target: \$JUICE_URL\"
echo \"[BENIGN] Duration: $DURATION seconds\"

request_count=0

while [ \"\$(date +%s)\" -lt \"\$END_TIME\" ]; do
    # Normal homepage visits
    echo \"[\$(ts)] [BENIGN] Homepage visit\"
    curl -s \"\${JUICE_URL}/\" -o /dev/null
    ((request_count++))
    sleep \$INTERVAL

    # Browse products
    echo \"[\$(ts)] [BENIGN] Products page\"
    curl -s \"\${JUICE_URL}/api/Products\" -o /dev/null
    ((request_count++))
    sleep \$INTERVAL

    # Check challenges
    echo \"[\$(ts)] [BENIGN] Challenges page\"
    curl -s \"\${JUICE_URL}/api/Challenges\" -o /dev/null
    ((request_count++))
    sleep \$INTERVAL

    # Search for legitimate terms
    legitimate_searches=(\"apple\" \"juice\" \"product\" \"banana\" \"orange\" \"search\" \"healthy\" \"organic\" \"fresh\")
    search_term=\${legitimate_searches[\$RANDOM % \${#legitimate_searches[@]}]}
    echo \"[\$(ts)] [BENIGN] Search: \$search_term\"
    curl -s \"\${JUICE_URL}/?q=\${search_term}\" -o /dev/null
    ((request_count++))
    sleep \$INTERVAL

    # Browse images
    images=(\"apple_juice.jpg\" \"banana_juice.jpg\" \"carrot_juice.jpg\" \"green_juice.jpg\")
    image=\${images[\$RANDOM % \${#images[@]}]}
    echo \"[\$(ts)] [BENIGN] Image: \$image\"
    curl -s \"\${JUICE_URL}/assets/public/images/products/\${image}\" -o /dev/null
    ((request_count++))
    sleep \$INTERVAL

    # About page
    echo \"[\$(ts)] [BENIGN] About page\"
    curl -s \"\${JUICE_URL}/#/about\" -o /dev/null
    ((request_count++))
    sleep \$INTERVAL

    # Random legitimate API calls
    apis=(\"Users\" \"Products\" \"Baskets\" \"Feedbacks\" \"Captchas\")
    api=\${apis[\$RANDOM % \${#apis[@]}]}
    echo \"[\$(ts)] [BENIGN] API: \$api\"
    curl -s \"\${JUICE_URL}/api/\${api}\" -o /dev/null
    ((request_count++))
    sleep \$INTERVAL
done

echo \"[BENIGN] Completed \$request_count benign requests\"
" > /tmp/benign_traffic.log 2>&1 &

BENIGN_PID=$!

# Wait for capture to complete
log "⏳ Capturing benign traffic for ${DURATION} seconds..."
sleep $DURATION

# Stop benign traffic
kill $BENIGN_PID 2>/dev/null || true

log "🛑 Stopping Suricata capture..."
docker exec sec_monitor pkill -f suricata || true
sleep 3

# Save the benign capture
log "💾 Saving benign capture data..."
docker exec sec_monitor bash -c "
if [ -f /captures/eve.json ]; then
    cp /captures/eve.json /captures/benign_eve_${TIMESTAMP}.json
    echo \"Benign capture saved: /captures/benign_eve_${TIMESTAMP}.json\"
    echo \"Benign events captured: \$(wc -l < /captures/benign_eve_${TIMESTAMP}.json)\"
else
    echo \"Warning: No eve.json file found\"
fi
"

# Restore original Suricata config
log "🔄 Restoring original Suricata configuration..."
docker exec sec_monitor bash -c "
if [ -f /etc/suricata/suricata.yaml.backup ]; then
    mv /etc/suricata/suricata.yaml.backup /etc/suricata/suricata.yaml
else
    echo 'No backup found, keeping current config'
fi
"

log_success "✅ Benign dataset generation completed!"
log "📁 Benign capture saved as: benign_eve_${TIMESTAMP}.json"
