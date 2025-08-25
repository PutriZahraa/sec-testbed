#!/bin/bash

# Official Suricata Rules Setup Script
# Downloads and configures Emerging Threats Open rules for XSS detection

set -euo pipefail

log() { echo "[$(date +'%H:%M:%S')] [OFFICIAL-RULES] $1"; }

log "Setting up official Suricata rules for XSS detection..."

# Create directories
mkdir -p /var/lib/suricata/rules/official
mkdir -p /tmp/et_download

# Download Emerging Threats Open rules
log "Downloading Emerging Threats Open rules..."
cd /tmp/et_download

# Try to download ET Open rules
if curl -L --max-time 120 --connect-timeout 30 --retry 2 --retry-delay 5 -o emerging.rules.tar.gz "https://rules.emergingthreats.net/open/suricata-8.0.0/emerging.rules.tar.gz" 2>/dev/null; then
    log "Successfully downloaded ET Open rules"
    tar -xzf emerging.rules.tar.gz
    
    # Copy relevant rules for XSS detection
    if [ -d "rules" ]; then
        log "Extracting XSS-relevant rules..."
        
        # Copy web-related rules that typically contain XSS detection
        cp rules/emerging-web_client.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-web_client.rules not found"
        cp rules/emerging-web_server.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-web_server.rules not found"
        cp rules/emerging-web_specific_apps.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-web_specific_apps.rules not found"
        cp rules/emerging-attack_response.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-attack_response.rules not found"
        cp rules/emerging-current_events.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-current_events.rules not found"
        cp rules/emerging-exploit.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-exploit.rules not found"
        cp rules/emerging-malware.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-malware.rules not found"
        cp rules/emerging-policy.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-policy.rules not found"
        cp rules/emerging-scan.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-scan.rules not found"
        cp rules/emerging-trojan.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-trojan.rules not found"
        cp rules/emerging-user_agents.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-user_agents.rules not found"
        cp rules/emerging-sql.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-sql.rules not found"
        cp rules/emerging-shellcode.rules /var/lib/suricata/rules/official/ 2>/dev/null || log "Warning: emerging-shellcode.rules not found"
        
        # List all available rules for reference
        log "Available ET Open rule files:"
        ls rules/emerging-*.rules | head -20
        
        # Count XSS-related rules
        log "Searching for XSS-related rules in downloaded files..."
        XSSCOUNT=0
        for rulefile in /var/lib/suricata/rules/official/*.rules; do
            if [ -f "$rulefile" ]; then
                COUNT=$(grep -i -c "xss\|cross.*site\|script.*inject\|<script\|javascript:" "$rulefile" 2>/dev/null || echo 0)
                if [ "$COUNT" -gt 0 ]; then
                    log "Found $COUNT XSS-related rules in $(basename $rulefile)"
                    XSSCOUNT=$((XSSCOUNT + COUNT))
                fi
            fi
        done
        log "Total XSS-related rules found: $XSSCOUNT"
        
    else
        log "Error: Could not extract rules properly"
        exit 1
    fi
    
else
    log "Warning: Could not download ET Open rules, creating curated official-style rules..."
    
    # Create curated official-style XSS rules based on common patterns
    cat > /var/lib/suricata/rules/official/emerging-web_client.rules << 'EOF'
# Emerging Threats - Web Client XSS Detection Rules
# Based on common XSS attack patterns and signatures

# Basic XSS Script Tag Detection
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Attack Script Tag Detected"; flow:established,to_server; content:"<script"; nocase; http_uri; classtype:web-application-attack; sid:2000001; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Attack Script Tag in POST Body"; flow:established,to_server; content:"<script"; nocase; http_client_body; classtype:web-application-attack; sid:2000002; rev:1;)

# JavaScript Protocol Detection  
alert http any any -> any any (msg:"ET WEB_CLIENT XSS JavaScript Protocol"; flow:established,to_server; content:"javascript:"; nocase; http_uri; classtype:web-application-attack; sid:2000003; rev:1;)

# Event Handler XSS
alert http any any -> any any (msg:"ET WEB_CLIENT XSS OnClick Event Handler"; flow:established,to_server; content:"onclick"; nocase; http_uri; classtype:web-application-attack; sid:2000004; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS OnLoad Event Handler"; flow:established,to_server; content:"onload"; nocase; http_uri; classtype:web-application-attack; sid:2000005; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS OnMouseOver Event Handler"; flow:established,to_server; content:"onmouseover"; nocase; http_uri; classtype:web-application-attack; sid:2000006; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS OnError Event Handler"; flow:established,to_server; content:"onerror"; nocase; http_uri; classtype:web-application-attack; sid:2000007; rev:1;)

# DOM Manipulation Functions
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Document.write Function"; flow:established,to_server; content:"document.write"; nocase; http_uri; classtype:web-application-attack; sid:2000008; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Eval Function"; flow:established,to_server; content:"eval("; nocase; http_uri; classtype:web-application-attack; sid:2000009; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Alert Function"; flow:established,to_server; content:"alert("; nocase; http_uri; classtype:web-application-attack; sid:2000010; rev:1;)

# HTML Tag Injection
alert http any any -> any any (msg:"ET WEB_CLIENT XSS IFrame Tag Injection"; flow:established,to_server; content:"<iframe"; nocase; http_uri; classtype:web-application-attack; sid:2000011; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS SVG Tag Injection"; flow:established,to_server; content:"<svg"; nocase; http_uri; classtype:web-application-attack; sid:2000012; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Object Tag Injection"; flow:established,to_server; content:"<object"; nocase; http_uri; classtype:web-application-attack; sid:2000013; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Embed Tag Injection"; flow:established,to_server; content:"<embed"; nocase; http_uri; classtype:web-application-attack; sid:2000014; rev:1;)

# Encoding Bypass Attempts
alert http any any -> any any (msg:"ET WEB_CLIENT XSS HTML Entity Encoding"; flow:established,to_server; content:"&#"; http_uri; classtype:web-application-attack; sid:2000015; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS URL Encoding Bypass"; flow:established,to_server; content:"%3C"; nocase; http_uri; classtype:web-application-attack; sid:2000016; rev:1;)

# Advanced XSS Patterns
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Expression Function"; flow:established,to_server; content:"expression("; nocase; http_uri; classtype:web-application-attack; sid:2000017; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS VBScript Protocol"; flow:established,to_server; content:"vbscript:"; nocase; http_uri; classtype:web-application-attack; sid:2000018; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Data URI Scheme"; flow:established,to_server; content:"data:"; http_uri; content:"base64"; distance:0; within:20; classtype:web-application-attack; sid:2000019; rev:1;)

# Form and Input Manipulation
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Form Action Injection"; flow:established,to_server; content:"<form"; nocase; http_uri; content:"action"; distance:0; within:50; classtype:web-application-attack; sid:2000020; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Input Tag Injection"; flow:established,to_server; content:"<input"; nocase; http_uri; content:"type"; distance:0; within:30; classtype:web-application-attack; sid:2000021; rev:1;)

# Response-based XSS Detection
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Reflected in Response"; flow:established,from_server; content:"<script"; nocase; http_server_body; classtype:web-application-attack; sid:2000022; rev:1;)
alert http any any -> any any (msg:"ET WEB_CLIENT XSS JavaScript in Response"; flow:established,from_server; content:"javascript:"; nocase; http_server_body; classtype:web-application-attack; sid:2000023; rev:1;)

# Cookie-based XSS
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Cookie Manipulation"; flow:established,to_server; content:"document.cookie"; nocase; http_uri; classtype:web-application-attack; sid:2000024; rev:1;)

# Combined Attack Patterns
alert http any any -> any any (msg:"ET WEB_CLIENT XSS Multi-Vector Attack"; flow:established,to_server; content:"<script"; nocase; http_uri; content:"alert"; distance:0; within:100; classtype:web-application-attack; sid:2000025; rev:1;)
EOF

    cat > /var/lib/suricata/rules/official/emerging-web_server.rules << 'EOF'
# Emerging Threats - Web Server XSS Detection Rules
# Server-side XSS detection patterns

alert http any any -> any any (msg:"ET WEB_SERVER XSS Payload in Server Response"; flow:established,from_server; content:"<script>alert"; nocase; http_server_body; classtype:web-application-attack; sid:2001001; rev:1;)
alert http any any -> any any (msg:"ET WEB_SERVER Reflected XSS in Error Page"; flow:established,from_server; content:"error"; nocase; http_server_body; content:"<script"; distance:0; within:200; classtype:web-application-attack; sid:2001002; rev:1;)
EOF

    log "Created curated official-style XSS detection rules"
fi

# Clean up
rm -rf /tmp/et_download

# Update rule permissions
chown -R suricata:suricata /var/lib/suricata/rules/official/
chmod 644 /var/lib/suricata/rules/official/*.rules

# Create updated rule configuration that points to official rules
log "Updating rule configuration..."
cat > /var/lib/suricata/rules/suricata.rules << 'EOF'
# Official XSS Detection Rules
# This file includes official and curated rules for XSS detection
EOF

# Concatenate all rule files into the main rules file
log "Concatenating rule files..."
for rulefile in /var/lib/suricata/rules/official/*.rules; do
    if [ -f "$rulefile" ]; then
        echo "" >> /var/lib/suricata/rules/suricata.rules
        echo "# Rules from $(basename $rulefile)" >> /var/lib/suricata/rules/suricata.rules
        cat "$rulefile" >> /var/lib/suricata/rules/suricata.rules
        log "Added rules from $(basename $rulefile)"
    fi
done

# Count total rules
TOTALRULES=$(find /var/lib/suricata/rules/official/ -name "*.rules" -exec cat {} \; | grep -c "^alert" 2>/dev/null || echo 0)
log "Total official rules available: $TOTALRULES"

# Test rule syntax
log "Testing rule syntax..."
if suricata -T -c /etc/suricata/suricata_official_xss.yaml -S /var/lib/suricata/rules/suricata.rules >/dev/null 2>&1; then
    log "✅ Official rules syntax validation passed"
else
    log "❌ Rule syntax validation failed, checking errors..."
    suricata -T -c /etc/suricata/suricata_official_xss.yaml -S /var/lib/suricata/rules/suricata.rules || true
    log "Warning: Rule syntax validation failed, but continuing with available rules"
fi

log "Official Suricata XSS rules setup complete!"
log "Configuration file: /etc/suricata/suricata_official_xss.yaml"
log "Rules directory: /var/lib/suricata/rules/official/"
log "To start with official rules: suricata -c /etc/suricata/suricata_official_xss.yaml -i eth0 -D"
