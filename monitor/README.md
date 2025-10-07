# Security Testbed Monitoring Guide

## Overview
This guide provides step-by-step instructions for running the current detection comparison framework:
- **Mode 1**: Suricata custom XSS rules based on attack patterns 1-20
- **Mode 2**: ML-based XSS detection using RandomForestClassifier with 8 HTTP features
- **Target**: OWASP Juice Shop on port 3000 for realistic XSS vulnerability testing

## Prerequisites
- Security testbed running (`./start_testbed.sh`)
- All containers operational (attacker, victim, monitor, switch)
- Network connectivity between containers established

## Current Workflow (6-Step Process)

The testbed follows a standardized 6-step workflow for detection comparison:

### Step 1: Start Testbed
```bash
./start_testbed.sh
```
Initializes all containers (attacker, victim, monitor, switch) and starts the testbed environment.

### Step 2: Clear Previous Logs (optional)
```bash
docker exec sec_monitor truncate -s 0 /captures/eve.json
```
Clears the eve.json file to ensure clean detection analysis for new traffic.

### Step 3: Generate Mixed Traffic
```bash
docker exec sec_attacker bash -c './randomized_mixed_attack.sh'
```
Generates randomized mixed traffic with 40% XSS attacks and 60% benign requests.

### Step 4: Analyze Detection Results
```bash
docker exec sec_monitor python3 /scripts/analyze_consolidated_detection.py /captures/eve.json
```
Compares Mode 1 (Suricata rules) vs Mode 2 (ML detection) results and shows detection performance.

### Step 5: Automated Experiment (alternative)
```bash
./run_custom_experiment.sh
```
Runs a complete automated experiment with exactly 200 requests.

### Step 6: Generate Dataset (for ML training)
```bash
./utils/generate_datasets.sh <duration_in_seconds>
```
Generates labeled datasets containing both attack and benign traffic for ML model training.

## System Verification

### Quick Health Check
Verify all components are working before analysis:

```bash
# 1. Check container status
docker ps | grep -E "(sec_monitor|sec_attacker|sec_victim|sec_switch)"

# 2. Check network connectivity
docker exec sec_attacker ping -c 2 100.64.0.20

# 3. Verify OWASP Juice Shop is accessible
docker exec sec_attacker curl -s http://100.64.0.20:3000/ | head -1

# 4. Check if eve.json is being populated
docker exec sec_monitor ls -la /captures/eve.json
docker exec sec_monitor tail -5 /captures/eve.json

# 5. Verify Suricata is running
docker exec sec_monitor ps aux | grep suricata
```

### Troubleshooting Common Issues

**Containers not running:**
```bash
cd /home/ubuntu/sec-testbed
./start_testbed.sh
```

**Network connectivity issues:**
```bash
# Check container networking
docker exec sec_attacker ip route
docker exec sec_victim ss -tlnp | grep 3000
```

**Eve.json not populated:**
```bash
# Check Suricata status and logs
docker exec sec_monitor ps aux | grep suricata
docker exec sec_monitor tail -20 /var/log/suricata/suricata.log

# Restart monitoring if needed
docker exec sec_monitor /start_suricata_monitoring.sh
```

## Detection Analysis Components

### Current Scripts Available

1. **`analyze_consolidated_detection.py`** - **Main Analysis Script**
   - Compares Mode 1 (Suricata rules) vs Mode 2 (ML detection)
   - Processes eve.json logs from Suricata
   - Provides consolidated comparison output

2. **`mode2_ml_detector.py`** - **ML Detection Engine**
   - RandomForestClassifier with 8 HTTP features
   - Processes HTTP events for XSS detection
   - Provides confidence scores

3. **`realtime_xss_detector.py`** - **Real-time Detection**
   - Live analysis of incoming traffic
   - Real-time XSS pattern detection

4. **`eve_processor.py`** - **Log Processing**
   - Suricata eve.json log processing utilities
   - HTTP event extraction and analysis

## Analysis Workflow Details

### Manual Mode Comparison
If you want to run the analysis step-by-step:

**Step 1: Generate Test Traffic**
```bash
# Clear previous logs (optional)
docker exec sec_monitor truncate -s 0 /captures/eve.json

# Generate mixed traffic (40% attacks, 60% benign)
docker exec sec_attacker bash -c './randomized_mixed_attack.sh'

# Verify traffic was generated
docker exec sec_monitor wc -l /captures/eve.json
docker exec sec_monitor grep -c '"event_type":"http"' /captures/eve.json
```

**Step 2: Run Consolidated Analysis**
```bash
# Main analysis script (compares both modes)
docker exec sec_monitor python3 /scripts/analyze_consolidated_detection.py /captures/eve.json
```

**Expected Output Example:**
```
� CONSOLIDATED MODE COMPARISON ANALYSIS
========================================

📊 TRAFFIC ANALYSIS:
   Total HTTP Requests: 200
   Attack Requests: ~40% (randomized XSS patterns)
   Benign Requests: ~60% (normal navigation)

🔍 MODE 1 - SURICATA XSS RULES:
   Rule Triggers: 45 alerts
   Detection Rate: 22.5%

🤖 MODE 2 - ML DETECTION:
   ML Detections: 52 attacks
   Detection Rate: 26.0%
   Model: RandomForestClassifier (8 features)

� COMPARISON SUMMARY:
   ML shows +3.5% better detection rate
   Hybrid approach recommended for optimal coverage
```

### Individual Script Usage

**ML Detection Only:**
```bash
docker exec sec_monitor python3 /scripts/mode2_ml_detector.py /captures/eve.json
```

**Real-time Detection:**
```bash
docker exec sec_monitor python3 /scripts/realtime_xss_detector.py
```

**Log Processing:**
```bash
docker exec sec_monitor python3 /scripts/eve_processor.py /captures/eve.json
```

## Understanding Results

### Detection Metrics
- **Mode 1 (Suricata Rules)**: Based on custom XSS rules for attack patterns 1-20
- **Mode 2 (ML Detection)**: RandomForestClassifier with 8 HTTP features
- **Traffic Mix**: 40% XSS attacks (patterns 21-40), 60% benign requests
- **Target**: OWASP Juice Shop vulnerable web application

### ML Model Features
The ML detection system analyzes these 8 HTTP features:
1. `src_port` - Source port analysis
2. `dest_port` - Destination port patterns  
3. `http_status` - HTTP response codes
4. `http_resp_len` - Response length analysis
5. `http_url_len` - URL length patterns
6. `url_contains_script_tag` - Script tag detection
7. `url_contains_onerror` - Event handler detection
8. `http_method_POST` - HTTP method analysis

### Detection Rate Interpretation
- **Detection Rate**: Percentage of HTTP traffic flagged as attacks
- **Not Effectiveness**: Requires knowing actual attack rate in traffic
- **Realistic Range**: 20-40% detection rate is normal for mixed traffic with 40% actual attacks

## Data Storage and Files

### Key Locations
- **Capture Data**: `/captures/eve.json` - Suricata event logs
- **Analysis Scripts**: `/scripts/` - Detection and analysis scripts
- **Rules**: `/etc/suricata/` - Suricata configuration and rules
- **Logs**: `/var/log/suricata/` - Suricata system logs

### Host Data Directories
- **`data/captures/`** - Packet captures and Suricata logs
- **`data/labeled_datasets/`** - Generated datasets (attack, benign, combined)
- **`data/analysis/`** - Detection analysis reports and comparisons

### Useful Commands
```bash
# View recent HTTP events
docker exec sec_monitor tail -20 /captures/eve.json | grep '"event_type":"http"' | jq .

# Count attack alerts
docker exec sec_monitor grep -c '"event_type":"alert"' /captures/eve.json

# Monitor live traffic
docker exec sec_monitor tail -f /captures/eve.json | grep '"event_type":"http"'

# Check Suricata rules being used
docker exec sec_monitor cat /etc/suricata/rules/*.rules | head -10
```

## Troubleshooting

### Common Issues

**No HTTP events in eve.json:**
```bash
# Check if Suricata is running
docker exec sec_monitor ps aux | grep suricata

# Check Suricata logs for errors
docker exec sec_monitor tail -20 /var/log/suricata/suricata.log

# Restart Suricata if needed
docker exec sec_monitor /start_suricata_monitoring.sh
```

**Analysis script errors:**
```bash
# Verify script exists
docker exec sec_monitor ls -la /scripts/analyze_consolidated_detection.py

# Check Python dependencies
docker exec sec_monitor python3 -c "import json, re, sys; print('Basic dependencies OK')"

# Run with verbose output
docker exec sec_monitor python3 -v /scripts/analyze_consolidated_detection.py /captures/eve.json
```

**No attack detections:**
```bash
# Verify attack traffic was generated
docker exec sec_monitor grep 'script' /captures/eve.json | head -5

# Check if rules are loaded
docker exec sec_monitor grep -c "alert" /etc/suricata/rules/*.rules

# Manual rule test
docker exec sec_attacker curl "http://100.64.0.20:3000/?q=<script>alert(1)</script>"
```

## Quick Reference

### Essential Commands
```bash
# Complete workflow (automated)
./run_custom_experiment.sh

# Manual step-by-step
./start_testbed.sh
docker exec sec_monitor truncate -s 0 /captures/eve.json
docker exec sec_attacker bash -c './randomized_mixed_attack.sh'
docker exec sec_monitor python3 /scripts/analyze_consolidated_detection.py /captures/eve.json

# Dataset generation
./utils/generate_datasets.sh 60

# System status
./utils/status.sh
```

### File Structure Summary
```
monitor/
├── scripts/
│   ├── analyze_consolidated_detection.py  # Main comparison script
│   ├── mode2_ml_detector.py              # ML detection engine
│   ├── realtime_xss_detector.py          # Real-time analysis
│   └── eve_processor.py                  # Log processing utilities
├── rules/
│   └── standard_xss_rules.rules          # Custom XSS detection rules
└── README.md                             # This guide
```

## Access Services
- **OWASP Juice Shop**: http://100.64.0.20:3000
- **Container Access**: `docker exec -it sec_monitor bash`

## Best Practices

1. **Clean Environment**: Use `truncate -s 0 /captures/eve.json` between tests
2. **Sufficient Traffic**: Generate enough requests for meaningful analysis  
3. **Document Results**: Save analysis outputs for comparison
4. **Consistent Testing**: Use same attack patterns for reproducible results
5. **Monitor Resources**: Check container logs if performance issues occur

## Support

For issues:
1. Check the main project README.md for complete setup instructions
2. Use `./utils/status.sh` to verify system health
3. Review troubleshooting section above
4. Check container logs: `docker logs sec_monitor`
