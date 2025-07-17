# Security Testbed Monitoring Guide

## Overview
This guide provides step-by-step instructions for comparing two detection methods:
- **Mode 1**: Suricata rule-based detection 
- **Mode 2**: Machine Learning-based detection

## Prerequisites
- Security testbed running (`./start_testbed.sh`)
- Attack scenarios available in attacker container
- ML model trained and available (`/scripts/models/detection_model.pkl`)

## Pre-Flight Checks

### Step 0: Verify System Status
Before running any analysis, ensure all components are working:

```bash
# 1. Check if containers are running
docker ps | grep -E "(sec_monitor|sec_attacker|sec_victim)"

# 2. Verify Suricata is running in monitor container
docker exec sec_monitor ps aux | grep suricata

# 3. Check if eve.json exists and is being populated
docker exec sec_monitor ls -la /captures/eve.json
docker exec sec_monitor tail -5 /captures/eve.json

# 4. Verify network connectivity
docker exec sec_attacker ping -c 2 100.64.0.20
docker exec sec_attacker curl -s http://100.64.0.20:3000/ | head -10

# 5. Check ML model availability
docker exec sec_monitor ls -la /scripts/models/detection_model.pkl
```

### Troubleshooting Setup Issues

**If containers are not running:**
```bash
cd /home/ubuntu/sec-testbed
./start_testbed.sh
```

**If Suricata is not running:**
```bash
docker exec sec_monitor /start_suricata_monitoring.sh
```

**If eve.json doesn't exist or is empty:**
```bash
# Check Suricata logs for errors
docker exec sec_monitor tail -20 /var/log/suricata/suricata.log

# Restart Suricata monitoring
docker restart sec_monitor
```

**Manual Suricata Control Commands:**
```bash
# Start Suricata manually
docker exec sec_monitor suricata -c /etc/suricata/suricata.yaml -i eth0 --runmode=autofp -D

# Stop Suricata processes
docker exec sec_monitor pkill -f suricata

# Kill all Suricata processes (force stop)
docker exec sec_monitor killall suricata

# Check Suricata process status
docker exec sec_monitor ps aux | grep suricata

# Start Suricata in foreground (for debugging)
docker exec -it sec_monitor suricata -c /etc/suricata/suricata.yaml -i eth0 --runmode=autofp

# Restart Suricata service
docker exec sec_monitor bash -c "pkill -f suricata && sleep 2 && /start_suricata_monitoring.sh"
```

**If victim service is not responding:**
```bash
# Check victim container
docker exec sec_victim ps aux | grep -E "(juice|node)"

# Restart victim if needed
docker restart sec_victim
```

**If ML model is missing:**
```bash
# Check if models directory exists
docker exec sec_monitor ls -la /scripts/models/

# You'll need to train and place your model there
# See "ML Model Setup" section below
```

## Suricata Management

### Manual Suricata Control
Essential commands for managing Suricata processes:

```bash
# Check if Suricata is running
docker exec sec_monitor ps aux | grep suricata | grep -v grep

# Start Suricata (daemon mode)
docker exec sec_monitor suricata -c /etc/suricata/suricata.yaml -i eth0 --runmode=autofp -D

# Stop Suricata (graceful)
docker exec sec_monitor pkill -f suricata

# Force kill Suricata
docker exec sec_monitor killall suricata

# Restart Suricata service
docker exec sec_monitor bash -c "pkill -f suricata && sleep 3 && /start_suricata_monitoring.sh"

# Check Suricata logs
docker exec sec_monitor tail -f /var/log/suricata/suricata.log

# Check eve.json output
docker exec sec_monitor tail -f /captures/eve.json

# Test Suricata configuration
docker exec sec_monitor suricata -T -c /etc/suricata/suricata.yaml
```

### Suricata Debugging
```bash
# Start Suricata in foreground (for debugging)
docker exec -it sec_monitor suricata -c /etc/suricata/suricata.yaml -i eth0 --runmode=autofp -v

# Check network interfaces
docker exec sec_monitor ip addr show

# Check if interface is receiving traffic
docker exec sec_monitor tcpdump -i eth0 -c 10

# Verify Suricata configuration file
docker exec sec_monitor cat /etc/suricata/suricata.yaml | grep -A 5 "eve-log:"
```

## Mode Comparison Workflow

### Step 1: Generate Mixed Traffic
Generate realistic mixed traffic with both attacks and benign requests:

```bash
# First, verify current eve.json baseline
docker exec sec_monitor wc -l /captures/eve.json

# Generate mixed traffic using randomized attack script
docker exec -it sec_attacker ./attack_scenarios/randomized_mixed_attack.sh

# Verify new traffic was generated
docker exec sec_monitor wc -l /captures/eve.json
docker exec sec_monitor tail -10 /captures/eve.json | grep '"event_type":"http"'
```

**Verification**: You should see HTTP events in eve.json with various URLs including XSS payloads.

This creates a realistic traffic mix where approximately 27% are XSS attacks and 73% are benign requests.

### Step 2: Run Mode 1 Analysis (Suricata Rules)
Analyze how well Suricata rules detect attacks:

```bash
# First check if eve.json has HTTP events
docker exec sec_monitor grep -c '"event_type":"http"' /captures/eve.json

# Check if there are any alert events
docker exec sec_monitor grep -c '"event_type":"alert"' /captures/eve.json

# Run simple Mode 1 analysis (rules-based detection)
docker exec sec_monitor python3 /scripts/analyze_mode1_simple.py /captures/eve.json
```

**If you get "file not found" errors:**
```bash
# Check if the analysis script exists
docker exec sec_monitor ls -la /scripts/analyze_mode1_simple.py

# If missing, use manual analysis
echo "=== Manual Mode 1 Analysis ==="
echo "HTTP Events:"
docker exec sec_monitor grep -c '"event_type":"http"' /captures/eve.json
echo "Alert Events:"
docker exec sec_monitor grep -c '"event_type":"alert"' /captures/eve.json
```

**Expected Output:**
```
📊 MODE 1 SURICATA ANALYSIS SUMMARY
================================
Total HTTP Requests: 59
Alert Events Generated: 23
Detection Rate: 39.0%

🔍 SURICATA RULE ANALYSIS:
   Rule Detection: Active
   XSS-related Alerts: 23
   Total Rule Triggers: 23

📋 ALERT SIGNATURES:
    14x XSS Attack Detected - Alert Function
     3x XSS Attack Detected - OnLoad Event
     2x XSS Attack Detected - JavaScript Event
```

### Step 3: Run Mode 2 Analysis (ML Detection)
Analyze ML model effectiveness:

```bash
# Verify ML model is available and properly formatted
docker exec sec_monitor python3 -c "
import pickle
try:
    with open('/scripts/models/detection_model.pkl', 'rb') as f:
        model = pickle.load(f)
    print('✅ Model loaded successfully')
    print('Model type:', type(model))
    if isinstance(model, dict):
        print('Keys:', list(model.keys()))
        print('Features:', len(model.get('feature_names', [])))
except Exception as e:
    print('❌ Model error:', e)
"

# Run Mode 2 analysis (ML-based detection)
docker exec sec_monitor python3 /scripts/mode2_ml_detector.py /captures/eve.json
```

**If model loading fails:**
```bash
# Check model file exists and permissions
docker exec sec_monitor ls -la /scripts/models/detection_model.pkl

# Check sklearn version compatibility
docker exec sec_monitor python3 -c "import sklearn; print('sklearn version:', sklearn.__version__)"
```

**Expected Output:**
```
📊 MODE 2 ML DETECTION SUMMARY
============================
Total HTTP Requests: 118
XSS Attacks Detected: 32
Detection Rate: 27.1%

🤖 ML DETECTION ANALYSIS:
   Model Type: RandomForestClassifier
   Features Used: 8
   
📊 DETECTION RATE ANALYSIS:
   Detection Rate: 27.1% of HTTP traffic flagged as attacks
   Detected Attacks: 32
   Total HTTP Requests: 118
   Unflagged Requests: 86
```

### Step 4: Compare Results
Run side-by-side comparison:

```bash
# First verify you have results from both modes
docker exec sec_monitor python3 -c "
import json
import os

# Check for HTTP events
try:
    with open('/captures/eve.json', 'r') as f:
        http_count = sum(1 for line in f if '\"event_type\":\"http\"' in line)
    print(f'HTTP events found: {http_count}')
except:
    print('❌ No eve.json found')

# Check for alert events (Mode 1)
try:
    with open('/captures/eve.json', 'r') as f:
        alert_count = sum(1 for line in f if '\"event_type\":\"alert\"' in line)
    print(f'Alert events found: {alert_count}')
except:
    print('❌ No alerts found')

# Check ML model
try:
    import pickle
    with open('/scripts/models/detection_model.pkl', 'rb') as f:
        model = pickle.load(f)
    print('✅ ML model available')
except:
    print('❌ ML model not available')
"

# Compare both modes (if comparison script exists)
docker exec sec_monitor python3 /scripts/compare_modes.py

# Or run manual comparison
echo "=== Mode 1 (Suricata Rules) ==="
docker exec sec_monitor grep -c '"event_type":"alert"' /captures/eve.json

echo "=== Mode 2 (ML Detection) ==="
docker exec sec_monitor python3 /scripts/mode2_ml_detector.py /captures/eve.json | grep -E "(Detection Rate|Detected|Total)"
```

## System Status Verification

### Quick Health Check
Run this comprehensive check before starting any analysis:

```bash
#!/bin/bash
echo "=== Security Testbed Health Check ==="

# Container status
echo "1. Container Status:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep sec_

# Suricata status
echo -e "\n2. Suricata Status:"
docker exec sec_monitor ps aux | grep suricata | grep -v grep

# Eve.json status
echo -e "\n3. Eve.json Status:"
docker exec sec_monitor ls -la /captures/eve.json 2>/dev/null || echo "❌ eve.json not found"

# Network connectivity
echo -e "\n4. Network Test:"
docker exec sec_attacker ping -c 1 100.64.0.20 >/dev/null 2>&1 && echo "✅ Network OK" || echo "❌ Network issue"

# Victim service
echo -e "\n5. Victim Service:"
docker exec sec_attacker curl -s http://100.64.0.20:3000/ | head -1 | grep -q "html" && echo "✅ Victim service OK" || echo "❌ Victim service issue"

# ML model
echo -e "\n6. ML Model:"
docker exec sec_monitor ls /scripts/models/detection_model.pkl >/dev/null 2>&1 && echo "✅ ML model found" || echo "❌ ML model missing"

echo -e "\n=== Health Check Complete ==="
```

Save this as `health_check.sh` and run: `bash health_check.sh`

## ML Model Setup

### Model Requirements
The ML detector expects a trained model at `/scripts/models/detection_model.pkl` with:
- **Format**: Dictionary with keys `'model'` and `'feature_names'`
- **Model Type**: RandomForestClassifier (or compatible sklearn model)
- **Features**: 8 HTTP-based features

### Model Structure
```python
# Expected model format
{
    'model': RandomForestClassifier(...),
    'feature_names': [
        'src_port', 'dest_port', 'http_status', 'http_resp_len', 
        'http_url_len', 'url_contains_script_tag', 
        'url_contains_onerror', 'http_method_POST'
    ]
}
```

### Training Your Own Model
1. **Generate training data**: Use ML dataset generator
2. **Train model**: Use balanced dataset with proper feature engineering
3. **Save model**: Save as structured dictionary format
4. **Test model**: Verify with mode2_ml_detector.py

## Key Detection Features

### Mode 1 Features (Suricata Rules)
- Pattern-based detection
- Signature matching
- Protocol analysis
- Real-time alerting
- Low false positive rate

### Mode 2 Features (ML Detection)
- **HTTP Status Analysis**: Response codes and patterns
- **URL Analysis**: Length, character patterns, encoding
- **Script Detection**: `<script>` tags, JavaScript patterns
- **Event Handler Detection**: `onerror`, `onload`, `onfocus` patterns
- **Method Analysis**: POST vs GET request patterns
- **Port Analysis**: Source and destination ports
- **Content Length**: Response size analysis
- **Adaptive Learning**: Model improves with training data

## Understanding Results

### Detection Rate Interpretation
- **Detection Rate**: Percentage of HTTP traffic flagged as attacks
- **Not Effectiveness**: Requires knowing actual attack rate in traffic
- **Realistic Range**: 20-40% detection rate is normal for mixed traffic

### ML Confidence Scores
- **0.6-0.8**: Typical confidence range for XSS detection
- **Higher confidence**: More certain attack detection
- **Lower confidence**: Potential false positive

### Comparison Metrics
- **Coverage**: What types of attacks each method detects
- **Precision**: How accurate the detections are
- **Recall**: How many actual attacks are caught

## Troubleshooting

### Common Issues
1. **Model Loading Errors**: Verify model file structure and sklearn compatibility
2. **Feature Extraction Errors**: Check HTTP event format in eve.json
3. **No Detections**: Ensure traffic contains actual XSS attacks
4. **High False Positives**: Adjust ML model threshold or retrain
5. **Empty eve.json**: Suricata may not be running or configured properly
6. **Container connection issues**: Check network connectivity between containers

### Startup Troubleshooting

**Problem**: Containers not running
```bash
# Check container status
docker ps -a | grep sec_

# Start testbed
cd /home/ubuntu/sec-testbed
./start_testbed.sh

# Check logs if containers fail to start
docker logs sec_monitor
docker logs sec_attacker
docker logs sec_victim
```

**Problem**: Suricata not capturing traffic
```bash
# Check Suricata process
docker exec sec_monitor ps aux | grep suricata

# Check Suricata logs
docker exec sec_monitor tail -20 /var/log/suricata/suricata.log

# Stop and restart Suricata
docker exec sec_monitor pkill -f suricata
docker exec sec_monitor /start_suricata_monitoring.sh

# Check network interface
docker exec sec_monitor ip addr show

# Manual Suricata start with specific interface
docker exec sec_monitor suricata -c /etc/suricata/suricata.yaml -i eth0 --runmode=autofp -D
```

**Problem**: No HTTP events in eve.json
```bash
# Check if eve.json exists
docker exec sec_monitor ls -la /captures/eve.json

# Check Suricata configuration
docker exec sec_monitor grep -A 5 "eve-log:" /etc/suricata/suricata.yaml

# Generate test traffic
docker exec sec_attacker curl http://100.64.0.20:3000/

# Check if events appear
docker exec sec_monitor tail -f /captures/eve.json
```

**Problem**: ML model not found
```bash
# Check models directory
docker exec sec_monitor ls -la /scripts/models/

# Create models directory if missing
docker exec sec_monitor mkdir -p /scripts/models/

# You need to train and place your model there
# See ML Model Setup section for details
```

### Debug Commands
```bash
# Check model structure
docker exec sec_monitor python3 -c "
import pickle
with open('/scripts/models/detection_model.pkl', 'rb') as f:
    model = pickle.load(f)
print('Model type:', type(model))
print('Keys:', list(model.keys()) if isinstance(model, dict) else 'Not a dict')
"

# Check traffic patterns
docker exec sec_monitor grep -c 'script' /captures/eve.json

# Monitor live traffic
docker exec sec_monitor tail -f /captures/eve.json | grep 'http'
```

## Advanced Usage

### Custom Attack Scenarios
Create custom attack patterns and test detection:

```bash
# Custom XSS attack
docker exec sec_attacker curl "http://100.64.0.20:3000/?q=<script>alert('custom')</script>"

# Test specific payload
docker exec sec_attacker curl "http://100.64.0.20:3000/?q=<svg%20onload=alert(1)>"
```

### Model Tuning
Adjust ML detection thresholds:

```python
# In mode2_ml_detector.py, modify prediction threshold
if prediction_prob > 0.5:  # Adjust threshold here
    return True, prediction_prob
```

### Performance Monitoring
Monitor detection performance:

```bash
# Check processing speed
docker exec sec_monitor python3 /scripts/mode2_ml_detector.py /captures/eve.json | grep -E "(requests|detected|errors)"
```

## Best Practices

1. **Consistent Testing**: Use same attack scenarios for both modes
2. **Sufficient Data**: Generate enough traffic for meaningful comparison
3. **Clean Environment**: Reset captures between tests
4. **Document Results**: Save analysis outputs for comparison
5. **Iterative Improvement**: Use results to improve detection methods

## File Locations

### Key Scripts
- `/scripts/mode2_ml_detector.py`: ML detection engine
- `/scripts/analyze_mode1.py`: Suricata analysis
- `/scripts/compare_modes.py`: Mode comparison
- `/scripts/models/detection_model.pkl`: Trained ML model

### Data Locations
- `/captures/eve.json`: Suricata event log
- `/logs/attack_markers.log`: Attack timing markers
- `/analysis/`: Analysis results and datasets

## Next Steps

After completing the comparison:
1. **Analyze Results**: Determine which method performs better
2. **Hybrid Approach**: Consider combining both methods
3. **Model Improvement**: Retrain ML model with more data
4. **Rule Updates**: Update Suricata rules based on findings
5. **Deployment**: Implement best-performing method in production

## Support

For issues or questions:
1. Check troubleshooting section
2. Review debug commands
3. Verify model and data formats
4. Ensure proper testbed setup
