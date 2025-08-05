# Security Testbed - Streamlined Research Environment

> **⚠️ CRITICAL WARNING**: This testbed contains intentionally vulnerable services. Use ONLY in isolated environments for educational and research purposes.

## Overview

A Docker-based security testbed designed for comparing traditional rule-based detection (Mode 1) with modern ML-based detection (Mode 2). This branch (`w_suricata_juiceshop`) features advanced monitoring capabilities with **official Suricata XSS rules** and comprehensive detection analysis.

### Purpose
- **Detection Comparison**: Compare official Suricata XSS rules vs ML-based detection
- **Official Baseline**: Industry-standard ET Open XSS rules for credible research comparison
- **ML Dataset Generation**: Create labeled datasets for ML/AI security research
- **Attack Simulation**: Test XSS attack scenarios with realistic traffic patterns
- **Performance Analysis**: Evaluate detection effectiveness and false positive rates
- **Security Research**: Advanced monitoring with official Suricata rule integration

## Key Features (w_suricata_juiceshop Branch)

🔍 **Mode 1**: Official Suricata XSS rules (27 ET Open signatures) with consolidated analysis
🤖 **Mode 2**: ML-based XSS detection using 8 HTTP features  
📊 **Side-by-side comparison** framework with automated consolidation
🎯 **Randomized mixed traffic** generation (27% attacks, 73% benign)
⚡ **Official rules setup** with ET Open XSS rule downloads
📚 **Comprehensive monitoring guide** with step-by-step instructions
🛠️ **Advanced troubleshooting** and system verification tools

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Attacker  │    │     OvS     │    │   Victim    │
│ 100.64.0.10 │────│ 100.64.0.1  │────│ 100.64.0.20 │
│   XSS Gen   │    │   Mirror    │    │ OWASP Juice │
└─────────────┘    └──────┬──────┘    └─────────────┘
                          │
                          │ (mirrored traffic)
                ┌─────────┴─────────┐
                │      Monitor      │
                │    100.64.0.30    │
                │   Suricata + ML   │
                └───────────────────┘
```

## Detection Modes

### Mode 1: Official Rule-Based Detection (Suricata)
- **Method**: Official ET Open XSS signatures (27 rules)
- **Source**: Emerging Threats Open ruleset with XSS-focused rules
- **Analysis**: Consolidated alert counting with duplicate removal
- **Output**: Alert events with official rule classifications
- **Strengths**: Industry standard, proven signatures, research credibility

### Mode 2: ML-Based Detection
- **Method**: RandomForest with 8 HTTP features
- **Features**: URL patterns, script detection, HTTP analysis
- **Output**: Confidence scores and malicious predictions
- **Strengths**: Adaptive, pattern recognition, zero-day detection

## Components

### 1. **Attacker Container** (100.64.0.10)
- **Purpose**: Generate randomized XSS attack traffic with timing markers
- **Attack Types**: Script injection, event handlers, JavaScript execution
- **Key Features**: 
  - Randomized mixed attack script (`randomized_mixed_attack.sh`)
  - Attack timing correlation for ML training
  - Realistic traffic patterns (27% attacks, 73% benign)

### 2. **Victim Container** (100.64.0.20:3000)
- **Purpose**: OWASP Juice Shop - intentionally vulnerable web application
- **Services**:
  - OWASP Juice Shop (port 3000) - Modern vulnerable web app
  - Multiple XSS vulnerabilities for testing
- **Features**: Real-world web application attack surface

### 3. **Monitor Container** (100.64.0.30)
- **Purpose**: Advanced monitoring with Suricata 8.0.0 + official XSS rules + ML detection
- **Key Features**:
  - **Mode 1**: Official Suricata XSS rules with consolidated analysis (`analyze_consolidated_detection.py`)
  - **Mode 2**: ML-based XSS detection (`mode2_ml_detector.py`)
  - Official ET Open XSS rule setup (`setup_official_rules.sh`)
  - Real-time traffic analysis and correlation
  - Comprehensive comparison framework

### 4. **Switch Container** (Host Network)
- **Purpose**: OpenVSwitch with port mirroring
- **Features**: Transparent traffic mirroring to monitor

## Quick Start

1. **Setup Environment**
   ```bash
   git clone <repository>
   cd sec-testbed
   git checkout w_suricata_juiceshop
   ```

2. **Start Testbed**
   ```bash
   ./start_testbed.sh
   ```

3. **Verify System Status**
   ```bash
   # Check containers
   docker ps | grep sec_
   
   # Verify Suricata
   docker exec sec_monitor ps aux | grep suricata
   ```

4. **Generate Mixed Traffic**
   ```bash
   # Generate attacks + benign traffic
   docker exec -it sec_attacker ./randomized_mixed_attack.sh
   ```

5. **Setup Official XSS Rules**
   ```bash
   # Download and setup official ET Open XSS rules
   docker exec sec_monitor /scripts/setup_official_rules.sh
   
   # Restart Suricata with official configuration
   docker exec sec_monitor pkill suricata
   docker exec sec_monitor suricata -c /etc/suricata/suricata_official_xss.yaml -i eth0 -D
   ```

6. **Clear Previous Data (Optional - For Clean Comparison)**
   ```bash
   # Clear eve.json for fresh analysis (recommended between test runs)
   docker exec sec_monitor truncate -s 0 /captures/eve.json
   ```

7. **Generate Mixed Traffic**
   ```bash
   # Generate attacks + benign traffic
   docker exec sec_attacker bash -c 'cd /attack_scenarios && timeout 30s ./randomized_mixed_attack.sh'
   ```

8. **Run Consolidated Analysis (Both Modes)**
   ```bash
   # Comprehensive Mode 1 vs Mode 2 comparison
   docker exec sec_monitor python3 /scripts/analyze_consolidated_detection.py /captures/eve.json
   ```

9. **Alternative: Individual Mode Analysis**
   ```bash
   # Mode 1 only (Official Suricata Rules)
   docker exec sec_monitor python3 /scripts/analyze_mode1_simple.py /captures/eve.json
   
   # Mode 2 only (ML Detection)
   docker exec sec_monitor python3 /scripts/mode2_ml_detector.py /captures/eve.json
   ```

10. **Access Services**
   - OWASP Juice Shop: http://100.64.0.20:3000

## Detection Comparison Results

### Example Analysis Output (Consolidated)

**Mode 1 vs Mode 2 Comparison:**
```
🔄 CONSOLIDATED MODE COMPARISON ANALYSIS
========================================

📊 TRAFFIC ANALYSIS:
   Total HTTP Requests: 62
   Attack Requests: ~27% (mixed XSS patterns)
   Benign Requests: ~73% (normal navigation)

🔍 MODE 1 - OFFICIAL SURICATA XSS RULES:
   Rule Triggers: 32 alerts
   Consolidated Detections: 12 unique attacks
   Detection Rate: 19.4%
   Official Rules: 27 ET Open XSS signatures

🤖 MODE 2 - ML DETECTION:
   ML Detections: 13 attacks
   Detection Rate: 21.0%
   Model: RandomForestClassifier (8 features)

📈 COMPARISON SUMMARY:
   ML Advantage: +1.6% detection rate
   Both methods detect different attack patterns
   Suggests potential for hybrid approach
```

### Legacy Individual Analysis

**Mode 1 (Official Suricata Rules):**
```
📊 MODE 1 OFFICIAL SURICATA ANALYSIS
Total HTTP Requests: 59
Alert Events Generated: 23
Detection Rate: 39.0%

🔍 OFFICIAL RULE ANALYSIS:
   Rules Active: 27 ET Open XSS signatures
   XSS-related Alerts: 23
   Alert Types: ET WEB_CLIENT XSS Alert Function, Script Tag, etc.
```

**Mode 2 (ML Detection):**
```
📊 MODE 2 ML DETECTION SUMMARY
Total HTTP Requests: 59
XSS Attacks Detected: 16
Detection Rate: 27.1%

🤖 ML DETECTION ANALYSIS:
   Model Type: RandomForestClassifier
   Features Used: 8
   Confidence Range: 0.62-0.74
```

## ML Model Features

The ML detector uses 8 HTTP-based features:
1. **src_port** - Source port analysis
2. **dest_port** - Destination port patterns
3. **http_status** - HTTP response codes
4. **http_resp_len** - Response length analysis
5. **http_url_len** - URL length patterns
6. **url_contains_script_tag** - Script tag detection
7. **url_contains_onerror** - Event handler detection
8. **http_method_POST** - HTTP method analysis

## Complete Documentation

📚 **Detailed Guide**: See `monitor/README.md` for comprehensive step-by-step instructions including:
- Pre-flight system checks
- Mode comparison workflow
- ML model setup requirements
- Troubleshooting guides
- Manual Suricata controls

## Data Collection Directories

```
data/
├── captures/          # Suricata eve.json events and traffic logs
├── analysis/          # Generated ML datasets and analysis reports  
├── attacker_logs/     # Attack execution logs and timing markers
└── logs/              # System logs and monitoring data
```

## Key Scripts and Tools

### Detection Analysis
- `monitor/scripts/analyze_consolidated_detection.py` - **NEW**: Comprehensive Mode 1 vs Mode 2 comparison
- `monitor/scripts/analyze_mode1_simple.py` - Simple Suricata rule analysis  
- `monitor/scripts/mode2_ml_detector.py` - ML-based XSS detection
- `monitor/scripts/setup_official_rules.sh` - **NEW**: Official ET Open XSS rules setup
- `attacker/attack_scenarios/randomized_mixed_attack.sh` - Traffic generator

### System Management
- `start_testbed.sh` - Complete testbed startup
- `utils/status.sh` - System health checks  
- `utils/cleanup.sh` - Data cleanup utilities

### Monitoring
- Official Suricata configuration with XSS-focused rules
- Real-time attack monitoring with consolidated analysis
- Suricata process management with official rule integration
- ML model validation tools

## Dependencies

- Docker & Docker Compose
- OpenVSwitch (installed in switch container)
- Suricata 8.0.0 with eve.json logging
- Python 3 with scikit-learn for ML detection
- Linux host with network privileges

## Branch-Specific Features

This `w_suricata_juiceshop` branch includes:
- ✅ Advanced Suricata integration with **official ET Open XSS rules**
- ✅ OWASP Juice Shop target application  
- ✅ ML-based detection framework
- ✅ **Mode 1 vs Mode 2 consolidated comparison** capabilities
- ✅ **Official rules setup automation** with ET Open integration
- ✅ Comprehensive monitoring guides
- ✅ **Research-ready baseline comparison** for publications

## Security Considerations

- **Isolation**: Always run in isolated networks
- **No Internet**: Never expose to public internet
- **Weak Credentials**: Intentionally vulnerable - for research only
- **Clean Up**: Stop containers when not in use

## Stopping the Testbed

```bash
docker compose down
```

## Research Applications

1. **Intrusion Detection**: Train ML models on labeled attack data
2. **Anomaly Detection**: Develop behavioral analysis algorithms  
3. **Threat Intelligence**: Study attack patterns and signatures
4. **Security Tool Testing**: Validate detection capabilities

## Troubleshooting

- **OVS Issues**: Check `docker logs sec_switch`
- **No Traffic**: Verify port mirroring with `ovs-vsctl list Mirror`
- **Service Access**: Confirm container IPs with `docker network inspect sec-testbed`

---

**Educational Use Only** - This testbed is designed for cybersecurity research and education in controlled environments.
