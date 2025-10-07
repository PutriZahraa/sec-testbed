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

## Key Features

🔍 **Mode 1**: Custom Suricata XSS rules based on attack patterns 1-20
🤖 **Mode 2**: ML-based XSS detection using RandomForestClassifier with 8 HTTP features  
📊 **Automated comparison** framework between rule-based and ML detection
🎯 **Randomized mixed traffic** generation with attacks 21-40 for testing
⚡ **One-command automation** with `run_custom_experiment.sh`
� **Dataset generation** tools for ML research

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

### Mode 1: Rule-Based Detection (Suricata)
- **Method**: Custom XSS rules based on attack patterns 1-20
- **File**: `monitor/rules/standard_xss_rules.rules`
- **Analysis**: Pattern matching against known XSS payloads
- **Output**: Alert events for detected attacks
- **Strengths**: Fast, deterministic, low false positives

### Mode 2: ML-Based Detection
- **Method**: RandomForestClassifier with 8 HTTP features
- **Training**: Uses same attack patterns 1-20 as rule-based mode
- **Features**: URL patterns, script detection, HTTP analysis
- **Output**: Confidence scores and attack predictions
- **Strengths**: Adaptive, can detect variations and new patterns

## Components

### 1. **Attacker Container** (100.64.0.10)
- **Purpose**: Generate randomized XSS attack traffic with timing markers
- **Attack Types**: Script injection, event handlers, JavaScript execution
- **Key Features**: 
  - Randomized mixed attack script (`randomized_mixed_attack.sh`)
  - Attack timing correlation for ML training
  - Realistic traffic patterns (40% attacks, 60% benign)

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

### Main Commands

1. **Start Testbed**
   ```bash
   ./start_testbed.sh
   ```
   Initializes all containers (attacker, victim, monitor, switch) and starts the testbed environment.

2. **Clear Previous Logs** (before sending new traffic)
   ```bash
   docker exec sec_monitor truncate -s 0 /captures/eve.json
   ```
   Clears the eve.json file to ensure clean detection analysis for new traffic.

3. **Send Mixed Traffic** (benign & attack)
   ```bash
   docker exec sec_attacker bash -c './randomized_mixed_attack.sh'
   ```
   Generates randomized mixed traffic containing both benign requests and XSS attacks.

4. **Analyze Detection Results** (Suricata Rules vs ML model)
   ```bash
   docker exec sec_monitor python3 /scripts/analyze_consolidated_detection.py /captures/eve.json
   ```
   Compares Mode 1 (Suricata rules) vs Mode 2 (ML detection) results and shows detection performance.

5. **Automated Experiment** (commands 1-4 with fixed 200 requests)
   ```bash
   ./run_custom_experiment.sh
   ```
   Runs a complete automated experiment: clears logs, sends 200 requests, and analyzes results.

6. **Generate Dataset** (for ML training)
   ```bash
   ./utils/generate_datasets.sh <duration_in_seconds>
   ```
   Generates labeled datasets containing both attack and benign traffic for ML model training.

### Access Services
- **OWASP Juice Shop**: http://100.64.0.20:3000

## Key Files and Components

### Detection Rules and Scripts

- **Suricata Rules**: `monitor/rules/standard_xss_rules.rules`
  - Custom XSS detection rules based on attack patterns 1-20
  - Used by Mode 1 (Suricata rule-based detection)

- **Attack Traffic Generator**: `attacker/attack_scenarios/randomized_mixed_attack.sh`
  - Generates mixed traffic with attacks 21-40 for testing
  - Creates realistic traffic patterns for evaluation

- **Training Attack Scripts**: `attacker/attack_scenarios/xss_attack.sh` or `xss_attack2.sh`
  - Contains attack patterns 1-20 used for model training
  - These attacks form the basis for Suricata rules

### Dataset Storage

- **Labeled Datasets**: `/home/ubuntu/sec-testbed/data/labeled_datasets/`
  - Separate files for attack, benign, and combined datasets
  - Used for ML model training and evaluation

## Example Detection Results

**Consolidated Analysis Output:**
```
🔄 CONSOLIDATED MODE COMPARISON ANALYSIS
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

📈 COMPARISON SUMMARY:
   ML shows +3.5% better detection rate
   Hybrid approach recommended for optimal coverage
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

## Data Storage

```
data/
├── captures/              # Suricata eve.json logs for analysis
├── labeled_datasets/      # Generated datasets (attack, benign, combined)
├── analysis/              # Detection analysis reports
└── attacker_logs/         # Attack execution logs
```

## Detection Methodology

### Mode 1: Rule-Based Detection (Suricata)
- **Rules**: Custom XSS rules based on attack patterns 1-20 from `xss_attack.sh`
- **Method**: Pattern matching against known XSS payloads
- **File**: `monitor/rules/standard_xss_rules.rules`

### Mode 2: ML-Based Detection
- **Model**: RandomForestClassifier with 8 HTTP features
- **Training Data**: Generated from attacks 1-20 (same as Suricata rules)
- **Test Data**: Attacks 21-40 from `randomized_mixed_attack.sh`

## Requirements

- Docker & Docker Compose
- Linux host with network privileges
- Python 3 with scikit-learn (for ML detection)

## Usage Notes

- **Training vs Testing**: Rules and ML model are trained on attacks 1-20, tested on attacks 21-40
- **Dataset Generation**: Use `generate_datasets.sh` to create labeled data for research
- **Automation**: `run_custom_experiment.sh` provides a complete automated workflow

## Stopping the Testbed

```bash
docker compose down
```

---

**⚠️ Educational Use Only** - This testbed contains intentionally vulnerable services for cybersecurity research and education in controlled environments.
