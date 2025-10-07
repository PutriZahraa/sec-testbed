# Codebase Analysis - Current State

## Overview
This document provides a comprehensive analysis of the current codebase state for the Security Testbed - a Docker-based research environment comparing rule-based detection (Suricata) with ML-based XSS detection.

## Current Implementation Status

### Core Detection Framework
- **Mode 1**: Custom Suricata XSS rules based on attack patterns 1-20
- **Mode 2**: ML-based XSS detection using RandomForestClassifier with 8 HTTP features
- **Comparison**: Consolidated analysis framework that compares detection effectiveness
- **Target**: OWASP Juice Shop on port 3000 for realistic XSS vulnerability testing

### Main Workflow Commands
Based on the user's documented workflow, the key commands are:
1. `./start_testbed.sh` - Initialize all containers
2. `docker exec sec_monitor truncate -s 0 /captures/eve.json` - Clear previous logs
3. `docker exec sec_attacker bash -c './randomized_mixed_attack-v2.sh'` - Send mixed traffic
4. `docker exec sec_monitor python3 /scripts/analyze_consolidated_detection.py /captures/eve.json` - Analyze results
5. `./run_custom_experiment.sh` - Automated workflow (200 requests)
6. `./utils/generate_datasets.sh <duration>` - Generate labeled datasets

### Traffic Generation Configuration
- **Attack Ratio**: 40% attacks, 60% benign traffic (based on `randomized_mixed_attack.sh`)
- **Attack Patterns**: Uses patterns 21-40 for testing (patterns 1-20 used for training)
- **Duration Control**: Configurable via `DURATION_SECONDS` environment variable

## Current File Structure

### Core Implementation Files ✅ ACTIVE
- `monitor/scripts/analyze_consolidated_detection.py` - **MAIN**: Mode 1 vs Mode 2 comparison analysis
- `monitor/scripts/mode2_ml_detector.py` - **ML**: ML-based XSS detection implementation
- `monitor/scripts/realtime_xss_detector.py` - **REALTIME**: Real-time XSS detection
- `monitor/scripts/eve_processor.py` - **PROCESSING**: Suricata eve.json log processing
- `monitor/setup_official_rules.sh` - **SETUP**: Suricata rule configuration
- `monitor/start_suricata_monitoring.sh` - **SERVICE**: Suricata monitoring service
- `monitor/rules/standard_xss_rules.rules` - **RULES**: Custom XSS detection rules

### Attack Generation Files ✅ ACTIVE
- `attacker/attack_scenarios/randomized_mixed_attack.sh` - **MAIN**: Mixed traffic generator (40% attacks, 60% benign)
- `attacker/attack_scenarios/custom_mixed_traffic-v2.sh` - **FIXED**: Fixed 200 requests for experiments
- `attacker/attack_scenarios/xss_attack.sh` - **TRAINING**: Attack patterns 1-20 for training
- `attacker/attack_scenarios/xss_attack2.sh` - **TRAINING**: Alternative training attacks
- `attacker/attack_scenarios/attack_tools.sh` - **TOOLS**: General attack toolset

### Utility Files ✅ ACTIVE
- `utils/generate_datasets.sh` - **DATASET**: Dataset generation for ML training
- `utils/cleanup.sh` - **MAINTENANCE**: Data cleanup utility
- `utils/status.sh` - **MONITORING**: System status checker
- `utils/reset.sh` - **RESET**: Complete environment reset
- `utils/archive.sh` - **BACKUP**: Data archiving utility

### Main Scripts ✅ ACTIVE
- `start_testbed.sh` - **STARTUP**: Main testbed initialization
- `run_custom_experiment.sh` - **AUTOMATION**: Automated 200-request experiment
- `safe_shutdown.sh` - **SHUTDOWN**: Safe environment shutdown

## Key Implementation Details

### Attack Traffic Configuration
- **`randomized_mixed_attack.sh`**: 40% XSS attacks, 60% benign traffic
- **Attack Patterns**: Tests use patterns 21-40; training uses patterns 1-20  
- **Duration Control**: `DURATION_SECONDS` environment variable (default: 60 seconds)
- **Fixed Requests**: `custom_mixed_traffic-v2.sh` sends exactly 200 requests

### Detection Rules and Files
- **Suricata Rules**: `monitor/rules/standard_xss_rules.rules` - Custom rules based on attack patterns 1-20
- **ML Model**: RandomForestClassifier with 8 HTTP features (port, URL length, script detection, etc.)
- **Target**: OWASP Juice Shop (vulnerable web application) on 100.64.0.20:3000

### Data Storage Locations
- **Capture Data**: `data/captures/` - Suricata eve.json logs
- **Labeled Datasets**: `data/labeled_datasets/` - Separated attack, benign, and combined datasets
- **Analysis Results**: `data/analysis/` - Detection analysis reports and comparisons

### Container Architecture
- **Attacker** (100.64.0.10): Traffic generation and attack simulation
- **Victim** (100.64.0.20): OWASP Juice Shop vulnerable application
- **Monitor** (100.64.0.30): Suricata + ML detection analysis
- **Switch** (host network): OpenVSwitch with traffic mirroring

## Current Workflow Analysis

### Standard Operating Procedure
The user has established a clear 6-step workflow for research operations:

1. **Environment Setup**: `./start_testbed.sh` initializes all Docker containers and networking
2. **Log Cleanup**: `docker exec sec_monitor truncate -s 0 /captures/eve.json` ensures clean analysis
3. **Traffic Generation**: `docker exec sec_attacker bash -c './randomized_mixed_attack.sh'` creates test traffic
4. **Detection Analysis**: `docker exec sec_monitor python3 /scripts/analyze_consolidated_detection.py /captures/eve.json` compares results
5. **Automated Testing**: `./run_custom_experiment.sh` runs the complete workflow with 200 fixed requests
6. **Dataset Creation**: `./utils/generate_datasets.sh <duration>` generates labeled data for ML research

### Script Variants
- **Main Script**: `randomized_mixed_attack.sh` - Duration-based mixed traffic generation
- **Fixed Request Variant**: `custom_mixed_traffic-v2.sh` - Sends exactly 200 requests for experiments
- **Training Scripts**: `xss_attack.sh` and `xss_attack2.sh` - Attack patterns 1-20 for model training

## Research Capabilities

### Detection Comparison Framework
The testbed provides comprehensive comparison between:
- **Mode 1**: Rule-based detection using Suricata with custom XSS rules
- **Mode 2**: ML-based detection using RandomForestClassifier with 8 HTTP features

### ML Model Features
The ML detection system analyzes:
1. `src_port` - Source port analysis
2. `dest_port` - Destination port patterns  
3. `http_status` - HTTP response codes
4. `http_resp_len` - Response length analysis
5. `http_url_len` - URL length patterns
6. `url_contains_script_tag` - Script tag detection
7. `url_contains_onerror` - Event handler detection
8. `http_method_POST` - HTTP method analysis

### Dataset Generation
- **Training Data**: Generated from attack patterns 1-20 (same as Suricata rules)
- **Test Data**: Uses attack patterns 21-40 from randomized mixed traffic
- **Labeled Output**: Separated files for attack, benign, and combined datasets
- **Research Ready**: CSV format suitable for ML frameworks and academic analysis

## Current Status and Recommendations

### ✅ Current Implementation Status
- **Functional Testbed**: All containers and networking operational
- **Detection Framework**: Both rule-based (Mode 1) and ML-based (Mode 2) detection working
- **Traffic Generation**: Randomized mixed traffic with proper attack/benign ratio (40%/60%)
- **Analysis Tools**: Consolidated detection comparison and dataset generation utilities
- **Documentation**: User-friendly command workflow established

### 📋 Documentation Status
1. **Attack Ratio Accuracy**: Confirmed 40% attacks, 60% benign traffic (corrected in README.md)
2. **Workflow Clarity**: The 6-step command sequence is well-documented and functional
3. **Script References**: All script names now correctly match actual file names

### 🔧 Technical Implementation
- **Attack Patterns**: Training (1-20) vs Testing (21-40) separation maintained
- **Data Storage**: Organized structure in `data/` directory with proper subdirectories
- **Container Architecture**: Properly isolated with defined IP addresses and roles
- **ML Features**: 8-dimensional feature vector for HTTP-based XSS detection

### 📊 Research Readiness
The testbed provides:
- **Reproducible Results**: Fixed experiment parameters via `run_custom_experiment.sh`
- **Labeled Datasets**: Properly separated attack/benign data for ML training
- **Comparison Framework**: Clear Mode 1 vs Mode 2 analysis output
- **Academic Suitability**: Clean results format for thesis/research documentation

### ✅ Ready for Production Use
The current implementation provides a stable, well-documented research environment suitable for:
- XSS detection research and comparison studies
- ML model training and evaluation
- Academic research and publication
- Educational cybersecurity demonstrations
