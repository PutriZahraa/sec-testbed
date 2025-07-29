# XSS Dataset Generation Pipeline

This pipeline generates labeled datasets for XSS attack detection by capturing separate attack and benign traffic sessions, then merging them into a final randomized dataset ready for ML training.

## Overview

The pipeline consists of 4 main steps:
1. **Benign Dataset Generation** - Captures normal browsing behavior
2. **Attack Dataset Generation** - Captures XSS attack traffic using existing attack scripts
3. **Processing & Labeling** - Converts eve.json to labeled CSV files with ML features
4. **Final Dataset Creation** - Merges and shuffles data into final training dataset

## Quick Start

```bash
# Ensure the security testbed is running
./start_testbed.sh

# Generate the complete dataset (default: 20 minutes total, configurable)
./utils/generate_datasets.sh

# Generate with custom duration (e.g., 15 minutes = 900 seconds)
./utils/generate_datasets.sh 900
```

## Pipeline Steps

### Step 1: Benign Dataset Generation
- **Duration**: Configurable (default: 600 seconds = 10 minutes)
- **Script**: `generate_benign_dataset_simple.sh`
- **Traffic**: Normal Juice Shop browsing, searches, API calls
- **Suricata**: Uses existing configuration for traffic capture
- **Output**: Benign HTTP events captured in eve.json

### Step 2: Attack Dataset Generation
- **Duration**: Configurable (same as benign session)
- **Script**: `generate_attack_dataset_simple.sh`
- **Traffic**: XSS attacks using `/attacker/attack_scenarios/xss_attack.sh`
- **Suricata**: Uses existing configuration for traffic capture
- **Output**: Attack HTTP events captured in eve.json

### Step 3: Processing & Labeling
- **Script**: `process_and_label_datasets.sh`
- **Input**: Raw eve.json files from both sessions
- **Processing**: Extracts HTTP events and converts to ML features
- **Features**: 15 XSS detection features per HTTP request
- **Output**: 
  - `benign_dataset_TIMESTAMP.csv` (labeled 0)
  - `attack_dataset_TIMESTAMP.csv` (labeled 1)
  - Enhanced versions with additional features (34 columns)
  - Enhanced full versions with metadata (38 columns)

### Step 4: Final Dataset Creation
- **Script**: `merge_datasets.py`
- **Processing**: Merges and shuffles datasets
- **Output**: `final_xss_dataset_TIMESTAMP.csv` - Complete shuffled dataset

## Dataset Features

The generated dataset includes 15 core features per HTTP request (normal version):

### Basic HTTP Features  
- `timestamp` - Request timestamp
- `src_ip`, `dest_ip` - Source and destination IP addresses
- `src_port`, `dest_port` - Network endpoints
- `proto` - Protocol (typically TCP)
- `http_method` - HTTP method (GET, POST, etc.)
- `http_status` - Response status code
- `http_resp_len` - Response length
- `http_url` - Full request URL
- `http_user_agent` - User agent string
- `http_url_len` - URL length

### XSS Detection Features
- `url_contains_script_tag` - Detects `<script>` tags
- `url_contains_onerror` - Detects `onerror` handlers

### Target Label
- `label` - 0 for benign, 1 for XSS attack

## Dataset Versions

Three versions are generated for different use cases:

### 1. Normal Dataset (15 columns)
- **Files**: `*_dataset_TIMESTAMP.csv`
- **Use**: Basic analysis, debugging, manual inspection
- **Contains**: Raw HTTP fields + basic XSS detection features

### 2. Enhanced Dataset (34 columns) 
- **Files**: `*_dataset_TIMESTAMP_enhanced.csv`
- **Use**: Machine Learning training
- **Contains**: Engineered numeric features, one-hot encoded methods, extensive XSS patterns
- **Privacy**: No raw URLs/IPs - only processed features

### 3. Enhanced Full Dataset (38 columns)
- **Files**: `*_dataset_TIMESTAMP_enhanced_full.csv` 
- **Use**: ML training with traceability
- **Contains**: All enhanced features + metadata (attack_type, timestamp, original_url)

## Configuration

### Capture Duration
Default is 600 seconds (10 minutes) per session. Modify by passing argument:
```bash
# 15-minute sessions (900 seconds)
./utils/generate_datasets.sh 900

# 5-minute sessions (300 seconds) 
./utils/generate_datasets.sh 300
```

### Attack Script
Uses `/attacker/attack_scenarios/xss_attack.sh` with configurable duration that matches the session length.

## Output Structure

```
data/labeled_datasets/
├── benign_dataset_TIMESTAMP.csv                    # Normal: 15 columns (label=0)
├── benign_dataset_TIMESTAMP_enhanced.csv           # Enhanced: 34 columns for ML
├── benign_dataset_TIMESTAMP_enhanced_full.csv      # Enhanced + metadata: 38 columns
├── attack_dataset_TIMESTAMP.csv                    # Normal: 15 columns (label=1)  
├── attack_dataset_TIMESTAMP_enhanced.csv           # Enhanced: 34 columns for ML
├── attack_dataset_TIMESTAMP_enhanced_full.csv      # Enhanced + metadata: 38 columns
└── final_xss_dataset_TIMESTAMP.csv                 # Final merged dataset (15 columns)
```

## Data Quality

- **Traffic Capture**: Uses existing Suricata configuration for consistent monitoring
- **Proper Labeling**: Attack/benign sessions clearly separated with automatic labeling
- **Feature Rich**: Multiple dataset versions (15/34/38 columns) for different use cases
- **Shuffled**: Final dataset randomized for ML training
- **No Dependencies**: Pipeline works without external Python packages (pandas-free)

## Usage Examples

### Generate with Different Durations
```bash
# 15-minute sessions (recommended for production)
./utils/generate_datasets.sh 900

# 5-minute sessions (faster testing)  
./utils/generate_datasets.sh 300

# 30-minute sessions (more comprehensive data)
./utils/generate_datasets.sh 1800
```

### Check Generated Dataset
```bash
cd data/labeled_datasets/

# Count samples in final dataset
wc -l final_xss_dataset_*.csv

# Check class distribution in normal dataset (15 columns)
cut -d',' -f15 final_xss_dataset_*.csv | sort | uniq -c

# Examine dataset structure
head -1 final_xss_dataset_*.csv  # See column headers
```

### Typical Results
- **15-minute sessions**: ~750 samples (300 benign, 450 attack)
- **10-minute sessions**: ~500 samples (200 benign, 300 attack)  
- **Attack ratio**: ~60% attack, 40% benign

## Requirements

- Security testbed running (`./start_testbed.sh`)
- Docker containers: `sec_monitor`, `sec_victim`, `sec_attacker`, `sec_switch`
- Python 3 (no external packages required)
- Sufficient disk space for capture files and datasets

## Troubleshooting

### No HTTP Events Captured
- Check if Juice Shop is accessible: `curl http://100.64.0.20:3000`
- Verify Suricata is running: `docker exec sec_monitor pgrep suricata`
- Check eve.json: `docker exec sec_monitor tail /captures/eve.json`

### Attack Script Not Working
- Check attacker container: `docker exec sec_attacker bash`
- Verify attack script: `docker exec sec_attacker ls -la /attack_scenarios/xss_attack.sh`
- Test connectivity: `docker exec sec_attacker ping 100.64.0.20`

### Processing Errors
- Check eve.json files exist: `docker exec sec_monitor ls -la /captures/`
- Verify containers are running: `docker ps`
- Check for permission issues in data directories

## Next Steps

After generating the dataset:
1. Use the **normal dataset** (15 columns) for basic analysis and ML training
2. Use the **enhanced dataset** (34 columns) for advanced ML features without PII
3. Use the **enhanced full dataset** (38 columns) when you need traceability
4. Experiment with different capture durations to find optimal dataset size
5. Train ML models using your preferred framework (scikit-learn, etc.)
