#!/bin/bash
set -euo pipefail

# Process and Label Datasets - Convert eve.json to labeled CSV files

TIMESTAMP="${1:-$(date +"%Y%m%d_%H%M%S")}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATASET_DIR="$PROJECT_ROOT/data/labeled_datasets"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')] [PROCESS] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] [PROCESS] ✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] [PROCESS] ⚠️  $1${NC}"
}

mkdir -p "$DATASET_DIR"

log "🔧 Processing captured eve.json files into labeled CSV datasets..."

# Create the Python processing script
docker exec sec_monitor python3 -c "
import json
import pandas as pd
import os
from urllib.parse import unquote
from datetime import datetime

def extract_http_features(eve_file, label, output_file, format_type='enhanced'):
    '''Extract HTTP features from eve.json and label them
    format_type: 'enhanced' (34 cols) or 'compatible' (15 cols)
    '''
    features = []
    
    print(f'Processing {eve_file} with label: {label}')
    
    try:
        with open(eve_file, 'r') as f:
            for line_num, line in enumerate(f):
                try:
                    event = json.loads(line.strip())
                    
                    if event.get('event_type') == 'http':
                        http_data = event.get('http', {})
                        url = http_data.get('url', '')
                        decoded_url = unquote(url)
                        method = http_data.get('http_method', 'GET')
                        status = http_data.get('status', 200)
                        length = http_data.get('length', 0)
                        
                        # Extract comprehensive features for ML
                        feature_enhanced = {
                            # Basic HTTP features
                            'src_port': event.get('src_port', 0),
                            'dest_port': event.get('dest_port', 0),
                            'http_method': method,
                            'http_status': status,
                            'http_resp_len': length,
                            'http_url_len': len(decoded_url),
                            
                            # XSS detection features
                            'url_contains_script_tag': 1 if '<script' in decoded_url.lower() else 0,
                            'url_contains_onerror': 1 if 'onerror' in decoded_url.lower() else 0,
                            'url_contains_onload': 1 if 'onload' in decoded_url.lower() else 0,
                            'url_contains_onclick': 1 if 'onclick' in decoded_url.lower() else 0,
                            'url_contains_onmouseover': 1 if 'onmouseover' in decoded_url.lower() else 0,
                            'url_contains_onfocus': 1 if 'onfocus' in decoded_url.lower() else 0,
                            'url_contains_alert': 1 if 'alert(' in decoded_url.lower() else 0,
                            'url_contains_javascript': 1 if 'javascript:' in decoded_url.lower() else 0,
                            'url_contains_eval': 1 if 'eval(' in decoded_url.lower() else 0,
                            'url_contains_document': 1 if 'document.' in decoded_url.lower() else 0,
                            'url_contains_cookie': 1 if 'cookie' in decoded_url.lower() else 0,
                            'url_contains_iframe': 1 if '<iframe' in decoded_url.lower() else 0,
                            'url_contains_svg': 1 if '<svg' in decoded_url.lower() else 0,
                            'url_contains_img': 1 if '<img' in decoded_url.lower() else 0,
                            'url_contains_object': 1 if '<object' in decoded_url.lower() else 0,
                            'url_contains_embed': 1 if '<embed' in decoded_url.lower() else 0,
                            
                            # HTTP method features
                            'http_method_GET': 1 if method == 'GET' else 0,
                            'http_method_POST': 1 if method == 'POST' else 0,
                            'http_method_PUT': 1 if method == 'PUT' else 0,
                            'http_method_DELETE': 1 if method == 'DELETE' else 0,
                            
                            # URL pattern features
                            'url_has_query_params': 1 if '?' in url else 0,
                            'url_query_param_count': url.count('&') + (1 if '?' in url else 0),
                            'url_encoded_chars': 1 if '%' in url else 0,
                            'url_suspicious_chars': 1 if any(c in decoded_url for c in ['<', '>', '\"', \"'\", '(', ')', '{', '}']) else 0,
                            
                            # Response features
                            'response_2xx': 1 if 200 <= status < 300 else 0,
                            'response_3xx': 1 if 300 <= status < 400 else 0,
                            'response_4xx': 1 if 400 <= status < 500 else 0,
                            'response_5xx': 1 if 500 <= status < 600 else 0,
                            
                            # Label
                            'is_malicious': label,
                            'attack_type': 'xss' if label == 1 else 'benign',
                            
                            # Metadata (for debugging/analysis)
                            'timestamp': event.get('timestamp', ''),
                            'original_url': url[:200]  # Truncated for CSV
                        }
                        
                        # Compatible format (15 columns matching existing dataset)
                        feature_compatible = {
                            'timestamp': event.get('timestamp', ''),
                            'src_ip': event.get('src_ip', ''),
                            'src_port': event.get('src_port', 0),
                            'dest_ip': event.get('dest_ip', ''),
                            'dest_port': event.get('dest_port', 0),
                            'proto': event.get('proto', 'TCP'),
                            'http_method': method,
                            'http_status': status,
                            'http_resp_len': length,
                            'http_url': url[:200],  # Truncated to avoid CSV issues
                            'http_user_agent': http_data.get('http_user_agent', ''),
                            'http_url_len': len(decoded_url),
                            'url_contains_script_tag': 1 if '<script' in decoded_url.lower() else 0,
                            'url_contains_onerror': 1 if 'onerror' in decoded_url.lower() else 0,
                            'label': label
                        }
                        
                        feature = feature_enhanced  # Default to enhanced
                        
                        # Select feature set based on format_type
                        if format_type == 'compatible':
                            features.append(feature_compatible)
                        else:
                            features.append(feature_enhanced)
                        
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f'Error processing line {line_num}: {e}')
                    continue
        
        # Convert to DataFrame and save
        if features:
            df = pd.DataFrame(features)
            
            if format_type == 'compatible':
                # For compatible format, save as-is (15 columns)
                df.to_csv(output_file, index=False)
                print(f'Compatible dataset saved: {output_file}')
                print(f'Total HTTP events: {len(df)}')
                print(f'Features: {len(df.columns)} (compatible format)')
            else:
                # For enhanced format, remove metadata columns for ML dataset
                ml_columns = [col for col in df.columns if col not in ['timestamp', 'original_url', 'http_method', 'attack_type']]
                ml_df = df[ml_columns]
                
                # Save full dataset with metadata
                df.to_csv(output_file.replace('.csv', '_full.csv'), index=False)
                print(f'Full dataset saved: {output_file.replace(\".csv\", \"_full.csv\")}')
                
                # Save ML-ready dataset
                ml_df.to_csv(output_file, index=False)
                print(f'Enhanced dataset saved: {output_file}')
                print(f'Total HTTP events: {len(df)}')
                print(f'Features extracted: {len(ml_df.columns)} (enhanced format)')
            
            # Show feature summary for attack datasets
            if label == 1:  # Attack dataset
                xss_indicators = [
                    'url_contains_script_tag', 'url_contains_onerror', 'url_contains_alert'
                ]
                if format_type == 'enhanced':
                    xss_indicators.extend(['url_contains_javascript', 'url_contains_onload', 'url_contains_onclick'])
                
                for indicator in xss_indicators:
                    if indicator in df.columns:
                        count = df[indicator].sum()
                        if count > 0:
                            print(f'  {indicator}: {count} occurrences')
            
            return len(df)
        else:
            print(f'No HTTP events found in {eve_file}')
            return 0
            
    except FileNotFoundError:
        print(f'File not found: {eve_file}')
        return 0
    except Exception as e:
        print(f'Error processing {eve_file}: {e}')
        return 0

# Process benign dataset
print('=' * 60)
print('PROCESSING BENIGN DATASET - COMPATIBLE FORMAT')
print('=' * 60)

benign_count_compatible = extract_http_features(
    '/captures/benign_eve_${TIMESTAMP}.json',
    0,  # Label: benign
    '/analysis/benign_dataset_${TIMESTAMP}.csv',
    'compatible'
)

print('=' * 60)
print('PROCESSING BENIGN DATASET - ENHANCED FORMAT')
print('=' * 60)

benign_count_enhanced = extract_http_features(
    '/captures/benign_eve_${TIMESTAMP}.json',
    0,  # Label: benign
    '/analysis/benign_dataset_${TIMESTAMP}_enhanced.csv',
    'enhanced'
)

print()
print('=' * 60)
print('PROCESSING ATTACK DATASET - COMPATIBLE FORMAT') 
print('=' * 60)

# Process attack dataset
attack_count_compatible = extract_http_features(
    '/captures/attack_eve_${TIMESTAMP}.json',
    1,  # Label: malicious
    '/analysis/attack_dataset_${TIMESTAMP}.csv',
    'compatible'
)

print('=' * 60)
print('PROCESSING ATTACK DATASET - ENHANCED FORMAT') 
print('=' * 60)

# Process attack dataset
attack_count_enhanced = extract_http_features(
    '/captures/attack_eve_${TIMESTAMP}.json',
    1,  # Label: malicious
    '/analysis/attack_dataset_${TIMESTAMP}_enhanced.csv',
    'enhanced'
)

print()
print('=' * 60)
print('PROCESSING SUMMARY')
print('=' * 60)
print(f'COMPATIBLE FORMAT (15 columns):')
print(f'  Benign HTTP events: {benign_count_compatible}')
print(f'  Attack HTTP events: {attack_count_compatible}')
print(f'  Total events: {benign_count_compatible + attack_count_compatible}')
print()
print(f'ENHANCED FORMAT (34+ columns):')
print(f'  Benign HTTP events: {benign_count_enhanced}')
print(f'  Attack HTTP events: {attack_count_enhanced}')
print(f'  Total events: {benign_count_enhanced + attack_count_enhanced}')

# Copy to labeled_datasets directory
import shutil
os.makedirs('/data/labeled_datasets', exist_ok=True)

# Copy compatible format files
if os.path.exists('/analysis/benign_dataset_${TIMESTAMP}.csv'):
    shutil.copy('/analysis/benign_dataset_${TIMESTAMP}.csv', '/data/labeled_datasets/')

if os.path.exists('/analysis/attack_dataset_${TIMESTAMP}.csv'):
    shutil.copy('/analysis/attack_dataset_${TIMESTAMP}.csv', '/data/labeled_datasets/')

# Copy enhanced format files  
if os.path.exists('/analysis/benign_dataset_${TIMESTAMP}_enhanced.csv'):
    shutil.copy('/analysis/benign_dataset_${TIMESTAMP}_enhanced.csv', '/data/labeled_datasets/')
    shutil.copy('/analysis/benign_dataset_${TIMESTAMP}_enhanced_full.csv', '/data/labeled_datasets/')

if os.path.exists('/analysis/attack_dataset_${TIMESTAMP}_enhanced.csv'):
    shutil.copy('/analysis/attack_dataset_${TIMESTAMP}_enhanced.csv', '/data/labeled_datasets/')
    shutil.copy('/analysis/attack_dataset_${TIMESTAMP}_enhanced_full.csv', '/data/labeled_datasets/')

print('Datasets copied to /data/labeled_datasets/')
"

# Copy the files from container to host
log "📋 Copying processed datasets to host..."

# Create the datasets directory on host
mkdir -p "$DATASET_DIR"

# Copy compatible format files (15 columns)
if docker exec sec_monitor test -f "/analysis/benign_dataset_${TIMESTAMP}.csv"; then
    docker cp "sec_monitor:/analysis/benign_dataset_${TIMESTAMP}.csv" "$DATASET_DIR/"
    log_success "Benign dataset (compatible) copied to host"
else
    log_warning "Benign dataset (compatible) not found in container"
fi

if docker exec sec_monitor test -f "/analysis/attack_dataset_${TIMESTAMP}.csv"; then
    docker cp "sec_monitor:/analysis/attack_dataset_${TIMESTAMP}.csv" "$DATASET_DIR/"
    log_success "Attack dataset (compatible) copied to host"
else
    log_warning "Attack dataset (compatible) not found in container"
fi

# Copy enhanced format files (34+ columns)
if docker exec sec_monitor test -f "/analysis/benign_dataset_${TIMESTAMP}_enhanced.csv"; then
    docker cp "sec_monitor:/analysis/benign_dataset_${TIMESTAMP}_enhanced.csv" "$DATASET_DIR/"
    docker cp "sec_monitor:/analysis/benign_dataset_${TIMESTAMP}_enhanced_full.csv" "$DATASET_DIR/"
    log_success "Benign dataset (enhanced) copied to host"
else
    log_warning "Benign dataset (enhanced) not found in container"
fi

if docker exec sec_monitor test -f "/analysis/attack_dataset_${TIMESTAMP}_enhanced.csv"; then
    docker cp "sec_monitor:/analysis/attack_dataset_${TIMESTAMP}_enhanced.csv" "$DATASET_DIR/"
    docker cp "sec_monitor:/analysis/attack_dataset_${TIMESTAMP}_enhanced_full.csv" "$DATASET_DIR/"
    log_success "Attack dataset (enhanced) copied to host"
else
    log_warning "Attack dataset (enhanced) not found in container"
fi

# Show summary
log "📊 Dataset processing summary:"
if [ -f "$DATASET_DIR/benign_dataset_${TIMESTAMP}.csv" ]; then
    BENIGN_COUNT=$(tail -n +2 "$DATASET_DIR/benign_dataset_${TIMESTAMP}.csv" | wc -l)
    log "   Benign samples: $BENIGN_COUNT"
fi

if [ -f "$DATASET_DIR/attack_dataset_${TIMESTAMP}.csv" ]; then
    ATTACK_COUNT=$(tail -n +2 "$DATASET_DIR/attack_dataset_${TIMESTAMP}.csv" | wc -l)
    log "   Attack samples: $ATTACK_COUNT"
fi

log_success "✅ Dataset processing and labeling completed!"
log "📁 Labeled datasets available in: $DATASET_DIR"
