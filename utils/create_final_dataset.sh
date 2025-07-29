#!/bin/bash
set -euo pipefail

# Create Final Dataset - Merge and shuffle attack and benign datasets

TIMESTAMP="${1:-$(date +"%Y%m%d_%H%M%S")}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATASET_DIR="$PROJECT_ROOT/data/labeled_datasets"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')] [FINAL] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] [FINAL] ✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] [FINAL] ⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] [FINAL] ❌ $1${NC}"
}

log "🔀 Creating final merged and shuffled dataset..."

# Check if the individual datasets exist
BENIGN_FILE="$DATASET_DIR/benign_dataset_${TIMESTAMP}.csv"
ATTACK_FILE="$DATASET_DIR/attack_dataset_${TIMESTAMP}.csv"

if [ ! -f "$BENIGN_FILE" ]; then
    log_error "Benign dataset not found: $BENIGN_FILE"
    exit 1
fi

if [ ! -f "$ATTACK_FILE" ]; then
    log_error "Attack dataset not found: $ATTACK_FILE"
    exit 1
fi

log_success "Found both benign and attack datasets"

# Use Python to merge and shuffle the datasets
python3 -c "
import pandas as pd
import numpy as np
from sklearn.utils import shuffle
import os

# Read the datasets
print('Loading datasets...')
benign_df = pd.read_csv('$BENIGN_FILE')
attack_df = pd.read_csv('$ATTACK_FILE')

print(f'Benign samples: {len(benign_df)}')
print(f'Attack samples: {len(attack_df)}')

# Verify the structure - check for 'label' column (your format) vs 'is_malicious'
expected_columns = ['timestamp', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 
                   'http_method', 'http_status', 'http_resp_len', 'http_url', 'http_user_agent', 
                   'http_url_len', 'url_contains_script_tag', 'url_contains_onerror', 'label']

# Check if datasets match your format
if 'label' in benign_df.columns and 'label' in attack_df.columns:
    label_col = 'label'
elif 'is_malicious' in benign_df.columns and 'is_malicious' in attack_df.columns:
    label_col = 'is_malicious'
else:
    print('Error: No recognized label column found')
    exit(1)

print(f'Using label column: {label_col}')

if benign_df.columns.tolist() != attack_df.columns.tolist():
    print('Warning: Column mismatch between datasets')
    print('Benign columns:', benign_df.columns.tolist()[:5], '...')
    print('Attack columns:', attack_df.columns.tolist()[:5], '...')
    
    # Use common columns only
    common_cols = list(set(benign_df.columns) & set(attack_df.columns))
    benign_df = benign_df[common_cols]
    attack_df = attack_df[common_cols]
    print(f'Using {len(common_cols)} common columns')

# Merge the datasets
print('Merging datasets...')
merged_df = pd.concat([benign_df, attack_df], ignore_index=True)

# Shuffle the dataset
print('Shuffling dataset...')
shuffled_df = shuffle(merged_df, random_state=42)

# Reset index
shuffled_df = shuffled_df.reset_index(drop=True)

# Create dataset summary
total_samples = len(shuffled_df)
malicious_samples = shuffled_df[label_col].sum()
benign_samples = total_samples - malicious_samples
malicious_percentage = (malicious_samples / total_samples) * 100

print()
print('=' * 60)
print('FINAL DATASET SUMMARY')
print('=' * 60)
print(f'Total samples: {total_samples}')
print(f'Benign samples: {benign_samples}')
print(f'Malicious samples: {malicious_samples}')
print(f'Malicious percentage: {malicious_percentage:.1f}%')
print(f'Features: {len(shuffled_df.columns) - 1}')  # Excluding label column

# Feature analysis for attack samples
if malicious_samples > 0:
    attack_subset = shuffled_df[shuffled_df[label_col] == 1]
    print()
    print('XSS Attack Pattern Analysis:')
    xss_features = [col for col in shuffled_df.columns if 'url_contains_' in col]
    for feature in xss_features:
        if feature in attack_subset.columns:
            count = attack_subset[feature].sum()
            if count > 0:
                percentage = (count / malicious_samples) * 100
                print(f'  {feature}: {count}/{malicious_samples} ({percentage:.1f}%)')

# Check for data quality
print()
print('Data Quality Checks:')
print(f'Missing values: {shuffled_df.isnull().sum().sum()}')
print(f'Duplicate rows: {shuffled_df.duplicated().sum()}')

# Remove duplicates if any
if shuffled_df.duplicated().sum() > 0:
    print('Removing duplicate rows...')
    shuffled_df = shuffled_df.drop_duplicates().reset_index(drop=True)
    print(f'Final dataset size: {len(shuffled_df)}')

# Save the final dataset
output_file = '$DATASET_DIR/final_xss_dataset_${TIMESTAMP}.csv'
shuffled_df.to_csv(output_file, index=False)
print(f'Final dataset saved: {output_file}')

# Create a smaller balanced dataset for quick testing
if len(shuffled_df) > 1000:
    print()
    print('Creating balanced subset for testing...')
    
    # Get equal numbers of each class (up to 500 each)
    max_per_class = min(500, benign_samples, malicious_samples)
    
    benign_subset = shuffled_df[shuffled_df[label_col] == 0].head(max_per_class)
    attack_subset = shuffled_df[shuffled_df[label_col] == 1].head(max_per_class)
    
    balanced_df = pd.concat([benign_subset, attack_subset], ignore_index=True)
    balanced_df = shuffle(balanced_df, random_state=42).reset_index(drop=True)
    
    balanced_file = '$DATASET_DIR/balanced_xss_dataset_${TIMESTAMP}.csv'
    balanced_df.to_csv(balanced_file, index=False)
    print(f'Balanced dataset saved: {balanced_file}')
    print(f'Balanced dataset size: {len(balanced_df)} ({len(benign_subset)} benign, {len(attack_subset)} attack)')

# Create metadata file
metadata = {
    'timestamp': '${TIMESTAMP}',
    'total_samples': int(total_samples),
    'benign_samples': int(benign_samples),
    'malicious_samples': int(malicious_samples),
    'malicious_percentage': float(malicious_percentage),
    'features_count': len(shuffled_df.columns) - 1,
    'feature_names': [col for col in shuffled_df.columns if col != label_col],
    'xss_patterns_detected': {
        feature: int(attack_subset[feature].sum()) if malicious_samples > 0 and feature in attack_subset.columns else 0
        for feature in xss_features
    },
    'data_quality': {
        'missing_values': int(shuffled_df.isnull().sum().sum()),
        'duplicates_removed': int(shuffled_df.duplicated().sum())
    }
}

import json
metadata_file = '$DATASET_DIR/dataset_metadata_${TIMESTAMP}.json'
with open(metadata_file, 'w') as f:
    json.dump(metadata, f, indent=2)

print(f'Metadata saved: {metadata_file}')
print()
print('✅ Final dataset creation completed!')
"

# Create a simple analysis script for the final dataset
cat > "$DATASET_DIR/analyze_dataset_${TIMESTAMP}.py" << 'EOF'
#!/usr/bin/env python3
"""
Quick analysis script for the generated XSS dataset
Usage: python3 analyze_dataset_TIMESTAMP.py
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

def analyze_dataset(dataset_file):
    """Analyze the XSS dataset"""
    print("🔍 XSS Dataset Analysis")
    print("=" * 50)
    
    # Load dataset
    df = pd.read_csv(dataset_file)
    
    # Basic statistics
    print(f"Dataset: {dataset_file}")
    print(f"Total samples: {len(df)}")
    print(f"Features: {len(df.columns) - 1}")
    print(f"Benign samples: {(df['is_malicious'] == 0).sum()}")
    print(f"Malicious samples: {(df['is_malicious'] == 1).sum()}")
    print(f"Class balance: {(df['is_malicious'] == 1).mean():.1%} malicious")
    
    # Feature analysis
    print("\n📊 Feature Analysis:")
    feature_cols = [col for col in df.columns if col != 'is_malicious']
    print(f"Numerical features: {len(feature_cols)}")
    
    # XSS pattern analysis
    xss_features = [col for col in df.columns if 'url_contains_' in col]
    if xss_features and df['is_malicious'].sum() > 0:
        print("\n🎯 XSS Pattern Distribution:")
        attack_df = df[df['is_malicious'] == 1]
        for feature in xss_features:
            count = attack_df[feature].sum()
            if count > 0:
                print(f"  {feature}: {count}")
    
    # Feature correlations with target
    print("\n🔗 Top Features Correlated with Malicious Label:")
    correlations = df[feature_cols].corrwith(df['is_malicious']).abs().sort_values(ascending=False)
    print(correlations.head(10))
    
    return df

if __name__ == "__main__":
    # Find the dataset file
    dataset_files = list(Path(".").glob("final_xss_dataset_*.csv"))
    if dataset_files:
        analyze_dataset(dataset_files[0])
    else:
        print("No dataset file found")
EOF

chmod +x "$DATASET_DIR/analyze_dataset_${TIMESTAMP}.py"

log_success "✅ Final dataset creation completed!"
log "📁 Files created:"
log "   📊 Final dataset: final_xss_dataset_${TIMESTAMP}.csv"
log "   ⚖️ Balanced dataset: balanced_xss_dataset_${TIMESTAMP}.csv"
log "   📋 Metadata: dataset_metadata_${TIMESTAMP}.json"
log "   🔍 Analysis script: analyze_dataset_${TIMESTAMP}.py"

# Show final summary
if [ -f "$DATASET_DIR/final_xss_dataset_${TIMESTAMP}.csv" ]; then
    TOTAL_SAMPLES=$(tail -n +2 "$DATASET_DIR/final_xss_dataset_${TIMESTAMP}.csv" | wc -l)
    FEATURES=$(head -1 "$DATASET_DIR/final_xss_dataset_${TIMESTAMP}.csv" | tr ',' '\n' | wc -l)
    log "📈 Final dataset stats: $TOTAL_SAMPLES samples, $((FEATURES-1)) features"
fi

log "🎉 Dataset is ready for ML training!"
