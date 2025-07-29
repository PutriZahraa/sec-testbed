#!/usr/bin/env python3
"""
Dataset Merger Utility
Merges benign and attack datasets with different timestamps into a final training dataset.
Useful for manual dataset creation and fixing timestamp coordination issues.
"""

import csv
import random
import sys
import os
from datetime import datetime

def merge_datasets(benign_file, attack_file, output_file=None):
    """Merge benign and attack datasets into a shuffled final dataset"""
    
    print(f"🔀 Merging datasets:")
    print(f"  Benign: {benign_file}")
    print(f"  Attack: {attack_file}")
    
    # Check if files exist
    if not os.path.exists(benign_file):
        print(f"❌ Benign file not found: {benign_file}")
        return False
    
    if not os.path.exists(attack_file):
        print(f"❌ Attack file not found: {attack_file}")
        return False
    
    # Read benign dataset
    benign_data = []
    with open(benign_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            benign_data.append(row)

    # Read attack dataset  
    attack_data = []
    with open(attack_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            attack_data.append(row)

    print(f"✅ Loaded {len(benign_data)} benign samples")
    print(f"✅ Loaded {len(attack_data)} attack samples")

    if not benign_data and not attack_data:
        print("❌ No data found in either file")
        return False

    # Combine datasets
    all_data = benign_data + attack_data

    # Shuffle the combined dataset
    random.seed(42)  # For reproducible results
    random.shuffle(all_data)

    # Generate output filename if not provided
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"data/labeled_datasets/merged_dataset_{timestamp}.csv"

    # Write the final dataset
    with open(output_file, 'w', newline='') as f:
        if all_data:
            fieldnames = all_data[0].keys()
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_data)

    print()
    print("=" * 60)
    print("MERGED DATASET SUMMARY")
    print("=" * 60)
    print(f"Total samples: {len(all_data)}")
    print(f"Benign samples: {len(benign_data)} (label=0)")
    print(f"Attack samples: {len(attack_data)} (label=1)")
    if all_data:
        print(f"Attack percentage: {(len(attack_data) / len(all_data) * 100):.1f}%")
        print(f"Dataset columns: {len(fieldnames)} features")

    # Analyze XSS features in attack samples
    if attack_data and all_data:
        print()
        print("XSS Pattern Analysis (Attack samples):")
        script_count = sum(1 for row in attack_data if row.get('url_contains_script_tag') == '1')
        onerror_count = sum(1 for row in attack_data if row.get('url_contains_onerror') == '1')
        
        if script_count > 0:
            print(f"  - Script tags detected: {script_count}/{len(attack_data)} ({script_count/len(attack_data)*100:.1f}%)")
        if onerror_count > 0:
            print(f"  - OnError events detected: {onerror_count}/{len(attack_data)} ({onerror_count/len(attack_data)*100:.1f}%)")

    print()
    print(f"✅ Final shuffled dataset saved: {output_file}")
    print("🎯 Dataset is ready for ML training!")
    
    return True

def main():
    """Main function with command line interface"""
    if len(sys.argv) < 3:
        print("Usage: python3 merge_datasets.py <benign_file> <attack_file> [output_file]")
        print()
        print("Examples:")
        print("  python3 merge_datasets.py benign_20250728_123456.csv attack_20250728_234567.csv")
        print("  python3 merge_datasets.py benign.csv attack.csv final_dataset.csv")
        sys.exit(1)
    
    benign_file = sys.argv[1]
    attack_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Add data/labeled_datasets/ prefix if not absolute path
    if not benign_file.startswith('/') and not benign_file.startswith('data/'):
        benign_file = f"data/labeled_datasets/{benign_file}"
    if not attack_file.startswith('/') and not attack_file.startswith('data/'):
        attack_file = f"data/labeled_datasets/{attack_file}"
    
    success = merge_datasets(benign_file, attack_file, output_file)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
