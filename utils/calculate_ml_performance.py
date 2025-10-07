#!/usr/bin/env python3

"""
ML Performance Calculator
Extracts performance metrics (Precision, Recall, F1-Score) from experiment results
"""

import re
import sys
import argparse
from pathlib import Path

def parse_experiment_results(file_path):
    """Parse experiment results file and extract metrics"""
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Extract all iterations
    iterations = []
    iteration_blocks = re.findall(r'ITERATION \d+.*?-------------------------------------------', content, re.DOTALL)
    
    for block in iteration_blocks:
        # Extract ground truth
        total_requests = int(re.search(r'Total HTTP Requests: (\d+)', block).group(1))
        attack_requests = int(re.search(r'Attack Requests: (\d+)', block).group(1))
        benign_requests = int(re.search(r'Benign Requests: (\d+)', block).group(1))
        
        # Extract detections
        mode1_detections = int(re.search(r'Mode 1 \(Official Rules\): (\d+) detections', block).group(1))
        mode2_detections = int(re.search(r'Mode 2 \(ML Detection\): (\d+) detections', block).group(1))
        
        iterations.append({
            'total_requests': total_requests,
            'actual_attacks': attack_requests,
            'actual_benign': benign_requests,
            'mode1_detections': mode1_detections,
            'mode2_detections': mode2_detections
        })
    
    return iterations

def calculate_ml_performance(iterations):
    """Calculate ML performance metrics across all iterations"""
    
    # Aggregate across all iterations
    total_actual_attacks = sum(it['actual_attacks'] for it in iterations)
    total_actual_benign = sum(it['actual_benign'] for it in iterations)
    total_ml_detections = sum(it['mode2_detections'] for it in iterations)
    total_requests = sum(it['total_requests'] for it in iterations)
    
    # Calculate performance metrics
    # True Positives: Assuming ML detections are mostly correct attacks
    # Since ML detection > actual attacks, we need to estimate TP, FP
    
    # Conservative estimate: TP = min(ml_detections, actual_attacks)
    true_positives = min(total_ml_detections, total_actual_attacks)
    
    # False Positives: ML detections beyond actual attacks
    false_positives = max(0, total_ml_detections - total_actual_attacks)
    
    # False Negatives: Actual attacks not detected by ML
    false_negatives = max(0, total_actual_attacks - total_ml_detections)
    
    # True Negatives: Benign requests not flagged
    true_negatives = total_actual_benign - false_positives
    
    # Ensure non-negative values
    true_negatives = max(0, true_negatives)
    
    # Calculate metrics
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    accuracy = (true_positives + true_negatives) / total_requests if total_requests > 0 else 0
    
    return {
        'iterations': len(iterations),
        'total_requests': total_requests,
        'total_actual_attacks': total_actual_attacks,
        'total_actual_benign': total_actual_benign,
        'total_ml_detections': total_ml_detections,
        'true_positives': true_positives,
        'false_positives': false_positives,
        'false_negatives': false_negatives,
        'true_negatives': true_negatives,
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'accuracy': accuracy
    }

def calculate_mode1_performance(iterations):
    """Calculate Mode 1 (Suricata Rules) performance metrics"""
    
    total_actual_attacks = sum(it['actual_attacks'] for it in iterations)
    total_actual_benign = sum(it['actual_benign'] for it in iterations)
    total_mode1_detections = sum(it['mode1_detections'] for it in iterations)
    total_requests = sum(it['total_requests'] for it in iterations)
    
    # Conservative estimates for Mode 1
    true_positives = min(total_mode1_detections, total_actual_attacks)
    false_positives = max(0, total_mode1_detections - total_actual_attacks)
    false_negatives = max(0, total_actual_attacks - total_mode1_detections)
    true_negatives = max(0, total_actual_benign - false_positives)
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (true_positives + true_negatives) / total_requests if total_requests > 0 else 0
    
    return {
        'total_mode1_detections': total_mode1_detections,
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'accuracy': accuracy
    }

def print_performance_report(ml_metrics, mode1_metrics):
    """Print comprehensive performance report"""
    
    print("=" * 70)
    print("🎯 ML PERFORMANCE ANALYSIS REPORT")
    print("=" * 70)
    print()
    
    print(f"📊 DATASET SUMMARY:")
    print(f"   Total Iterations: {ml_metrics['iterations']}")
    print(f"   Total HTTP Requests: {ml_metrics['total_requests']:,}")
    print(f"   Actual Attacks: {ml_metrics['total_actual_attacks']:,}")
    print(f"   Actual Benign: {ml_metrics['total_actual_benign']:,}")
    print(f"   Attack Rate: {ml_metrics['total_actual_attacks']/ml_metrics['total_requests']*100:.1f}%")
    print()
    
    print(f"🛡️  MODE 1 (SURICATA RULES) PERFORMANCE:")
    print(f"   Total Detections: {mode1_metrics['total_mode1_detections']}")
    print(f"   Precision: {mode1_metrics['precision']:.3f}")
    print(f"   Recall: {mode1_metrics['recall']:.3f}")
    print(f"   F1-Score: {mode1_metrics['f1_score']:.3f}")
    print(f"   Accuracy: {mode1_metrics['accuracy']:.3f}")
    print()
    
    print(f"🤖 MODE 2 (ML DETECTION) PERFORMANCE:")
    print(f"   Total Detections: {ml_metrics['total_ml_detections']}")
    print(f"   Precision: {ml_metrics['precision']:.3f}")
    print(f"   Recall: {ml_metrics['recall']:.3f}")
    print(f"   F1-Score: {ml_metrics['f1_score']:.3f}")
    print(f"   Accuracy: {ml_metrics['accuracy']:.3f}")
    print()
    
    print(f"📈 DETAILED ML CONFUSION MATRIX:")
    print(f"   True Positives (TP): {ml_metrics['true_positives']}")
    print(f"   False Positives (FP): {ml_metrics['false_positives']}")
    print(f"   False Negatives (FN): {ml_metrics['false_negatives']}")
    print(f"   True Negatives (TN): {ml_metrics['true_negatives']}")
    print()
    
    print(f"🔄 COMPARISON:")
    print(f"   ML vs Rules Precision: {ml_metrics['precision']:.3f} vs {mode1_metrics['precision']:.3f}")
    print(f"   ML vs Rules Recall: {ml_metrics['recall']:.3f} vs {mode1_metrics['recall']:.3f}")
    print(f"   ML vs Rules F1-Score: {ml_metrics['f1_score']:.3f} vs {mode1_metrics['f1_score']:.3f}")
    
    # Determine winner
    if ml_metrics['f1_score'] > mode1_metrics['f1_score']:
        print(f"   🏆 Winner: ML Detection (F1: {ml_metrics['f1_score']:.3f})")
    else:
        print(f"   🏆 Winner: Suricata Rules (F1: {mode1_metrics['f1_score']:.3f})")
    print()
    
    print(f"⚠️  NOTE: These metrics are estimated based on detection counts.")
    print(f"   For exact metrics, individual request classification is needed.")
    print()

def main():
    parser = argparse.ArgumentParser(description='Calculate ML performance metrics from experiment results')
    parser.add_argument('results_file', help='Path to experiment results file')
    parser.add_argument('--output', '-o', help='Output file for performance report')
    
    args = parser.parse_args()
    
    if not Path(args.results_file).exists():
        print(f"❌ Error: File {args.results_file} not found")
        sys.exit(1)
    
    try:
        # Parse experiment results
        iterations = parse_experiment_results(args.results_file)
        
        if not iterations:
            print("❌ Error: No iterations found in results file")
            sys.exit(1)
        
        # Calculate performance metrics
        ml_metrics = calculate_ml_performance(iterations)
        mode1_metrics = calculate_mode1_performance(iterations)
        
        # Print report
        if args.output:
            # Redirect output to file
            import io
            from contextlib import redirect_stdout
            
            f = io.StringIO()
            with redirect_stdout(f):
                print_performance_report(ml_metrics, mode1_metrics)
            
            with open(args.output, 'w') as out_file:
                out_file.write(f.getvalue())
            
            print(f"✅ Performance report saved to: {args.output}")
        else:
            print_performance_report(ml_metrics, mode1_metrics)
            
    except Exception as e:
        print(f"❌ Error processing results: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
