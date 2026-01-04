#!/usr/bin/env python3

"""
Official Rules (Mode 1) vs ML Detection (Mode 2) Comparison
Follows the main README.md workflow for proper comparison
Uses real official rules with post-processing consolidation only
"""

import json
import sys
import argparse
from datetime import datetime
from collections import defaultdict, Counter
import re

def analyze_mode1_official(eve_file):
    """Analyze Mode 1: Official Suricata Rules Detection (with consolidation)"""
    
    print("=" * 60)
    print("📊 MODE 1: OFFICIAL SURICATA RULES ANALYSIS")
    print("=" * 60)
    
    try:
        with open(eve_file, 'r') as f:
            events = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ Error: File {eve_file} not found")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in {eve_file}: {e}")
        return None
    
    # Separate events
    alerts = [e for e in events if e.get('event_type') == 'alert']
    http_events = [e for e in events if e.get('event_type') == 'http']
    
    print(f"Total HTTP Requests: {len(http_events)}")
    print(f"Alert Events Generated: {len(alerts)}")
    print()
    
    # Filter XSS-related alerts (post-processing only, not rule modification)
    xss_keywords = ['xss', 'script', 'javascript', 'cross', 'inject', 'client', 'alert', 'eval', 'document']
    xss_alerts = []
    
    for alert in alerts:
        alert_data = alert.get('alert', {})
        signature = alert_data.get('signature', '').lower()
        
        if any(keyword in signature for keyword in xss_keywords):
            xss_alerts.append(alert)
    
    print(f"🔍 OFFICIAL SURICATA RULE ANALYSIS:")
    print(f"   Rule Detection: Active")
    print(f"   XSS-related Alerts: {len(xss_alerts)}")
    print(f"   Total Rule Triggers: {len(alerts)}")
    print()
    
    # Consolidate multiple alerts per HTTP request (for fair ML comparison)
    # This is POST-PROCESSING, not rule modification
    # Option 2: HTTP request fingerprinting (more reliable than flow_id)
    request_groups = defaultdict(list)
    
    for alert in xss_alerts:
        # Create composite key based on actual HTTP request content
        http_data = alert.get('http', {})
        hostname = http_data.get('hostname', 'unknown')
        url = http_data.get('url', '')
        method = http_data.get('http_method', 'unknown')
        src_ip = alert.get('src_ip', 'unknown')
        timestamp = alert.get('timestamp', '')[:19]  # Second precision
        
        # HTTP request fingerprint: combines request identity markers
        request_key = f"{hostname}_{url}_{method}_{src_ip}_{timestamp}"
        request_groups[request_key].append(alert)
    
    # Calculate detected attack ratio (consolidating multiple rule triggers per request)
    # Using HTTP fingerprinting ensures same logical request = single detection
    unique_xss_detections = len(request_groups)
    detected_attack_ratio = (unique_xss_detections / len(http_events) * 100) if http_events else 0
    
    print(f"Detected Attack Ratio: {detected_attack_ratio:.1f}%")
    print()
    
    # Show alert signatures (official rules in action)
    signature_counts = Counter()
    for alert in xss_alerts:
        sig = alert.get('alert', {}).get('signature', 'Unknown')
        signature_counts[sig] += 1
    
    print(f"📋 ALERT SIGNATURES:")
    for sig, count in signature_counts.most_common():
        print(f"    {count:2d}x {sig}")
    print()
    
    return {
        'total_requests': len(http_events),
        'xss_detections': unique_xss_detections,
        'detected_attack_ratio': detected_attack_ratio,
        'alert_details': xss_alerts,
        'signature_counts': signature_counts
    }

def analyze_mode2_optimized_ml(eve_file):
    """Mode 2: Optimized ML Detection with better threshold"""
    
    print("=" * 60)
    print("🤖 MODE 2: OPTIMIZED ML DETECTION")
    print("=" * 60)
    
    try:
        with open(eve_file, 'r') as f:
            events = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ Error: File {eve_file} not found")
        return None
    
    http_events = [e for e in events if e.get('event_type') == 'http']
    print(f"Total HTTP Requests: {len(http_events)}")
    print()
    
    # Use the actual ML detector with optimized threshold
    import sys
    import os
    sys.path.append('/scripts')
    
    try:
        from mode2_new_ml import MLXSSDetector
        
        # Load ML detector
        detector = MLXSSDetector()
        
        if detector.model is None:
            print("❌ ML model not available - cannot perform ML detection")
            return None
        
        print(f"🔧 ML Model: {type(detector.model).__name__}")
        print(f"   Features: {len(detector.feature_columns)}")
        print(f"   Higher threshold: 0.65 (to reduce false positives)")
        print()
        
        # Process events with optimized threshold
        ml_detections = 0
        detected_requests = []
        confidence_scores = []
        
        for event in http_events:
            features = detector.extract_features(event)
            if features is not None:
                try:
                    # Get ML probability
                    probability = detector.model.predict_proba(features)[0][1]
                    confidence_scores.append(probability)
                    
                    # Use higher threshold of 0.65 to reduce false positives
                    is_attack = probability > 0.65
                    
                    if is_attack:
                        ml_detections += 1
                        detected_requests.append({
                            'timestamp': event.get('timestamp'),
                            'url': event.get('http', {}).get('url', ''),
                            'confidence': probability
                        })
                        
                except Exception as e:
                    confidence_scores.append(0.0)
            else:
                confidence_scores.append(0.0)
        
        detected_attack_ratio = (ml_detections / len(http_events) * 100) if http_events else 0
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        print(f"🔍 NEW ML ANALYSIS:")
        print(f"   Detection Method: RandomForest with threshold=0.65")
        print(f"   XSS Attacks Detected: {ml_detections}")
        print(f"   Detected Attack Ratio: {detected_attack_ratio:.1f}%")
        print(f"   Average Confidence: {avg_confidence:.3f}")
        print()
        
        # Show confidence distribution
        high_conf = sum(1 for c in confidence_scores if c > 0.6)
        medium_conf = sum(1 for c in confidence_scores if 0.3 < c <= 0.6)
        low_conf = sum(1 for c in confidence_scores if c <= 0.3)
        
        print(f"📊 CONFIDENCE DISTRIBUTION:")
        print(f"   High confidence (>0.6): {high_conf} requests")
        print(f"   Medium confidence (0.3-0.6): {medium_conf} requests")
        print(f"   Low confidence (≤0.3): {low_conf} requests")
        print()
        
        print(f"🎯 TOP DETECTIONS:")
        # Sort by confidence and show top examples
        detected_requests.sort(key=lambda x: x['confidence'], reverse=True)
        for i, detection in enumerate(detected_requests[:5]):
            print(f"   {i+1}. {detection['url']} (confidence: {detection['confidence']:.3f})")
        
        if len(detected_requests) > 5:
            print(f"   ... and {len(detected_requests) - 5} more detections")
        print()
        
        return {
            'total_requests': len(http_events),
            'xss_detections': ml_detections,
            'detected_attack_ratio': detected_attack_ratio,
            'detected_requests': detected_requests,
            'model_type': 'New ML (rf_xss_detector.pkl, threshold=0.65)',
            'avg_confidence': avg_confidence,
            'confidence_distribution': {
                'high': high_conf,
                'medium': medium_conf, 
                'low': low_conf
            }
        }
        
    except Exception as e:
        print(f"❌ Error with ML detection: {e}")
        import traceback
        traceback.print_exc()
        return None


def compare_modes(mode1_results, mode2_results):
    """Compare Mode 1 (Official Rules) vs Mode 2 (ML) Detection"""
    
    print("=" * 60)
    print("🔄 MODE COMPARISON SUMMARY")
    print("=" * 60)
    
    if not mode1_results or not mode2_results:
        print("❌ Cannot compare - missing results")
        return
    
    print(f"📊 DETECTION COMPARISON:")
    print(f"   Total HTTP Requests: {mode1_results['total_requests']}")
    print()
    
    print(f"🛡️  MODE 1 (Official Suricata Rules):")
    print(f"   XSS Detections: {mode1_results['xss_detections']}")
    print(f"   Detected Attack Ratio: {mode1_results['detected_attack_ratio']:.1f}%")
    print()
    
    print(f"🤖 MODE 2 (ML Detection):")
    print(f"   Model Type: {mode2_results.get('model_type', 'Unknown')}")
    print(f"   XSS Detections: {mode2_results['xss_detections']}")
    print(f"   Detected Attack Ratio: {mode2_results['detected_attack_ratio']:.1f}%")
    print()
    
    # Comparison analysis
    detection_diff = mode1_results['xss_detections'] - mode2_results['xss_detections']
    
    print(f"📈 DETECTION SUMMARY:")
    print(f"   Official Rules: {mode1_results['xss_detections']} XSS detections")
    print(f"   ML Detection: {mode2_results['xss_detections']} XSS detections")
    if detection_diff > 0:
        print(f"   Detection Difference: {detection_diff} more by Official Rules")
    elif detection_diff < 0:
        print(f"   Detection Difference: {abs(detection_diff)} more by ML Detection")
    else:
        print(f"   Detection Difference: Both methods detected equal amounts")
    print()
    
    print(f"⚠️  NOTE: Performance evaluation requires actual attack count comparison")
    print()

def main():
    parser = argparse.ArgumentParser(description='Compare Official Rules vs ML Detection')
    parser.add_argument('eve_file', help='Path to eve.json file')
    parser.add_argument('--mode', choices=['1', '2', 'both'], default='both', 
                       help='Analysis mode: 1=Official Rules, 2=ML, both=Comparison')
    
    args = parser.parse_args()
    
    if args.mode in ['1', 'both']:
        mode1_results = analyze_mode1_official(args.eve_file)
    else:
        mode1_results = None
        
    if args.mode in ['2', 'both']:
        mode2_results = analyze_mode2_optimized_ml(args.eve_file)
    else:
        mode2_results = None
    
    if args.mode == 'both' and mode1_results and mode2_results:
        compare_modes(mode1_results, mode2_results)

if __name__ == "__main__":
    main()
