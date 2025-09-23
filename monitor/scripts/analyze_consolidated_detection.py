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
    request_groups = defaultdict(list)
    
    for alert in xss_alerts:
        flow_id = alert.get('flow_id', 'unknown')
        timestamp = alert.get('timestamp', '')[:19]
        src_ip = alert.get('src_ip', '')
        dest_ip = alert.get('dest_ip', '')
        http_data = alert.get('http', {})
        url = http_data.get('url', '')
        
        request_key = f"{flow_id}_{timestamp}_{src_ip}_{dest_ip}_{url}"
        request_groups[request_key].append(alert)
    
    # Calculate detected attack ratio (consolidating multiple rule triggers per request)
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
        from mode2_ml_detector import MLXSSDetector
        
        # Load ML detector
        detector = MLXSSDetector()
        
        if detector.model is None:
            print("❌ ML model not available, using pattern fallback")
            # Simple pattern fallback
            import re
            ml_detections = 0
            detected_requests = []
            
            xss_patterns = [r'<script', r'javascript:', r'alert\(', r'onerror\s*=']
            
            for event in http_events:
                url = event.get('http', {}).get('url', '')
                if any(re.search(pattern, url, re.IGNORECASE) for pattern in xss_patterns):
                    ml_detections += 1
                    detected_requests.append({
                        'timestamp': event.get('timestamp'),
                        'url': url,
                        'confidence': 0.75
                    })
            
            detected_attack_ratio = (ml_detections / len(http_events) * 100) if http_events else 0
            
            return {
                'total_requests': len(http_events),
                'xss_detections': ml_detections,
                'detected_attack_ratio': detected_attack_ratio,
                'detected_requests': detected_requests,
                'model_type': 'Pattern Fallback'
            }
        
        print(f"🔧 ML Model: {type(detector.model).__name__}")
        print(f"   Features: {len(detector.feature_columns)}")
        print(f"   Optimized threshold: 0.35 (vs default 0.5)")
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
                    
                    # Use optimized threshold of 0.35
                    is_attack = probability > 0.35
                    
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
        
        print(f"🔍 OPTIMIZED ML ANALYSIS:")
        print(f"   Detection Method: RandomForest with threshold=0.35")
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
            'model_type': 'Optimized ML (threshold=0.35)',
            'avg_confidence': avg_confidence,
            'confidence_distribution': {
                'high': high_conf,
                'medium': medium_conf, 
                'low': low_conf
            }
        }
        
    except Exception as e:
        print(f"❌ Error with optimized ML: {e}")
        import traceback
        traceback.print_exc()
        return None
    print("⚡ MODE 2: OPTIMIZED PATTERN DETECTION")
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
    
    # Comprehensive XSS patterns (based on actual attack evidence)
    xss_patterns = [
        # Script injection
        r'<script[^>]*>',
        r'javascript:',
        r'%3Cscript',
        r'&lt;script',
        
        # Event handlers
        r'onerror\s*=',
        r'onload\s*=', 
        r'onclick\s*=',
        r'onmouseover\s*=',
        r'onfocus\s*=',
        r'onkeyup\s*=',
        r'onchange\s*=',
        r'onsubmit\s*=',
        
        # JavaScript functions
        r'alert\s*\(',
        r'confirm\s*\(',
        r'prompt\s*\(',
        r'eval\s*\(',
        r'document\.write',
        r'top\.alert',
        
        # HTML injection with event handlers
        r'<img[^>]*onerror',
        r'<audio[^>]*onerror', 
        r'<video[^>]*onerror',
        r'<iframe[^>]*onload',
        r'<svg[^>]*onload',
        r'<body[^>]*onload',
        r'<marquee[^>]*on\w+',
        r'<input[^>]*onfocus',
        r'<textarea[^>]*onfocus',
        r'<button[^>]*onmouseover',
        
        # Iframe and object injections
        r'<iframe[^>]*src\s*=\s*[\'"]?javascript:',
        r'<iframe[^>]*srcdoc',
        r'<object[^>]*data\s*=\s*[\'"]?javascript:',
        r'<embed[^>]*src\s*=\s*[\'"]?javascript:',
        
        # Style-based XSS
        r'style\s*=\s*[\'"][^\'\"]*javascript:',
        r'<style[^>]*onload',
        
        # Meta refresh XSS
        r'<meta[^>]*http-equiv.*refresh.*javascript:',
        
        # Form-based XSS
        r'<form[^>]*action\s*=\s*[\'"]?javascript:',
        
        # MathML XSS
        r'<math[^>]*xmlns.*onload',
        r'<mstyle[^>]*onload',
        
        # SVG-based XSS
        r'<svg[^>]*><script',
        r'<animate[^>]*onbegin',
        
        # Encoding variants
        r'%22%3E%3Cscript',  # "><script
        r'%3C%2Fscript%3E',  # </script>
        r'&quot;&gt;&lt;script',
    ]
    
    detected_requests = []
    pattern_matches = {}
    
    for event in http_events:
        http_data = event.get('http', {})
        url = http_data.get('url', '')
        
        matched_patterns = []
        for i, pattern in enumerate(xss_patterns):
            if re.search(pattern, url, re.IGNORECASE):
                matched_patterns.append(i)
        
        if matched_patterns:
            # Calculate confidence based on number and type of matches
            confidence = min(0.75 + (len(matched_patterns) * 0.05), 0.95)
            
            detected_requests.append({
                'timestamp': event.get('timestamp'),
                'url': url,
                'confidence': confidence,
                'matched_patterns': len(matched_patterns)
            })
            
            # Track pattern usage
            for pattern_idx in matched_patterns:
                pattern_matches[pattern_idx] = pattern_matches.get(pattern_idx, 0) + 1
    
    detected_attack_ratio = (len(detected_requests) / len(http_events) * 100) if http_events else 0
    
    print(f"🔍 OPTIMIZED PATTERN ANALYSIS:")
    print(f"   Detection Method: Comprehensive pattern matching")
    print(f"   Total Patterns: {len(xss_patterns)}")
    print(f"   Active Patterns: {len(pattern_matches)}")
    print(f"   XSS Attacks Detected: {len(detected_requests)}")
    print(f"   Detected Attack Ratio: {detected_attack_ratio:.1f}%")
    print()
    
    print(f"🎯 TOP TRIGGERED PATTERNS:")
    sorted_patterns = sorted(pattern_matches.items(), key=lambda x: x[1], reverse=True)
    for i, (pattern_idx, count) in enumerate(sorted_patterns[:5]):
        pattern = xss_patterns[pattern_idx]
        print(f"   {i+1}. {pattern:<30} ({count} matches)")
    print()
    
    print(f"🎯 DETECTION SAMPLES:")
    for i, detection in enumerate(detected_requests[:5]):
        print(f"   {i+1}. {detection['url']} (conf: {detection['confidence']:.2f}, patterns: {detection['matched_patterns']})")
    
    if len(detected_requests) > 5:
        print(f"   ... and {len(detected_requests) - 5} more detections")
    print()
    
    return {
        'total_requests': len(http_events),
        'xss_detections': len(detected_requests),
        'detected_attack_ratio': detected_attack_ratio,
        'detected_requests': detected_requests,
        'model_type': 'Optimized Pattern Matching',
        'active_patterns': len(pattern_matches),
        'total_patterns': len(xss_patterns)
    }
    """Analyze Mode 2: HYBRID Detection (Pattern-based + ML validation)"""
    
    print("=" * 60)
    print("🤖 MODE 2: HYBRID DETECTION ANALYSIS")
    print("=" * 60)
    
    try:
        with open(eve_file, 'r') as f:
            events = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ Error: File {eve_file} not found")
        return None
    
    # Extract HTTP events for analysis
    http_events = [e for e in events if e.get('event_type') == 'http']
    
    print(f"Total HTTP Requests: {len(http_events)}")
    print()
    
    # Hybrid approach: Pattern-based detection + ML validation
    import sys
    import os
    import re
    sys.path.append('/scripts')
    
    # XSS detection patterns (proven effective)
    xss_patterns = [
        r'<script',
        r'javascript:',
        r'alert\(',
        r'eval\(',
        r'document\.write',
        r'onclick\s*=',
        r'onload\s*=',
        r'onerror\s*=',
        r'<iframe',
        r'<svg.*onload',
        r'onmouseover\s*=',
        r'onfocus\s*=',
        r'<img.*onerror',
        r'<audio.*onerror',
        r'<video.*onerror'
    ]
    
    try:
        # Try to load ML detector for validation
        from mode2_ml_detector import MLXSSDetector
        ml_detector = MLXSSDetector()
        ml_available = ml_detector.model is not None
        print(f"🔧 ML Validator: {'Available' if ml_available else 'Pattern-only mode'}")
    except:
        ml_detector = None
        ml_available = False
        print(f"🔧 ML Validator: Pattern-only mode")
    
    print()
    
    hybrid_detections = 0
    detected_requests = []
    pattern_matches = 0
    ml_confirmations = 0
    
    for event in http_events:
        http_data = event.get('http', {})
        url = http_data.get('url', '')
        
        # Step 1: Pattern-based detection (primary)
        pattern_detected = any(re.search(pattern, url, re.IGNORECASE) for pattern in xss_patterns)
        
        if pattern_detected:
            pattern_matches += 1
            confidence = 0.75  # Base confidence for pattern match
            
            # Step 2: ML validation (if available)
            if ml_available:
                try:
                    is_xss_ml, ml_prob = ml_detector.predict_xss(event)
                    if is_xss_ml:
                        # ML confirms pattern detection
                        confidence = min(0.85 + (ml_prob * 0.15), 0.95)
                        ml_confirmations += 1
                    else:
                        # ML disagrees, reduce confidence but still detect
                        confidence = max(0.65, 0.75 * ml_prob)
                except:
                    pass  # Keep pattern-based confidence
            
            hybrid_detections += 1
            detected_requests.append({
                'timestamp': event.get('timestamp'),
                'url': url,
                'confidence': confidence,
                'detection_method': 'pattern+ml' if ml_available else 'pattern'
            })
    
    detected_attack_ratio = (hybrid_detections / len(http_events) * 100) if http_events else 0
    
    print(f"🔍 HYBRID DETECTION ANALYSIS:")
    print(f"   Detection Method: Pattern-based + ML validation")
    print(f"   Pattern Matches: {pattern_matches}")
    if ml_available:
        print(f"   ML Confirmations: {ml_confirmations}")
        print(f"   ML Confirmation Rate: {(ml_confirmations/pattern_matches*100):.1f}%" if pattern_matches > 0 else "   ML Confirmation Rate: N/A")
    print(f"   Final Detections: {hybrid_detections}")
    print(f"   Detected Attack Ratio: {detected_attack_ratio:.1f}%")
    print()
    
    print(f"🎯 HYBRID DETECTION RESULTS:")
    for i, detection in enumerate(detected_requests[:5]):  # Show first 5
        method = detection.get('detection_method', 'pattern')
        print(f"   {i+1}. {detection['url']} (confidence: {detection['confidence']:.3f}, method: {method})")
    
    if len(detected_requests) > 5:
        print(f"   ... and {len(detected_requests) - 5} more detections")
    print()
    
    return {
        'total_requests': len(http_events),
        'xss_detections': hybrid_detections,
        'detected_attack_ratio': detected_attack_ratio,
        'detected_requests': detected_requests,
        'model_type': 'Hybrid (Pattern + ML)',
        'pattern_matches': pattern_matches,
        'ml_confirmations': ml_confirmations if ml_available else 0
    }

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
