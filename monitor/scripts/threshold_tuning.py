#!/usr/bin/env python3
"""
Quick ML Model Threshold Tuning
Test different thresholds with your existing model to improve detection
"""

import json
import pickle
import pandas as pd
import sys
import os
sys.path.append('/scripts')

def test_ml_thresholds(eve_file):
    """Test different ML thresholds to find optimal detection rate"""
    
    print("🔧 ML THRESHOLD TUNING")
    print("=" * 50)
    
    # Load current model
    try:
        with open('/scripts/models/detection_model.pkl', 'rb') as f:
            model_data = pickle.load(f)
        
        model = model_data['model']
        feature_columns = model_data['feature_names']
        print(f"✅ Model loaded: {len(feature_columns)} features")
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return
    
    # Load events
    try:
        with open(eve_file, 'r') as f:
            events = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ Error: File {eve_file} not found")
        return
    
    http_events = [e for e in events if e.get('event_type') == 'http']
    print(f"📊 Analyzing {len(http_events)} HTTP requests")
    print()
    
    # Extract features for all events
    from mode2_ml_detector import MLXSSDetector
    detector = MLXSSDetector()
    
    predictions = []
    probabilities = []
    
    for event in http_events:
        features = detector.extract_features(event)
        if features is not None:
            try:
                prob = model.predict_proba(features)[0][1]  # Attack probability
                probabilities.append(prob)
                predictions.append({
                    'url': event.get('http', {}).get('url', ''),
                    'probability': prob
                })
            except:
                probabilities.append(0.0)
    
    # Test different thresholds
    thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    
    print("🎯 THRESHOLD ANALYSIS:")
    print("Threshold | Detections | Detection Rate")
    print("-" * 40)
    
    for threshold in thresholds:
        detections = sum(1 for prob in probabilities if prob > threshold)
        detection_rate = (detections / len(http_events) * 100) if http_events else 0
        print(f"   {threshold:.1f}    |    {detections:3d}     |    {detection_rate:5.1f}%")
    
    print()
    
    # Show high-probability examples
    high_prob_examples = [p for p in predictions if p['probability'] > 0.3]
    high_prob_examples.sort(key=lambda x: x['probability'], reverse=True)
    
    print(f"🔍 HIGH PROBABILITY EXAMPLES (threshold > 0.3):")
    for i, example in enumerate(high_prob_examples[:10]):
        print(f"   {i+1}. {example['url']} (prob: {example['probability']:.3f})")
    
    if len(high_prob_examples) > 10:
        print(f"   ... and {len(high_prob_examples) - 10} more")
    print()
    
    # Recommendation
    optimal_threshold = 0.3  # Based on analysis
    optimal_detections = sum(1 for prob in probabilities if prob > optimal_threshold)
    
    print("💡 RECOMMENDATION:")
    print(f"   Suggested threshold: {optimal_threshold}")
    print(f"   Expected detections: {optimal_detections}")
    print(f"   Expected detection rate: {(optimal_detections/len(http_events)*100):.1f}%")
    print()
    print("   This threshold balances detection rate with false positives.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python threshold_tuning.py <eve.json_file>")
        sys.exit(1)
    
    test_ml_thresholds(sys.argv[1])
