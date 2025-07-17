#!/usr/bin/env python3
"""
Debug ML Model Predictions
"""

import json
import pandas as pd
import pickle
from urllib.parse import unquote

# Load the model
with open('/scripts/models/detection_model.pkl', 'rb') as f:
    model = pickle.load(f)

def extract_features(event):
    """Extract features from HTTP event for ML prediction"""
    try:
        http_data = event.get('http', {})
        url = http_data.get('url', '')
        method = http_data.get('http_method', 'GET')
        status = http_data.get('status', 200)
        length = http_data.get('length', 0)
        src_port = event.get('src_port', 0)
        dest_port = event.get('dest_port', 80)
        decoded_url = unquote(url)
        
        features = {
            'http_url_len': len(decoded_url),
            'src_port': src_port,
            'http_resp_len': length,
            'http_status': status,
            'url_contains_script_tag': 1 if '<script' in decoded_url.lower() else 0,
            'url_contains_onerror': 1 if 'onerror' in decoded_url.lower() else 0,
            'http_method_POST': 1 if method == 'POST' else 0,
            'dest_port': dest_port
        }
        
        feature_df = pd.DataFrame([features])
        expected_features = ['http_url_len', 'src_port', 'http_resp_len', 'http_status', 
                           'url_contains_script_tag', 'url_contains_onerror', 'http_method_POST', 'dest_port']
        
        for col in expected_features:
            if col not in feature_df.columns:
                feature_df[col] = 0.0
        
        feature_df = feature_df[expected_features]
        return feature_df
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

# Test specific examples
test_events = [
    {
        "event_type": "http",
        "src_port": 52710,
        "dest_port": 80,
        "http": {
            "url": "/?q=<script>alert(1)</script>",
            "http_method": "GET",
            "status": 200,
            "length": 1024
        }
    },
    {
        "event_type": "http",
        "src_port": 52711,
        "dest_port": 80,
        "http": {
            "url": "/rest/products/1",
            "http_method": "GET", 
            "status": 404,
            "length": 273
        }
    },
    {
        "event_type": "http",
        "src_port": 52712,
        "dest_port": 80,
        "http": {
            "url": "/",
            "http_method": "GET", 
            "status": 200,
            "length": 5000
        }
    }
]

print("=== Model Prediction Debug ===")
print(f"Model type: {type(model).__name__}")
print(f"Model has predict_proba: {hasattr(model, 'predict_proba')}")

for i, event in enumerate(test_events):
    print(f"\nEvent {i+1}:")
    print(f"URL: {event['http']['url']}")
    print(f"Status: {event['http']['status']}")
    print(f"Response Length: {event['http']['length']}")
    
    features = extract_features(event)
    if features is not None:
        print("Features:")
        print(features.to_string())
        
        # Make prediction
        prediction = model.predict(features)[0]
        
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(features)[0]
            print(f"Prediction: {prediction}")
            print(f"Probabilities: [benign: {probabilities[0]:.3f}, xss: {probabilities[1]:.3f}]")
        else:
            print(f"Prediction: {prediction}")
    else:
        print("Failed to extract features")
