#!/usr/bin/env python3
"""
Debug ML Feature Extraction
"""

import json
import pandas as pd
from urllib.parse import unquote

# Test with a few sample events
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
    }
]

def extract_features(event):
    """Extract features from HTTP event for ML prediction - FIXED to match training model"""
    try:
        # Get HTTP data
        http_data = event.get('http', {})
        
        # Extract basic features from HTTP event
        url = http_data.get('url', '')
        method = http_data.get('http_method', 'GET')
        status = http_data.get('status', 200)
        length = http_data.get('length', 0)
        
        # Get network data
        src_port = event.get('src_port', 0)
        dest_port = event.get('dest_port', 80)
        
        # Decode URL to get actual content
        decoded_url = unquote(url)
        
        # Extract features EXACTLY as in your training script
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
        
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

print("=== Feature Extraction Debug ===")
for i, event in enumerate(test_events):
    print(f"\nEvent {i+1}:")
    print(f"URL: {event['http']['url']}")
    print(f"Method: {event['http']['http_method']}")
    print(f"Status: {event['http']['status']}")
    
    features = extract_features(event)
    if features:
        print("Extracted features:")
        for feature, value in features.items():
            print(f"  {feature}: {value}")
        
        print(f"Expected label: {'XSS' if features['url_contains_script_tag'] or features['url_contains_onerror'] else 'Benign'}")
    else:
        print("Failed to extract features")
