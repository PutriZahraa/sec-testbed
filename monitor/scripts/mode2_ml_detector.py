#!/usr/bin/env python3
"""
Mode 2 ML Detection Script
Tests ML effectiveness for XSS detection using HTTP events only
Uses existing trained detection_model.pkl for actual ML inference
"""

import json
import pickle
import pandas as pd
import numpy as np
import sys
import os
from datetime import datetime
from collections import defaultdict
from urllib.parse import unquote

class MLXSSDetector:
    def __init__(self):
        # Load the trained ML model
        self.model_path = "/scripts/models/detection_model.pkl"  # Updated path
        self.model = None
        self.feature_columns = None
        
        # Detection stats
        self.stats = {
            'total_requests': 0,
            'xss_detected': 0,
            'ml_predictions': defaultdict(int),
            'feature_extraction_errors': 0,
            'true_positives': 0
        }
        
        # Load the model
        self.load_model()
    
    def load_model(self):
        """Load the trained ML model"""
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            print(f"DEBUG: Model data type: {type(model_data)}")
            print(f"DEBUG: Is dict: {isinstance(model_data, dict)}")
            
            # Handle both old and new model formats
            if isinstance(model_data, dict) and 'model' in model_data:
                self.model = model_data['model']
                self.feature_columns = model_data['feature_names']
                print(f"✅ ML Model loaded successfully from: {self.model_path}")
                print(f"   Model type: {type(self.model).__name__}")
                print(f"   Features: {len(self.feature_columns)}")
                print(f"   Feature order: {self.feature_columns}")
            else:
                self.model = model_data
                # Default order based on training output
                self.feature_columns = [
                    'src_port', 'dest_port', 'http_status', 'http_resp_len', 'http_url_len',
                    'url_contains_script_tag', 'url_contains_onerror', 'http_method_POST'
                ]
                print(f"✅ ML Model loaded successfully from: {self.model_path}")
                print(f"   Model type: {type(self.model).__name__}")
                print(f"   Features: {len(self.feature_columns)}")
            
        except Exception as e:
            print(f"❌ Error loading ML model: {e}")
            print("   Falling back to basic XSS pattern detection")
            self.model = None
    
    def extract_features(self, event):
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
            
            # Create DataFrame with correct column order (matching the loaded model)
            feature_df = pd.DataFrame([features])
            
            # Ensure all required columns exist (use the feature order from the loaded model)
            for col in self.feature_columns:
                if col not in feature_df.columns:
                    feature_df[col] = 0.0
            
            # Reorder columns to match model expectations
            feature_df = feature_df[self.feature_columns]
            
            return feature_df
            
        except Exception as e:
            print(f"Feature extraction error: {e}")
            self.stats['feature_extraction_errors'] += 1
            return None
    
    def predict_xss(self, event):
        """Use ML model to predict XSS attack"""
        if self.model is None:
            return self.pattern_based_xss_detection(event)
        
        features = self.extract_features(event)
        if features is None:
            return False, 0.0
        
        try:
            # Make prediction
            prediction = self.model.predict(features)[0]
            
            # Get prediction probability if available
            if hasattr(self.model, 'predict_proba'):
                probability = self.model.predict_proba(features)[0][1]
            else:
                probability = 1.0 if prediction == 1 else 0.0
            
            return prediction == 1, probability
            
        except Exception as e:
            print(f"ML prediction error: {e}")
            self.stats['feature_extraction_errors'] += 1
            # Fallback to pattern-based detection
            return self.pattern_based_xss_detection(event)
    
    def pattern_based_xss_detection(self, event):
        """Pattern-based XSS detection as ML fallback"""
        http_data = event.get('http', {})
        url = http_data.get('url', '')
        
        # Decode URL to get actual content
        decoded_url = unquote(url)
        
        # XSS patterns to detect
        xss_patterns = [
            '<script', 'javascript:', 'alert(', 'confirm(', 'prompt(',
            'onerror=', 'onload=', 'onclick=', 'onmouseover=', 'onfocus=',
            'onstart=', '<svg', '<iframe', '<img', '<body', '<marquee',
            '<form', '<input', '<math', 'document.', 'window.'
        ]
        
        # Check for XSS patterns (case-insensitive)
        url_lower = decoded_url.lower()
        xss_found = any(pattern in url_lower for pattern in xss_patterns)
        
        # Calculate confidence based on pattern matching
        if xss_found:
            # Count how many patterns matched
            pattern_count = sum(1 for pattern in xss_patterns if pattern in url_lower)
            confidence = min(0.5 + (pattern_count * 0.1), 0.95)
            return True, confidence
        else:
            return False, 0.1
    
    def process_event(self, event):
        """Process a single event"""
        if event.get('event_type') != 'http':
            return
        
        self.stats['total_requests'] += 1
        
        # Use ML model to predict XSS
        is_xss, probability = self.predict_xss(event)
        
        if is_xss:
            self.stats['xss_detected'] += 1
            self.stats['true_positives'] += 1
            
            http_data = event.get('http', {})
            
            print(f"🚨 ML XSS DETECTED: {event.get('timestamp', 'N/A')}")
            print(f"   URL: {http_data.get('url', 'N/A')}")
            print(f"   Method: {http_data.get('http_method', 'N/A')}")
            print(f"   Status: {http_data.get('status', 'N/A')}")
            print(f"   ML Confidence: {probability:.2f}")
            print()
        
        # Track prediction distribution
        pred_key = f"malicious_{probability:.1f}" if is_xss else f"benign_{probability:.1f}"
        self.stats['ml_predictions'][pred_key] += 1
    
    def analyze_file(self, filename):
        """Analyze events from file"""
        print(f"🔍 Analyzing Mode 2 events from: {filename}")
        print("=" * 60)
        
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            event = json.loads(line)
                            self.process_event(event)
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            print(f"❌ File not found: {filename}")
            return
        
        self.print_summary()
    
    def print_summary(self):
        """Print detection summary"""
        print("=" * 60)
        print("📊 MODE 2 ML DETECTION SUMMARY")
        print("=" * 60)
        print(f"Total HTTP Requests: {self.stats['total_requests']}")
        print(f"XSS Attacks Detected: {self.stats['xss_detected']}")
        print(f"Detection Rate: {(self.stats['xss_detected'] / self.stats['total_requests'] * 100):.1f}%")
        print()
        
        print("🤖 ML DETECTION ANALYSIS:")
        print(f"   Model Type: {type(self.model).__name__ if self.model else 'Pattern-based fallback'}")
        print(f"   Features Used: {len(self.feature_columns)}")
        print()
        
        print("📈 ML Prediction Distribution:")
        sorted_predictions = sorted(self.stats['ml_predictions'].items(), 
                                  key=lambda x: x[1], reverse=True)
        for pred_type, count in sorted_predictions[:5]:
            print(f"   {pred_type}: {count} events")
        print()
        
        if self.stats['feature_extraction_errors'] > 0:
            print(f"⚠️  Feature extraction errors: {self.stats['feature_extraction_errors']}")
            print()
        if self.stats['total_requests'] > 0:
            detection_rate = (self.stats['xss_detected'] / self.stats['total_requests']) * 100
            
            print("📊 DETECTION RATE ANALYSIS:")
            print(f"   Detection Rate: {detection_rate:.1f}% of HTTP traffic flagged as attacks")
            print(f"   Detected Attacks: {self.stats['xss_detected']}")
            print(f"   Total HTTP Requests: {self.stats['total_requests']}")
            print(f"   Unflagged Requests: {self.stats['total_requests'] - self.stats['xss_detected']}")
            print()
            print("💡 Note: Detection rate shows what percentage of HTTP traffic was flagged as attacks.")
            print("   This doesn't indicate model effectiveness without knowing the actual attack rate in the traffic.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 mode2_ml_detector.py <eve.json>")
        sys.exit(1)
    
    filename = sys.argv[1]
    detector = MLXSSDetector()
    detector.analyze_file(filename)

if __name__ == "__main__":
    main()
