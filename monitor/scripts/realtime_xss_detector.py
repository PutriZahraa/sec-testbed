#!/usr/bin/env python3

"""
Real-Time XSS Detection Monitor
Continuously processes Suricata eve.json events for real-time attack detection
Combines Mode 1 (Suricata Rules) + Mode 2 (ACTUAL ML Model Detection)
"""

import json
import time
import re
import signal
import sys
import os
import pickle
import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict, deque
from threading import Thread, Event
from urllib.parse import unquote
import subprocess

class RealTimeXSSDetector:
    def __init__(self, eve_file='/captures/eve.json', alerts_file='/captures/realtime_alerts.json'):
        self.eve_file = eve_file
        self.alerts_file = alerts_file
        self.running = True
        self.stats = {
            'total_http_requests': 0,
            'total_alerts': 0,
            'mode1_detections': 0,  # Suricata rule alerts
            'mode2_detections': 0,  # ML pattern detections
            'session_start': datetime.now(),
            'recent_attacks': deque(maxlen=50)  # Keep last 50 attacks
        }
        
        # Load actual ML model (from mode2_ml_detector.py)
        self.model_path = "/scripts/models/detection_model.pkl"
        self.model = None
        self.feature_columns = None
        self.load_ml_model()
        
        # Mode 1: XSS alert keywords (from analyze_consolidated_detection.py)
        self.xss_keywords = ['xss', 'script', 'javascript', 'cross', 'inject', 'client', 'alert', 'eval', 'document']
        
        self.stop_event = Event()
        
    def load_ml_model(self):
        """Load the trained ML model for actual Mode 2 detection"""
        print("🔄 Loading ML model...")
        try:
            print(f"   Reading model from: {self.model_path}")
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            print("   Model file loaded, processing...")
            
            # Handle both old and new model formats
            if isinstance(model_data, dict) and 'model' in model_data:
                self.model = model_data['model']
                self.feature_columns = model_data['feature_names']
                print("   Using new model format (dict)")
            else:
                self.model = model_data
                # Default order based on training output
                self.feature_columns = [
                    'src_port', 'dest_port', 'http_status', 'http_resp_len', 'http_url_len',
                    'url_contains_script_tag', 'url_contains_onerror', 'http_method_POST'
                ]
                print("   Using legacy model format")
            
            print(f"✅ ML Model loaded successfully: {type(self.model).__name__}")
            print(f"   Features: {len(self.feature_columns)}")
            
        except Exception as e:
            print(f"❌ CRITICAL: Failed to load ML model: {e}")
            print("   Real-time detection requires ML model!")
            self.model = None
            raise Exception("ML model loading failed - cannot start real-time detection")
        
        print("🔄 Model loading complete, starting monitoring system...")
        
    def log_alert(self, alert_type, event_data, confidence=None):
        """Log real-time alert to alerts file"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'alert_type': alert_type,  # 'mode1' or 'mode2'
            'confidence': confidence,
            'event_data': {
                'src_ip': event_data.get('src_ip'),
                'dest_ip': event_data.get('dest_ip'),
                'http_url': event_data.get('http', {}).get('url', ''),
                'flow_id': event_data.get('flow_id'),
                'signature': event_data.get('alert', {}).get('signature', '') if alert_type == 'mode1' else 'ML Pattern Detection'
            }
        }
        
        # Write to alerts file
        try:
            with open(self.alerts_file, 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except Exception as e:
            print(f"Error writing alert: {e}")
            
        # Add to recent attacks for dashboard
        self.stats['recent_attacks'].append(alert)
        
    def extract_features(self, event):
        """Extract features from HTTP event for ML prediction - from mode2_ml_detector.py"""
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
            
            # Extract features EXACTLY as in training script
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
            
            # Create DataFrame with correct column order
            feature_df = pd.DataFrame([features])
            
            # Ensure all required columns exist
            for col in self.feature_columns:
                if col not in feature_df.columns:
                    feature_df[col] = 0.0
            
            # Reorder columns to match model expectations
            feature_df = feature_df[self.feature_columns]
            
            return feature_df
            
        except Exception as e:
            return None
    
    def predict_xss_ml(self, event):
        """Use actual ML model to predict XSS attack - matching analyze_consolidated_detection.py approach"""
        if self.model is None:
            return False, 0.0
        
        features = self.extract_features(event)
        if features is None:
            return False, 0.0
        
        try:
            # Get ML probability - exactly like in analyze_consolidated_detection.py
            probability = self.model.predict_proba(features)[0][1]
            
            # Use optimized threshold of 0.35 - exactly like in analyze_consolidated_detection.py
            optimized_threshold = 0.35
            is_attack = probability > optimized_threshold
            
            return is_attack, probability
            
        except Exception as e:
            print(f"⚠️  ML prediction error: {e}", flush=True)
            return False, 0.0
    

        
    def process_mode1_alert(self, event):
        """Process Mode 1: Suricata Rule Alerts"""
        if event.get('event_type') != 'alert':
            return False
            
        alert_data = event.get('alert', {})
        signature = alert_data.get('signature', '').lower()
        
        # Check if it's an XSS-related alert
        if any(keyword in signature for keyword in self.xss_keywords):
            self.stats['mode1_detections'] += 1
            self.log_alert('mode1', event)
            return True
        return False
        
    def process_mode2_ml(self, event):
        """Process Mode 2: ACTUAL ML Model Detection"""
        if event.get('event_type') != 'http':
            return False
            
        # Use actual ML model for prediction
        is_xss, confidence = self.predict_xss_ml(event)
        
        if is_xss:
            self.stats['mode2_detections'] += 1
            self.log_alert('mode2', event, confidence)
            return True
        return False
        
    def process_event(self, event_line):
        """Process a single eve.json event line"""
        try:
            event = json.loads(event_line.strip())
        except (json.JSONDecodeError, AttributeError):
            return
            
        event_type = event.get('event_type')
        
        # Count HTTP requests
        if event_type == 'http':
            self.stats['total_http_requests'] += 1
            
        # Count all alerts
        if event_type == 'alert':
            self.stats['total_alerts'] += 1
            
        # Process Mode 1 (Suricata Rules)
        mode1_detected = self.process_mode1_alert(event)
        
        # Process Mode 2 (ML Patterns)
        mode2_detected = self.process_mode2_ml(event)
        
        # Print real-time detection
        if mode1_detected or mode2_detected:
            timestamp = datetime.now().strftime('%H:%M:%S')
            url = event.get('http', {}).get('url', event.get('alert', {}).get('signature', 'N/A'))
            # Truncate long URLs for cleaner output
            display_url = url[:60] + "..." if len(url) > 60 else url
            
            if mode1_detected and mode2_detected:
                print(f"[{timestamp}] 🔴 BOTH {display_url}", flush=True)
            elif mode1_detected:
                print(f"[{timestamp}] 🛡️  M1 {display_url}", flush=True)
            elif mode2_detected:
                print(f"[{timestamp}] 🤖 M2 {display_url}", flush=True)
                
    def tail_eve_file(self):
        """Continuously tail the eve.json file for new events"""        
        print(f"📡 Starting to monitor {self.eve_file}...", flush=True)
        try:
            # Use subprocess to tail the file
            process = subprocess.Popen(['tail', '-F', self.eve_file], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     universal_newlines=True)
            
            print("📡 File monitoring active - waiting for events...", flush=True)
                                     
            while self.running and not self.stop_event.is_set():
                line = process.stdout.readline()
                if line:
                    self.process_event(line)
                else:
                    time.sleep(0.1)  # Short pause if no new lines
                    
        except FileNotFoundError:
            print(f"❌ Error: {self.eve_file} not found", flush=True)
        except KeyboardInterrupt:
            print("\n⏹️  Stopping real-time monitoring...", flush=True)
        except Exception as e:
            print(f"❌ Error in tail monitoring: {e}", flush=True)
        finally:
            if 'process' in locals():
                process.terminate()
                
    def print_dashboard(self):
        """Print simple statistics without clearing screen"""
        print("🚀 Real-Time XSS Detection Started", flush=True)
        print("🔍 Watching for attacks... (detections will appear below)", flush=True)
        print("Press Ctrl+C to stop monitoring", flush=True)
        print("-" * 50, flush=True)
        
        while self.running and not self.stop_event.is_set():
            time.sleep(30)  # Show stats every 30 seconds
            
            if self.stats['total_http_requests'] > 0:
                print(f"\n📊 Stats: {self.stats['total_http_requests']} requests, " +
                      f"🛡️ {self.stats['mode1_detections']} M1, " +
                      f"🤖 {self.stats['mode2_detections']} M2 detections", flush=True)
            
            # Only show if there are many requests to avoid spam
            if self.stats['total_http_requests'] > 50:
                time.sleep(60)  # Slow down stats when busy
            
    def start(self):
        """Start real-time monitoring"""
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Initialize alerts file
        with open(self.alerts_file, 'w') as f:
            f.write("")
            
        # Start dashboard thread (minimal stats)
        dashboard_thread = Thread(target=self.print_dashboard, daemon=True)
        dashboard_thread.start()
        
        # Start main monitoring (blocking)
        self.tail_eve_file()
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n📊 Final Statistics:")
        print(f"   Session Duration: {datetime.now() - self.stats['session_start']}")
        print(f"   Total HTTP Requests: {self.stats['total_http_requests']}")
        print(f"   Mode 1 Detections: {self.stats['mode1_detections']}")
        print(f"   Mode 2 Detections: {self.stats['mode2_detections']}")
        print(f"   Alerts saved to: {self.alerts_file}")
        
        self.running = False
        self.stop_event.set()
        sys.exit(0)

def main():
    print("🚀 Initializing Real-Time XSS Detector...", flush=True)
    try:
        detector = RealTimeXSSDetector()
        if detector.model is None:
            print("❌ CRITICAL: No ML model available - cannot start real-time detection", flush=True)
            print("   Please ensure the ML model is properly trained and saved", flush=True)
            sys.exit(1)
        detector.start()
    except KeyboardInterrupt:
        print("\n⏹️  Detector stopped by user", flush=True)
    except Exception as e:
        print(f"❌ Error starting detector: {e}", flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
