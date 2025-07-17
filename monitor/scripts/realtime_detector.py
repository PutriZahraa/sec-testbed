#!/usr/bin/env python3
"""
Real-time ML Detection from Suricata eve.json
Loads pre-trained .pkl model and performs inference on live eve.json events
Seamlessly integrates with existing monitor container architecture
"""

import json
import pickle
import pandas as pd
import numpy as np
import time
import logging
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s [REALTIME-DETECTOR] %(message)s')
logger = logging.getLogger(__name__)

class RealtimeMLDetector:
    def __init__(self, 
                 model_path: str = "/models/detection_model.pkl",
                 eve_path: str = "/captures/eve.json",
                 output_dir: str = "/analysis"):
        self.model_path = model_path
        self.eve_path = eve_path
        self.output_dir = output_dir
        self.model = None
        self.feature_columns = None
        self.detection_log = os.path.join(output_dir, "realtime_detections.log")
        self.last_position = 0
        self.stats = {
            'total_events': 0,
            'predictions_made': 0,
            'malicious_detected': 0,
            'errors': 0
        }
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Load the pre-trained model
        self.load_model()
        
    def load_model(self) -> bool:
        """Load the pre-trained Random Forest model"""
        try:
            if not os.path.exists(self.model_path):
                logger.warning(f"Model file not found: {self.model_path}")
                logger.info("Detector will run in feature extraction mode only")
                return False
                
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            logger.info(f"Successfully loaded model from {self.model_path}")
            
            # Extract feature names from the model
            if hasattr(self.model, 'feature_names_in_'):
                self.feature_columns = list(self.model.feature_names_in_)
            else:
                # Define standard feature columns for network security ML
                self.feature_columns = [
                    'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
                    'total_length_fwd_packets', 'total_length_bwd_packets',
                    'fwd_packet_length_max', 'fwd_packet_length_min',
                    'fwd_packet_length_mean', 'fwd_packet_length_std',
                    'bwd_packet_length_max', 'bwd_packet_length_min', 
                    'bwd_packet_length_mean', 'bwd_packet_length_std',
                    'flow_bytes_per_sec', 'flow_packets_per_sec',
                    'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
                    'fwd_iat_total', 'fwd_iat_mean', 'fwd_iat_std',
                    'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std',
                    'protocol_tcp', 'protocol_udp', 'protocol_icmp'
                ]
            
            logger.info(f"Model expects {len(self.feature_columns)} features")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model = None
            return False
    
    def extract_features_from_eve_event(self, event: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Extract ML features from a single eve.json event compatible with existing architecture"""
        try:
            features = {}
            
            # Initialize with default values
            for col in self.feature_columns:
                features[col] = 0.0
            
            event_type = event.get('event_type', '')
            
            if event_type == 'flow':
                # Extract flow-based features (compatible with existing eve_processor.py)
                flow = event.get('flow', {})
                
                # Basic flow metrics
                features['flow_duration'] = flow.get('age', 0)
                features['total_fwd_packets'] = flow.get('pkts_toserver', 0)
                features['total_bwd_packets'] = flow.get('pkts_toclient', 0)
                features['total_length_fwd_packets'] = flow.get('bytes_toserver', 0)
                features['total_length_bwd_packets'] = flow.get('bytes_toclient', 0)
                
                # Calculate derived features
                total_packets = features['total_fwd_packets'] + features['total_bwd_packets']
                total_bytes = features['total_length_fwd_packets'] + features['total_length_bwd_packets']
                
                if features['flow_duration'] > 0:
                    features['flow_bytes_per_sec'] = total_bytes / features['flow_duration']
                    features['flow_packets_per_sec'] = total_packets / features['flow_duration']
                
                # Protocol encoding
                proto = event.get('proto', '').lower()
                features['protocol_tcp'] = 1 if proto == 'tcp' else 0
                features['protocol_udp'] = 1 if proto == 'udp' else 0
                features['protocol_icmp'] = 1 if proto == 'icmp' else 0
                
                # Packet size statistics (estimated)
                if features['total_fwd_packets'] > 0:
                    features['fwd_packet_length_mean'] = features['total_length_fwd_packets'] / features['total_fwd_packets']
                if features['total_bwd_packets'] > 0:
                    features['bwd_packet_length_mean'] = features['total_length_bwd_packets'] / features['total_bwd_packets']
                
                return features
                
            elif event_type == 'alert':
                # Extract alert-based features (high priority for detection)
                alert = event.get('alert', {})
                flow_info = event.get('flow', {})
                
                # Use alert severity and signature as features
                features['alert_severity'] = alert.get('severity', 0)
                features['alert_signature_id'] = min(alert.get('signature_id', 0), 10000)  # Normalize large IDs
                
                # Include flow info if available
                if flow_info:
                    features['flow_duration'] = flow_info.get('age', 0)
                    features['total_fwd_packets'] = flow_info.get('pkts_toserver', 0)
                    features['total_bwd_packets'] = flow_info.get('pkts_toclient', 0)
                    features['total_length_fwd_packets'] = flow_info.get('bytes_toserver', 0)
                    features['total_length_bwd_packets'] = flow_info.get('bytes_toclient', 0)
                
                # Protocol encoding
                proto = event.get('proto', '').lower()
                features['protocol_tcp'] = 1 if proto == 'tcp' else 0
                features['protocol_udp'] = 1 if proto == 'udp' else 0
                features['protocol_icmp'] = 1 if proto == 'icmp' else 0
                
                return features
                
            elif event_type == 'stats':
                # Extract network statistics features (compatible with ml_demo.py)
                stats = event.get('stats', {})
                decoder = stats.get('decoder', {})
                flow = stats.get('flow', {})
                
                # Convert stats to flow-like features
                features['total_fwd_packets'] = decoder.get('pkts', 0) / 2  # Estimate
                features['total_bwd_packets'] = decoder.get('pkts', 0) / 2  # Estimate
                features['total_length_fwd_packets'] = decoder.get('bytes', 0) / 2
                features['total_length_bwd_packets'] = decoder.get('bytes', 0) / 2
                features['flow_duration'] = 1.0  # Stats interval
                
                # Active flows as a feature
                active_flows = flow.get('active', 0)
                features['active_flows_ratio'] = min(active_flows / 1000.0, 1.0)  # Normalize
                
                return features
            
            return None
            
        except Exception as e:
            logger.debug(f"Error extracting features from {event_type} event: {e}")
            return None
    
    def predict_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Predict if an event is malicious using the loaded model"""
        if not self.model:
            return None
            
        try:
            # Extract features
            features = self.extract_features_from_eve_event(event)
            if not features:
                return None
            
            # Convert to DataFrame with proper column ordering
            df = pd.DataFrame([features])
            
            # Ensure all required columns are present
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = 0.0
            
            # Select only the required columns in the correct order
            df = df[self.feature_columns]
            
            # Make prediction
            prediction = self.model.predict(df)[0]
            probabilities = self.model.predict_proba(df)[0]
            
            return {
                'prediction': int(prediction),
                'probability_benign': float(probabilities[0]),
                'probability_malicious': float(probabilities[1]) if len(probabilities) > 1 else 0.0,
                'confidence': float(max(probabilities)),
                'event_type': event.get('event_type'),
                'features_extracted': len([f for f in features.values() if f != 0.0])
            }
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            self.stats['errors'] += 1
            return None
    
    def log_detection(self, event: Dict[str, Any], prediction_result: Dict[str, Any]) -> None:
        """Log detection results with integration to existing analysis pipeline"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'event_timestamp': event.get('timestamp'),
                'event_type': event.get('event_type'),
                'src_ip': event.get('src_ip'),
                'dest_ip': event.get('dest_ip'),
                'dest_port': event.get('dest_port'),
                'proto': event.get('proto'),
                'prediction': prediction_result['prediction'],
                'confidence': prediction_result['confidence'],
                'probability_malicious': prediction_result['probability_malicious'],
                'is_malicious': prediction_result['prediction'] == 1,
                'features_count': prediction_result['features_extracted']
            }
            
            # Add alert-specific information if available
            if event.get('event_type') == 'alert':
                alert = event.get('alert', {})
                log_entry.update({
                    'alert_signature': alert.get('signature', ''),
                    'alert_severity': alert.get('severity', 0),
                    'alert_signature_id': alert.get('signature_id', 0)
                })
            
            # Write to detection log
            with open(self.detection_log, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
            # Update statistics
            self.stats['predictions_made'] += 1
            if prediction_result['prediction'] == 1:
                self.stats['malicious_detected'] += 1
                
            # Log to console if malicious with high confidence
            if prediction_result['prediction'] == 1 and prediction_result['confidence'] > 0.7:
                logger.warning(f"🚨 MALICIOUS ACTIVITY DETECTED: {event.get('src_ip', 'unknown')} -> {event.get('dest_ip', 'unknown')}:{event.get('dest_port', 'unknown')} "
                             f"(Confidence: {prediction_result['confidence']:.3f}, Type: {event.get('event_type', 'unknown')})")
                
        except Exception as e:
            logger.error(f"Logging error: {e}")
    
    def save_detection_stats(self) -> None:
        """Save detection statistics for integration with existing analysis"""
        try:
            stats_file = os.path.join(self.output_dir, "realtime_detection_stats.json")
            stats_data = {
                'timestamp': datetime.now().isoformat(),
                'model_path': self.model_path,
                'model_loaded': self.model is not None,
                'feature_count': len(self.feature_columns) if self.feature_columns else 0,
                'statistics': self.stats.copy(),
                'detection_rate': f"{(self.stats['malicious_detected'] / max(self.stats['predictions_made'], 1)) * 100:.2f}%"
            }
            
            with open(stats_file, 'w') as f:
                json.dump(stats_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving stats: {e}")
    
    def monitor_eve_json(self) -> None:
        """Monitor eve.json file for new events and perform real-time detection"""
        logger.info("Starting real-time ML detection monitoring...")
        logger.info(f"Monitoring: {self.eve_path}")
        logger.info(f"Output: {self.detection_log}")
        
        if not self.model:
            logger.info("Running in feature extraction mode (no model loaded)")
        
        # Save initial stats
        self.save_detection_stats()
        
        while True:
            try:
                if not os.path.exists(self.eve_path):
                    logger.debug(f"Waiting for {self.eve_path} to be created...")
                    time.sleep(2)
                    continue
                
                # Read new lines from eve.json
                with open(self.eve_path, 'r') as f:
                    f.seek(self.last_position)
                    new_lines = f.readlines()
                    self.last_position = f.tell()
                
                # Process each new event
                events_processed = 0
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                        
                    try:
                        event = json.loads(line)
                        self.stats['total_events'] += 1
                        events_processed += 1
                        
                        # Process events that are useful for ML detection
                        if event.get('event_type') in ['flow', 'alert', 'stats']:
                            if self.model:
                                prediction_result = self.predict_event(event)
                                if prediction_result:
                                    self.log_detection(event, prediction_result)
                            else:
                                # Log features even without model for debugging
                                features = self.extract_features_from_eve_event(event)
                                if features:
                                    logger.debug(f"Extracted {len([f for f in features.values() if f != 0.0])} features from {event.get('event_type')} event")
                                
                    except json.JSONDecodeError:
                        continue
                
                # Save stats periodically
                if events_processed > 0 and self.stats['total_events'] % 100 == 0:
                    self.save_detection_stats()
                    logger.info(f"Processed {self.stats['total_events']} events, {self.stats['predictions_made']} predictions made, {self.stats['malicious_detected']} malicious detected")
                
                # Brief pause to avoid excessive CPU usage
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(5)

def main():
    """Main function with integration support"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Real-time ML detection from Suricata eve.json')
    parser.add_argument('--model-path', default='/models/detection_model.pkl', help='Path to .pkl model file')
    parser.add_argument('--eve-path', default='/captures/eve.json', help='Path to eve.json file')
    parser.add_argument('--output-dir', default='/analysis', help='Output directory for detections')
    parser.add_argument('--test-features', action='store_true', help='Test feature extraction without model')
    
    args = parser.parse_args()
    
    detector = RealtimeMLDetector(
        model_path=args.model_path,
        eve_path=args.eve_path,
        output_dir=args.output_dir
    )
    
    if args.test_features:
        logger.info("Testing feature extraction...")
        # Test with sample event
        sample_event = {
            'event_type': 'flow',
            'proto': 'TCP',
            'flow': {'age': 10, 'pkts_toserver': 5, 'pkts_toclient': 3, 'bytes_toserver': 1024, 'bytes_toclient': 512}
        }
        features = detector.extract_features_from_eve_event(sample_event)
        if features:
            logger.info(f"Successfully extracted {len(features)} features")
            logger.info(f"Non-zero features: {sum(1 for v in features.values() if v != 0.0)}")
        return
    
    try:
        detector.monitor_eve_json()
    except KeyboardInterrupt:
        logger.info("Real-time detection stopped by user")
        detector.save_detection_stats()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
