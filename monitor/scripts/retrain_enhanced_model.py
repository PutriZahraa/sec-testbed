#!/usr/bin/env python3
"""
ML Model Retraining Script
Addresses current model weaknesses with improved feature engineering
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import pickle
import re
from urllib.parse import unquote

def enhanced_feature_extraction(df):
    """Extract enhanced features for better XSS detection"""
    
    print("🔧 Extracting enhanced features...")
    
    # Decode URLs for better analysis
    df['decoded_url'] = df['http_url'].apply(lambda x: unquote(x) if pd.notnull(x) else '')
    
    # Original features (keep existing)
    features = {
        'src_port': df['src_port'],
        'dest_port': df['dest_port'], 
        'http_status': df['http_status'],
        'http_resp_len': df['http_resp_len'],
        'http_url_len': df['http_url_len'],
        'url_contains_script_tag': df['url_contains_script_tag'],
        'url_contains_onerror': df['url_contains_onerror'],
        'http_method_POST': (df['http_method'] == 'POST').astype(int)
    }
    
    # Enhanced XSS-specific features
    print("   Adding XSS-specific features...")
    
    # JavaScript execution patterns
    features['contains_javascript_protocol'] = df['decoded_url'].str.contains(r'javascript:', case=False, na=False).astype(int)
    features['contains_alert'] = df['decoded_url'].str.contains(r'alert\s*\(', case=False, na=False).astype(int)
    features['contains_eval'] = df['decoded_url'].str.contains(r'eval\s*\(', case=False, na=False).astype(int)
    features['contains_document_write'] = df['decoded_url'].str.contains(r'document\.write', case=False, na=False).astype(int)
    
    # Event handler patterns (high XSS indicators)
    event_handlers = ['onclick', 'onload', 'onmouseover', 'onfocus', 'onkeyup', 'onchange', 'onsubmit']
    for handler in event_handlers:
        features[f'contains_{handler}'] = df['decoded_url'].str.contains(f'{handler}\\s*=', case=False, na=False).astype(int)
    
    # HTML tag patterns
    features['contains_iframe'] = df['decoded_url'].str.contains(r'<iframe', case=False, na=False).astype(int)
    features['contains_svg'] = df['decoded_url'].str.contains(r'<svg', case=False, na=False).astype(int)
    features['contains_img_onerror'] = df['decoded_url'].str.contains(r'<img[^>]*onerror', case=False, na=False).astype(int)
    features['contains_audio_onerror'] = df['decoded_url'].str.contains(r'<audio[^>]*onerror', case=False, na=False).astype(int)
    features['contains_video_onerror'] = df['decoded_url'].str.contains(r'<video[^>]*onerror', case=False, na=False).astype(int)
    
    # Encoding detection (evasion techniques)
    features['url_encoded_chars'] = df['decoded_url'].str.count(r'%[0-9A-Fa-f]{2}')
    features['html_encoded_chars'] = df['decoded_url'].str.count(r'&\w+;')
    features['has_suspicious_encoding'] = (features['url_encoded_chars'] > 5).astype(int)
    
    # Character analysis
    features['special_char_ratio'] = df['decoded_url'].apply(
        lambda x: len(re.findall(r'[<>()=\'";&]', str(x))) / max(len(str(x)), 1)
    )
    
    # XSS payload complexity
    features['script_tag_count'] = df['decoded_url'].str.count(r'<script', case=False)
    features['has_nested_tags'] = df['decoded_url'].str.contains(r'<\w+[^>]*>[^<]*<\w+', case=False, na=False).astype(int)
    
    return pd.DataFrame(features)

def train_enhanced_model(dataset_path):
    """Train enhanced ML model with better features"""
    
    print("🚀 Training Enhanced XSS Detection Model")
    print("=" * 50)
    
    # Load dataset
    print(f"📁 Loading dataset: {dataset_path}")
    df = pd.read_csv(dataset_path)
    
    print(f"   Total samples: {len(df)}")
    print(f"   Attack samples: {df['label'].sum()}")
    print(f"   Benign samples: {len(df) - df['label'].sum()}")
    print(f"   Attack ratio: {df['label'].mean()*100:.1f}%")
    print()
    
    # Extract enhanced features
    X = enhanced_feature_extraction(df)
    y = df['label']
    
    print(f"🎯 Feature engineering complete:")
    print(f"   Original features: 8")
    print(f"   Enhanced features: {len(X.columns)}")
    print(f"   New XSS-specific features: {len(X.columns) - 8}")
    print()
    
    # Handle missing values
    X = X.fillna(0)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Train model with optimized parameters
    print("🤖 Training Random Forest with optimized parameters...")
    
    model = RandomForestClassifier(
        n_estimators=200,  # Increased from 100
        max_depth=15,      # Prevent overfitting
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',
        random_state=42,
        class_weight='balanced'  # Handle class imbalance
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate model
    print("📊 Model evaluation:")
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    
    print(f"   Training accuracy: {train_score:.3f}")
    print(f"   Test accuracy: {test_score:.3f}")
    
    # Cross-validation
    cv_scores = cross_val_score(model, X_train, y_train, cv=5)
    print(f"   CV mean accuracy: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
    print()
    
    # Feature importance
    print("🔍 Top 10 Feature Importances:")
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for i, (_, row) in enumerate(feature_importance.head(10).iterrows()):
        print(f"   {i+1:2d}. {row['feature']:<25} {row['importance']:.4f}")
    print()
    
    # Detailed classification report
    y_pred = model.predict(X_test)
    print("📈 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Attack']))
    print()
    
    # Save enhanced model
    model_data = {
        'model': model,
        'feature_names': list(X.columns),
        'training_info': {
            'total_samples': len(df),
            'attack_samples': df['label'].sum(),
            'test_accuracy': test_score,
            'cv_accuracy': cv_scores.mean(),
            'feature_count': len(X.columns)
        }
    }
    
    output_path = '/scripts/models/enhanced_detection_model.pkl'
    with open(output_path, 'wb') as f:
        pickle.dump(model_data, f)
    
    print(f"✅ Enhanced model saved: {output_path}")
    print(f"🎯 Key improvements:")
    print(f"   • {len(X.columns)} features (vs 8 original)")
    print(f"   • Balanced class weights")
    print(f"   • Enhanced XSS pattern detection")
    print(f"   • Better encoding evasion detection")
    
    return model, X.columns, test_score

def main():
    # Find the most recent dataset
    import glob
    dataset_files = glob.glob('/home/ubuntu/sec-testbed/data/labeled_datasets/final_xss_dataset_*.csv')
    
    if not dataset_files:
        print("❌ No dataset files found!")
        return
    
    latest_dataset = max(dataset_files)
    print(f"Using latest dataset: {latest_dataset}")
    print()
    
    train_enhanced_model(latest_dataset)

if __name__ == "__main__":
    main()
