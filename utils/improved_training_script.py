#!/usr/bin/env python3
"""
Improved ML Training Script
Based on your original script but with better feature engineering and XSS focus
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import re
from urllib.parse import unquote

def add_enhanced_xss_features(df):
    """Add XSS-specific features to improve detection"""
    print("🔧 Adding enhanced XSS features...")
    
    # Decode URLs for better pattern matching
    df['decoded_url'] = df['http_url'].apply(lambda x: unquote(str(x)) if pd.notnull(x) else '')
    
    # JavaScript-related features
    df['contains_javascript'] = df['decoded_url'].str.contains(r'javascript:', case=False, na=False).astype(int)
    df['contains_alert'] = df['decoded_url'].str.contains(r'alert\s*\(', case=False, na=False).astype(int)
    df['contains_eval'] = df['decoded_url'].str.contains(r'eval\s*\(', case=False, na=False).astype(int)
    df['contains_document_write'] = df['decoded_url'].str.contains(r'document\.write', case=False, na=False).astype(int)
    
    # Event handlers (high XSS indicators)
    event_handlers = ['onclick', 'onload', 'onmouseover', 'onfocus', 'onkeyup', 'onchange']
    for handler in event_handlers:
        df[f'contains_{handler}'] = df['decoded_url'].str.contains(f'{handler}\\s*=', case=False, na=False).astype(int)
    
    # HTML tags that commonly carry XSS
    df['contains_iframe'] = df['decoded_url'].str.contains(r'<iframe', case=False, na=False).astype(int)
    df['contains_svg'] = df['decoded_url'].str.contains(r'<svg', case=False, na=False).astype(int)
    df['contains_img_onerror'] = df['decoded_url'].str.contains(r'<img[^>]*onerror', case=False, na=False).astype(int)
    df['contains_object'] = df['decoded_url'].str.contains(r'<object', case=False, na=False).astype(int)
    df['contains_embed'] = df['decoded_url'].str.contains(r'<embed', case=False, na=False).astype(int)
    
    # Encoding evasion detection
    df['url_encoded_count'] = df['decoded_url'].apply(lambda x: str(x).count('%'))
    df['has_suspicious_encoding'] = (df['url_encoded_count'] > 3).astype(int)
    
    # Character analysis
    df['special_char_ratio'] = df['decoded_url'].apply(
        lambda x: len(re.findall(r'[<>()=\'";&]', str(x))) / max(len(str(x)), 1)
    )
    
    # Script complexity
    df['script_tag_count'] = df['decoded_url'].str.count(r'<script', case=False)
    df['nested_tags'] = df['decoded_url'].str.contains(r'<\w+[^>]*>[^<]*<\w+', case=False, na=False).astype(int)
    
    print(f"   Added {len([col for col in df.columns if col.startswith('contains_') or col in ['url_encoded_count', 'has_suspicious_encoding', 'special_char_ratio', 'script_tag_count', 'nested_tags', 'contains_javascript', 'contains_alert', 'contains_eval', 'contains_document_write']])} new XSS features")
    
    return df

def train_improved_model(dataset_path):
    """Train improved ML model with better XSS detection"""
    
    print("🚀 IMPROVED XSS ML MODEL TRAINING")
    print("=" * 50)
    
    # --- 1: Load The Dataset ---
    df = pd.read_csv(dataset_path)
    print("--- Original Dataset Shape ---")
    print(df['label'].value_counts())
    print(f"Attack ratio: {df['label'].mean()*100:.1f}%")
    print()
    
    # --- 2: Add Enhanced XSS Features BEFORE dropping columns ---
    df = add_enhanced_xss_features(df)
    
    # --- 3: Data Preprocessing ---
    print("--- Preprocessing Data ---")
    # Keep XSS-relevant columns, drop metadata
    columns_to_drop = ['timestamp', 'src_ip', 'dest_ip', 'http_url', 'http_user_agent', 'decoded_url']
    df = df.drop([col for col in columns_to_drop if col in df.columns], axis=1)
    
    # One-hot encode categorical columns
    categorical_columns = ['proto', 'http_method']
    df = pd.get_dummies(df, columns=[col for col in categorical_columns if col in df.columns], drop_first=True)
    print(f"  > Preprocessing complete. Final features: {len(df.columns)-1}")
    print()
    
    # --- 4: Split to training & testing ---
    X = df.drop('label', axis=1)
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # --- 5: Train Improved Random Forest model ---
    print("--- Training Improved Model ---")
    rf_model = RandomForestClassifier(
        n_estimators=150,  # Increased from 100
        max_depth=20,      # Prevent overfitting but allow complexity
        min_samples_split=3,
        min_samples_leaf=1,
        random_state=42, 
        class_weight='balanced',  # Handle imbalance
        max_features='sqrt'       # Reduce overfitting
    )
    rf_model.fit(X_train, y_train)
    print("  > Model training complete.")
    print()
    
    # --- 6: Evaluate Model ---
    print("--- Evaluating Model ---")
    train_score = rf_model.score(X_train, y_train)
    test_score = rf_model.score(X_test, y_test)
    print(f"Training accuracy: {train_score:.3f}")
    print(f"Test accuracy: {test_score:.3f}")
    
    y_pred = rf_model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print()
    
    # --- 7: Feature Importance Analysis ---
    print("--- Feature Importance Analysis ---")
    feature_importances = pd.DataFrame({
        'feature': X_train.columns,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("Top 15 Most Important Features:")
    for i, (_, row) in enumerate(feature_importances.head(15).iterrows()):
        print(f"  {i+1:2d}. {row['feature']:<25} {row['importance']:.4f}")
    print()
    
    # Check XSS feature importance
    xss_features = [col for col in X_train.columns if 'contains_' in col or col in ['url_contains_script_tag', 'url_contains_onerror']]
    xss_importance = feature_importances[feature_importances['feature'].isin(xss_features)]['importance'].sum()
    print(f"🎯 XSS-specific features total importance: {xss_importance:.3f} ({xss_importance*100:.1f}%)")
    print()
    
    # --- 8: Save the Improved Model ---
    print("--- Saving Improved Model ---")
    model_data = {
        'model': rf_model,
        'feature_names': X_train.columns.tolist(),
        'training_info': {
            'total_samples': len(df),
            'attack_samples': df['label'].sum(),
            'test_accuracy': test_score,
            'xss_feature_importance': xss_importance,
            'feature_count': len(X_train.columns)
        }
    }
    
    # Save to your original filename format
    model_filename = 'detection_model.pkl'  # Same as your current model
    with open(model_filename, 'wb') as file:
        pickle.dump(model_data, file)
    print(f"  > Improved model saved as {model_filename}")
    print()
    
    # --- 9: Test with XSS examples ---
    print("--- Testing with XSS Examples ---")
    
    # Create test examples
    test_examples = [
        {  # Strong XSS example
            'src_port': 45678, 'dest_port': 80, 'http_status': 200, 'http_resp_len': 1500,
            'http_url_len': 45, 'url_contains_script_tag': 1, 'url_contains_onerror': 1,
            'contains_javascript': 1, 'contains_alert': 1, 'contains_iframe': 1,
            'special_char_ratio': 0.15, 'script_tag_count': 2
        },
        {  # Benign example
            'src_port': 45678, 'dest_port': 80, 'http_status': 200, 'http_resp_len': 1200,
            'http_url_len': 25, 'url_contains_script_tag': 0, 'url_contains_onerror': 0,
            'contains_javascript': 0, 'contains_alert': 0, 'contains_iframe': 0,
            'special_char_ratio': 0.02, 'script_tag_count': 0
        }
    ]
    
    for i, example in enumerate(test_examples):
        # Fill missing features with 0
        test_data = {col: example.get(col, 0) for col in X_train.columns}
        test_df = pd.DataFrame([test_data])
        
        prediction = rf_model.predict(test_df)[0]
        probability = rf_model.predict_proba(test_df)[0]
        
        example_type = "XSS" if i == 0 else "Benign"
        print(f"{example_type} Example:")
        print(f"  Prediction: {prediction} (0=benign, 1=attack)")
        print(f"  Probabilities: benign={probability[0]:.3f}, attack={probability[1]:.3f}")
        print()
    
    print("🎉 Improved model training complete!")
    return rf_model, X_train.columns, test_score

if __name__ == "__main__":
    # Use your existing dataset
    dataset_path = 'final_xss_dataset_20250729_230620_fixed.csv'
    
    try:
        train_improved_model(dataset_path)
    except FileNotFoundError:
        print(f"❌ Dataset file not found: {dataset_path}")
        print("Please ensure the dataset file is in the current directory")
