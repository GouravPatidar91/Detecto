import os
import sys
import json
import time
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# Add parent directory to sys.path so we can import backend.feature_extractor
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
sys.path.insert(0, PARENT_DIR)

from backend.feature_extractor import extract_url_features

def train_and_evaluate(dataset_csv: str, model_save_path: str, features_save_path: str):
    print("=" * 60)
    print("      DETECTO - AI MALICIOUS URL DETECTOR (TRAINING)")
    print("=" * 60)
    
    start_time = time.time()
    print(f"[1/5] Loading dataset from {dataset_csv}...")
    df = pd.read_csv(dataset_csv)
    print(f"      Total records: {len(df)} (Benign: {(df['label'] == 0).sum()}, Malicious: {(df['label'] == 1).sum()})")
    
    print("[2/5] Extracting URL features using Detecto Feature Extractor...")
    feature_list = []
    labels = df["label"].values
    
    for idx, url in enumerate(df["url"]):
        feats = extract_url_features(url)
        feature_list.append(feats)
        if (idx + 1) % 5000 == 0 or (idx + 1) == len(df):
            print(f"      Processed {idx + 1}/{len(df)} URLs...")
            
    X_df = pd.DataFrame(feature_list)
    feature_names = list(X_df.columns)
    X = X_df.values
    y = labels
    
    print(f"[3/5] Splitting data (80% Train, 20% Test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print("[4/5] Training Random Forest Classifier with 100 estimators...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    
    print("[5/5] Evaluating Model Performance...")
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    
    print("\n" + "=" * 45)
    print("           MODEL EVALUATION RESULTS")
    print("=" * 45)
    print(f"  Accuracy:  {acc * 100:.2f}%")
    print(f"  Precision: {prec * 100:.2f}%")
    print(f"  Recall:    {rec * 100:.2f}%")
    print(f"  F1-Score:  {f1 * 100:.2f}%")
    print(f"  ROC-AUC:   {auc:.4f}")
    print("=" * 45)
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))
    
    # Feature importances
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("Top 10 Most Influential Features:")
    for rank, i in enumerate(sorted_idx[:10], 1):
        print(f"  {rank:2d}. {feature_names[i]:<28} {importances[i]*100:.2f}%")
        
    # Save model and metadata
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    joblib.dump(clf, model_save_path)
    print(f"\n[OK] Model serialized and saved to: {model_save_path}")
    
    with open(features_save_path, "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)
    print(f"[OK] Feature names saved to: {features_save_path}")
    
    elapsed = time.time() - start_time
    print(f"Training completed successfully in {elapsed:.1f} seconds.")

if __name__ == "__main__":
    dataset_path = os.path.join(CURRENT_DIR, "..", "data", "urls_dataset.csv")
    model_path = os.path.join(CURRENT_DIR, "saved_models", "url_classifier.joblib")
    features_path = os.path.join(CURRENT_DIR, "saved_models", "feature_names.json")
    
    train_and_evaluate(dataset_path, model_path, features_path)
