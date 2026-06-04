
import os
import sys
import time
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, f1_score
import matplotlib.pyplot as plt
import seaborn as sns

# Add current directory to path so we can import project modules
sys.path.append(os.getcwd())

from ids_ips_trainer import IDSPredictor, engineer_features

def test_ml_layer_performance():
    print("=" * 60)
    print("      SUDOSOC IDS/IPS - ML LAYER FINAL VALIDATION")
    print("=" * 60)

    # 1. Load the Model
    model_dir = "ids_output"
    if not os.path.exists(os.path.join(model_dir, "ids_model.pkl")):
        print(f"[!] Error: Model not found in {model_dir}")
        return

    print(f"[+] Loading IDSPredictor from {model_dir}...")
    try:
        predictor = IDSPredictor(model_dir)
    except Exception as e:
        print(f"[!] Failed to load predictor: {e}")
        return

    # 2. Load Test Data
    test_data_path = os.path.join("data", "processed_KDDTest+.csv")
    if not os.path.exists(test_data_path):
        # Fallback to any processed file
        import glob
        files = glob.glob(os.path.join("data", "processed_*.csv"))
        if not files:
            print("[!] No test data found in data/")
            return
        test_data_path = files[0]

    print(f"[+] Loading test dataset: {test_data_path}...")
    df_test = pd.read_csv(test_data_path)
    
    # 2.5 Ensure required columns for engineer_features exist
    if 'src_ip' not in df_test.columns:
        df_test['src_ip'] = "192.168.1.100"
    if 'dst_ip' not in df_test.columns:
        df_test['dst_ip'] = "10.0.0.1"

    # Normalize labels if they are objects (some datasets use strings, some use ints)
    if 'label' not in df_test.columns:
        print("[!] Dataset missing 'label' column. Cannot calculate accuracy.")
        return

    # 3. Run Batch Prediction & Measure Performance
    print(f"[+] Running predictions on {len(df_test):,} flows...")
    
    start_time = time.time()
    # Predict batch
    df_results = predictor.predict_batch(df_test)
    end_time = time.time()
    
    total_time = end_time - start_time
    avg_latency = (total_time / len(df_test)) * 1000 # in ms

    # 4. Calculate Accuracy and Metrics
    # Normalize ground truth for comparison
    def normalize_label(l):
        l = str(l).upper().strip()
        if l in {"NORMAL", "BENIGN", "0"}: return "NORMAL"
        return "ATTACK" # Collapse all attacks to binary for a high-level accuracy check

    y_true = df_test['label'].apply(normalize_label)
    y_pred = df_results['prediction'].apply(normalize_label)

    acc = accuracy_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred, pos_label="ATTACK")
    
    print("\n" + "-" * 30)
    print("      PERFORMANCE RESULTS")
    print("-" * 30)
    print(f"Total Flows Tested:  {len(df_test):,}")
    print(f"Total Processing:    {total_time:.2f} seconds")
    print(f"Average Latency:     {avg_latency:.4f} ms/flow")
    print(f"Throughput:          {len(df_test)/total_time:.2f} flows/sec")

    print("\n" + "-" * 30)
    print("      ACCURACY RESULTS")
    print("-" * 30)
    print(f"Overall Accuracy:    {acc * 100:.2f}%")
    print(f"F1-Score (Attack):   {f1 * 100:.2f}%")
    
    print("\nClassification Report (Binary):")
    print(classification_report(y_true, y_pred))

    # Multi-class breakdown if available
    if predictor.mode == "supervised":
        le = predictor.meta["label_encoder"]
        print("\nDetailed Multi-class Report:")
        # We need to map y_test labels to what the model predicts
        # However, processed_KDDTest labels might be strings that match le.classes_
        y_true_multi = df_test['label'].apply(lambda x: str(x).upper())
        # Filter classes that exist in the label encoder
        valid_classes = set(le.classes_)
        mask = y_true_multi.isin(valid_classes)
        if mask.any():
            print(classification_report(y_true_multi[mask], df_results['prediction'][mask]))

    # 5. Conclusion
    if acc > 0.85:
        print(f"\n{chr(27)}[92m[PASS]{chr(27)}[0m ML Layer is working optimally.")
    else:
        print(f"\n{chr(27)}[91m[WARNING]{chr(27)}[0m Accuracy is lower than expected ({acc*100:.1f}%). Check model training.")

if __name__ == "__main__":
    test_ml_layer_performance()
