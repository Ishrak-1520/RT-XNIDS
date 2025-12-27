import time
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import os
import warnings
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from colorama import Fore, Style, init

# --- IGNORE WARNINGS ---
warnings.filterwarnings("ignore")

# --- Setup ---
init()

# --- Configuration ---
# Global default path
DEFAULT_DATASET_PATH = "datasets/CICIDS2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv" 
MODEL_PATH = "model.pkl"
SCALER_PATH = "scaler.pkl"

# The features we extract for the simulation
MODEL_FEATURES = ["Duration", "FwdPkts", "BwdPkts", "LenMean", "LenStd", "IAT"]

# Mapping for CIC-IDS2017
FEATURE_MAP = {
    "Flow Duration": "Duration",
    "Total Fwd Packets": "FwdPkts",
    "Total Backward Packets": "BwdPkts",
    "Fwd Packet Length Mean": "LenMean",
    "Fwd Packet Length Std": "LenStd",
    "Flow IAT Mean": "IAT",
    "Label": "Label"
}

def load_artifacts():
    print(f"{Fore.CYAN}[INFO] Loading Model and Scaler...{Style.RESET_ALL}")
    if not os.path.exists(SCALER_PATH) or not os.path.exists(MODEL_PATH):
        print(f"{Fore.RED}[ERROR] 'model.pkl' or 'scaler.pkl' missing.{Style.RESET_ALL}")
        print("   Run 'train_model.py' first.")
        exit(1)
        
    scaler = joblib.load(SCALER_PATH)
    model = joblib.load(MODEL_PATH)
    return model, scaler

def main():
    print(f"\n{Fore.CYAN}=== NIDS Evaluation System ==={Style.RESET_ALL}")
    
    # 1. Load Artifacts
    model, scaler = load_artifacts()
    
    # Check expected features
    EXPECTED_FEATURES = model.n_features_in_ if hasattr(model, "n_features_in_") else 78
    print(f"[INFO] Model expects {EXPECTED_FEATURES} input features.")

    # 2. Load Data (Fixing the Scope Error)
    # We use a new local variable 'target_path' to avoid UnboundLocalError
    target_path = DEFAULT_DATASET_PATH

    if not os.path.exists(target_path):
        # Try finding it in the local folder as a fallback
        if os.path.exists("training_data.csv"):
             target_path = "training_data.csv"
        else:
            print(f"{Fore.RED}[ERROR] Dataset not found at: {target_path}{Style.RESET_ALL}")
            print(f"   (Also checked 'training_data.csv' and found nothing)")
            return

    print(f"[INFO] Loading dataset from: {target_path}...")
    
    # Load a sample (e.g., 10,000 rows) to keep evaluation fast. Remove 'nrows' to evaluate all.
    try:
        df = pd.read_csv(target_path, nrows=10000) 
        df.columns = df.columns.str.strip()
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to read CSV: {e}{Style.RESET_ALL}")
        return
    
    # 3. Prepare Data (Padding Logic)
    print(f"[INFO] Preprocessing {len(df)} flows...")
    
    X_padded = np.zeros((len(df), EXPECTED_FEATURES))
    y_true_binary = []
    
    # Extract the 6 known features and map labels
    label_col = next((k for k, v in FEATURE_MAP.items() if v == "Label"), None)
    
    # Map data to vectors
    for i, row in df.iterrows():
        # 0: Duration, 1: FwdPkts, 2: BwdPkts, 3: LenMean, 4: LenStd, 5: IAT
        for feature_idx, feat_name in enumerate(MODEL_FEATURES):
            csv_col = next((k for k, v in FEATURE_MAP.items() if v == feat_name), None)
            if csv_col and csv_col in row:
                try: val = float(row[csv_col])
                except: val = 0.0
                X_padded[i, feature_idx] = val
        
        # Label Processing
        label = str(row[label_col]) if label_col in row else "UNKNOWN"
        # 1 = Malicious, 0 = Benign
        is_malicious = 1 if label.upper() not in ["BENIGN", "NORMAL", "0", "UNKNOWN"] else 0
        y_true_binary.append(is_malicious)

    # 4. Inference
    print(f"[INFO] Running Inference on {len(df)} samples...")
    X_scaled = scaler.transform(X_padded)
    
    start_time = time.time()
    y_pred = model.predict(X_scaled)
    end_time = time.time()
    
    # Convert predictions to binary (0/1) if they aren't already
    y_pred_binary = []
    for pred in y_pred:
        p_str = str(pred).upper()
        if p_str in ["BENIGN", "NORMAL", "0"]:
            y_pred_binary.append(0)
        else:
            y_pred_binary.append(1)

    # 5. Metrics
    total_latency_ms = (end_time - start_time) * 1000
    avg_latency_ms = total_latency_ms / len(df)
    
    print(f"\n{Fore.GREEN}--- Performance Metrics ---{Style.RESET_ALL}")
    print(f"Overall Accuracy:  {accuracy_score(y_true_binary, y_pred_binary)*100:.2f}%")
    print(f"Precision:         {precision_score(y_true_binary, y_pred_binary, zero_division=0):.4f}")
    print(f"Recall:            {recall_score(y_true_binary, y_pred_binary, zero_division=0):.4f}")
    print(f"F1-Score:          {f1_score(y_true_binary, y_pred_binary, zero_division=0):.4f}")
    print(f"Avg Latency:       {avg_latency_ms:.4f} ms per flow")

    # 6. Confusion Matrix Plot
    print(f"\n[INFO] Generating Confusion Matrix...")
    cm = confusion_matrix(y_true_binary, y_pred_binary)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Benign', 'Malicious'], 
                yticklabels=['Benign', 'Malicious'])
    plt.title('NIDS Detection Performance')
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig('confusion_matrix.png')
    print(f"[SUCCESS] Saved chart to 'confusion_matrix.png'")
    
    print(f"\n{Fore.GREEN}Evaluation Complete!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()