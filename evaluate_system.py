import time
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import shap
import os
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from colorama import Fore, Style, init

# --- Setup ---
init()

# --- Configuration ---
DATASET_PATH = "datasets/CICIDS2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv" # Update as needed
MODEL_PATH = "nids_model.pth"
SCALER_PATH = "scaler.pkl"

MODEL_FEATURES = ["Duration", "FwdPkts", "BwdPkts", "LenMean", "LenStd", "IAT"]

# === OPTION 1: CICIDS2017 / CSE-CIC-IDS2018 (Default) ===
FEATURE_MAP = {
    "Flow Duration": "Duration",
    "Total Fwd Packets": "FwdPkts",
    "Total Backward Packets": "BwdPkts",
    "Fwd Packet Length Mean": "LenMean",
    "Fwd Packet Length Std": "LenStd",
    "Flow IAT Mean": "IAT",
    "Label": "Label"
}

# === OPTION 2: UNSW-NB15 ===
# FEATURE_MAP = {
#     "dur": "Duration",
#     "spkts": "FwdPkts",
#     "dpkts": "BwdPkts",
#     "smean": "LenMean",      
#     "sinpkt": "IAT",         
#     "label": "Label"
# }

# === OPTION 3: NSL-KDD ===
# FEATURE_MAP = {
#     "duration": "Duration",
#     "count": "FwdPkts",      
#     "srv_count": "BwdPkts",  
#     "src_bytes": "LenMean",  
#     "class": "Label"
# }

# --- Model Definition ---
class NIDSModel(nn.Module):
    def __init__(self, input_dim):
        super(NIDSModel, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )
        
    def forward(self, x):
        return self.network(x)

def load_artifacts():
    if not os.path.exists(SCALER_PATH) or not os.path.exists(MODEL_PATH):
        print(f"{Fore.RED}❌ Error: Model or Scaler file missing.{Style.RESET_ALL}")
        exit(1)
        
    scaler = joblib.load(SCALER_PATH)
    model = NIDSModel(input_dim=len(MODEL_FEATURES))
    model.load_state_dict(torch.load(MODEL_PATH, map_location=torch.device('cpu')))
    model.eval()
    return model, scaler

def main():
    print(f"\n{Fore.CYAN}=== NIDS Evaluation System ==={Style.RESET_ALL}")
    
    # 1. Load Data
    if not os.path.exists(DATASET_PATH):
        print(f"{Fore.RED}❌ Dataset not found at {DATASET_PATH}{Style.RESET_ALL}")
        return

    print(f"Loading dataset: {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    df.columns = df.columns.str.strip()
    
    # 2. Extract Features and Labels
    X_raw = []
    y_true_labels = []
    
    label_col = next((k for k, v in FEATURE_MAP.items() if v == "Label"), None)
    
    for _, row in df.iterrows():
        # Feature Extraction
        features = []
        for model_feat in MODEL_FEATURES:
            csv_col = next((k for k, v in FEATURE_MAP.items() if v == model_feat), None)
            val = 0.0
            if csv_col and csv_col in row:
                try:
                    val = float(row[csv_col])
                except:
                    val = 0.0
            features.append(val)
        X_raw.append(features)
        
        # Label Extraction
        if label_col and label_col in row:
            y_true_labels.append(str(row[label_col]).strip())
        else:
            y_true_labels.append("UNKNOWN")

    X_raw = np.array(X_raw)
    y_true_binary = [1 if label.upper() not in ["BENIGN", "NORMAL", "0", "UNKNOWN"] else 0 for label in y_true_labels]

    # 3. Model Inference & Latency
    model, scaler = load_artifacts()
    X_scaled = scaler.transform(X_raw)
    X_tensor = torch.FloatTensor(X_scaled)
    
    print(f"Processing {len(X_tensor)} flows for inference...")
    
    start_time = time.time()
    with torch.no_grad():
        outputs = model(X_tensor)
        y_probs = outputs.squeeze().numpy()
    end_time = time.time()
    
    total_latency_ms = (end_time - start_time) * 1000
    avg_latency_ms = total_latency_ms / len(X_tensor)
    
    y_pred_binary = (y_probs > 0.5).astype(int)

    # 4. Accuracy & Metrics
    print(f"\n{Fore.GREEN}--- Performance Metrics ---{Style.RESET_ALL}")
    print(f"Overall Accuracy: {accuracy_score(y_true_binary, y_pred_binary):.4f}")
    print(f"Precision: {precision_score(y_true_binary, y_pred_binary, zero_division=0):.4f}")
    print(f"Recall (Overall): {recall_score(y_true_binary, y_pred_binary, zero_division=0):.4f}")
    print(f"F1-Score: {f1_score(y_true_binary, y_pred_binary, zero_division=0):.4f}")
    print(f"Average Latency per Flow: {avg_latency_ms:.4f} ms")

    # 5. Classification Report (per attack class)
    print(f"\n{Fore.YELLOW}--- Detailed Classification Report ---{Style.RESET_ALL}")
    # We use y_true_labels for granular reporting
    # Map predictions back to 'Malicious' or 'Benign' for report clarity if labels aren't balanced
    report = classification_report(y_true_binary, y_pred_binary, target_names=["Benign", "Malicious"], zero_division=0)
    print(report)

    # Specific Recall for Malicious Classes (Anomaly Performance)
    malicious_indices = [i for i, val in enumerate(y_true_binary) if val == 1]
    if malicious_indices:
        malicious_recall = recall_score(np.array(y_true_binary)[malicious_indices], np.array(y_pred_binary)[malicious_indices], zero_division=0)
        print(f"{Fore.MAGENTA}Zero-Day / Anomaly Recall: {malicious_recall:.4f}{Style.RESET_ALL}")
    else:
        print(f"{Fore.MAGENTA}No malicious flows found in dataset sample.{Style.RESET_ALL}")

    # 6. Confusion Matrix
    cm = confusion_matrix(y_true_binary, y_pred_binary)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign', 'Malicious'], yticklabels=['Benign', 'Malicious'])
    plt.title('NIDS Confusion Matrix')
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    plt.savefig('confusion_matrix.png')
    print(f"\n✅ Confusion Matrix saved as 'confusion_matrix.png'")

    # 7. SHAP Explanations (Explanation Clarity)
    print(f"\n{Fore.CYAN}Generating SHAP explanations for 100 samples...{Style.RESET_ALL}")
    sample_size = min(100, len(X_tensor))
    X_sample = X_tensor[:sample_size]
    
    # Background data for SHAP (using a small zero-tensor as reference)
    background = torch.zeros((1, len(MODEL_FEATURES)))
    explainer = shap.DeepExplainer(model, background)
    shap_values = explainer.shap_values(X_sample)
    
    # Handle SHAP output format
    if isinstance(shap_values, list):
        shap_values_plot = shap_values[0]
    else:
        shap_values_plot = shap_values

    plt.figure(figsize=(10, 6))
    shap.summary_plot(shap_values_plot, X_sample.numpy(), feature_names=MODEL_FEATURES, show=False)
    plt.tight_layout()
    plt.savefig('shap_summary.png')
    print(f"✅ SHAP Summary Plot saved as 'shap_summary.png'")

    print(f"\n{Fore.GREEN}Evaluation Complete!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
