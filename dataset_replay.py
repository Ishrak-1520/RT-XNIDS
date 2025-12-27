import time
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib
import shap
import os
import csv
from colorama import Fore, Style, init

# 1. Setup & Artifacts
init()  # Initialize colorama

# --- Configuration ---
# CHANGE THIS PATH TO YOUR DATASET FILE
DATASET_PATH = "datasets\CICIDS2017\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv" 

MODEL_PATH = "nids_model.pth"
SCALER_PATH = "scaler.pkl"
LOG_FILE = "alerts.log"

# --- Feature Mapping ---
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
    try:
        if not os.path.exists(SCALER_PATH) or not os.path.exists(MODEL_PATH):
            print(f"{Fore.RED}❌ Error: Model or Scaler file missing.{Style.RESET_ALL}")
            exit(1)
            
        scaler = joblib.load(SCALER_PATH)
        model = NIDSModel(input_dim=len(MODEL_FEATURES))
        model.load_state_dict(torch.load(MODEL_PATH, map_location=torch.device('cpu')))
        model.eval()
        
        # Initialize SHAP
        background_data = torch.zeros((10, 6))
        explainer = shap.DeepExplainer(model, background_data)
        return model, scaler, explainer
    except Exception as e:
        print(f"{Fore.RED}❌ Error loading artifacts: {e}{Style.RESET_ALL}")
        exit(1)

def main():
    print(f"{Fore.CYAN}Initializing Replay System...{Style.RESET_ALL}")
    model, scaler, explainer = load_artifacts()

    # 2. Data Ingestion
    if not os.path.exists(DATASET_PATH):
        print(f"{Fore.RED}❌ Dataset file not found at: {DATASET_PATH}{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}Loading dataset from {DATASET_PATH}...{Style.RESET_ALL}")
    try:
        # Load Dataframe
        df = pd.read_csv(DATASET_PATH, nrows=None) 
        
        # --- FIX 1: Clean Column Names (Remove Spaces) ---
        df.columns = df.columns.str.strip()
        print(f"{Fore.GREEN}✅ Dataset loaded: {len(df)} rows. Columns cleaned.{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to read CSV: {e}{Style.RESET_ALL}")
        return

    # Ensure log file exists
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "SrcIP", "DstIP", "Confidence", "AttackReason", "ImpactScore"])

    print(f"{Fore.GREEN}✅ Simulation starting... (Ctrl+C to stop){Style.RESET_ALL}")
    
    # 3. Simulation Loop
    try:
        for index, row in df.iterrows():
            feature_vector = []
            
            # Map features
            for model_feat in MODEL_FEATURES:
                csv_col = next((k for k, v in FEATURE_MAP.items() if v == model_feat), None)
                val = 0.0
                if csv_col and csv_col in row:
                    try:
                        val = float(row[csv_col])
                    except:
                        val = 0.0
                feature_vector.append(val)
            
            # Metadata retrieval
            src_ip = row.get("Source IP", row.get("srcip", "0.0.0.0"))
            dst_ip = row.get("Destination IP", row.get("dstip", "0.0.0.0"))
            
            # Ground Truth Label
            label_col = next((k for k, v in FEATURE_MAP.items() if v == "Label"), None)
            ground_truth = str(row[label_col]) if label_col and label_col in row else "UNKNOWN"
            
            # Inference
            X = np.array(feature_vector).reshape(1, -1)
            X_scaled = scaler.transform(X)
            X_tensor = torch.FloatTensor(X_scaled)

            with torch.no_grad():
                output = model(X_tensor)
                prob = output.item()

            # Logic
            is_malicious_pred = prob > 0.5
            is_malicious_label = ground_truth.upper() not in ["BENIGN", "NORMAL", "0", "UNKNOWN"]

            if is_malicious_pred or is_malicious_label:
                shap_values = explainer.shap_values(X_tensor)
                vals = shap_values[0][0] if isinstance(shap_values, list) else shap_values[0]
                max_idx = np.argmax(np.abs(vals))
                top_feature = MODEL_FEATURES[max_idx]
                
                # --- FIX 2: Safe Float Conversion ---
                impact_val = vals[max_idx].item()

                # Log & Print
                alert_color = Fore.RED if is_malicious_pred else Fore.YELLOW
                print(f"{alert_color}🚨 ALERT [{ground_truth}] | Conf: {prob:.2f} | Reason: {top_feature} ({impact_val:.2f}) | Src: {src_ip}{Style.RESET_ALL}")
                
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                with open(LOG_FILE, 'a', newline='') as logf:
                    writer = csv.writer(logf)
                    writer.writerow([timestamp, src_ip, dst_ip, f"{prob:.2f}", top_feature, f"{impact_val:.2f}"])
            
            time.sleep(0.05)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Simulation stopped.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Simulation Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()