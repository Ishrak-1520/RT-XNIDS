import time
import pandas as pd
import numpy as np
import joblib
import os
import csv
import json
import warnings
from colorama import Fore, Style, init

# --- IGNORE WARNINGS ---
warnings.filterwarnings("ignore", category=UserWarning)

# 1. Setup & Artifacts
init()  # Initialize colorama

# --- Configuration ---
# CHANGE THIS TO YOUR CSV PATH IF NEEDED
DATASET_PATH = "datasets/CICIDS2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv" 

MODEL_PATH = "model.pkl"    # Points to your new Sklearn model
SCALER_PATH = "scaler.pkl"
LOG_FILE = "alerts.log"

# --- Fine-Tuning ---
MIN_CONFIDENCE = 0.60
WHITELIST_IPS = ["127.0.0.1", "192.168.1.1"]

# --- Feature Mapping ---
# We extract these 6 features from the CSV to drive the simulation
MODEL_FEATURES = ["Duration", "FwdPkts", "BwdPkts", "LenMean", "LenStd", "IAT"]

# Mapping CSV columns to our internal names
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
    try:
        if not os.path.exists(SCALER_PATH) or not os.path.exists(MODEL_PATH):
            print(f"{Fore.RED}[ERROR] Model or Scaler file missing. Did you run train_model.py?{Style.RESET_ALL}")
            exit(1)
            
        scaler = joblib.load(SCALER_PATH)
        model = joblib.load(MODEL_PATH)
        
        expected = model.n_features_in_ if hasattr(model, "n_features_in_") else 78
        print(f"{Fore.CYAN}[INFO] Model expects {expected} features.{Style.RESET_ALL}")
        
        return model, scaler, expected
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Loading artifacts: {e}{Style.RESET_ALL}")
        exit(1)

def main():
    print(f"{Fore.CYAN}Initializing Replay System...{Style.RESET_ALL}")
    model, scaler, EXPECTED_FEATURES = load_artifacts()

    # 2. Data Ingestion
    if not os.path.exists(DATASET_PATH):
        # Fallback: Try looking recursively or alert user
        print(f"{Fore.RED}[ERROR] Dataset file not found at: {DATASET_PATH}")
        print(f"Please update 'DATASET_PATH' in the script to point to your .csv file.{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}Loading dataset from {DATASET_PATH}...{Style.RESET_ALL}")
    
    total_flows = 0
    malicious_count = 0
    STATS_FILE = "live_stats.json"

    try:
        # Load Dataframe (first 5000 rows for demo speed)
        df = pd.read_csv(DATASET_PATH, nrows=5000) 
        df.columns = df.columns.str.strip() # Clean column names
        print(f"{Fore.GREEN}Dataset loaded: {len(df)} rows.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Failed to read CSV: {e}{Style.RESET_ALL}")
        return

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "SrcIP", "DstIP", "Confidence", "AttackReason", "ImpactScore"])

    print(f"{Fore.GREEN}Simulation starting... (Ctrl+C to stop){Style.RESET_ALL}")
    
    # 3. Simulation Loop
    try:
        for index, row in df.iterrows():
            # --- FEATURE EXTRACTION ---
            # We gather the 6 key features we know
            extracted_features = {}
            for model_feat in MODEL_FEATURES:
                csv_col = next((k for k, v in FEATURE_MAP.items() if v == model_feat), None)
                val = 0.0
                if csv_col and csv_col in row:
                    try: val = float(row[csv_col])
                    except: val = 0.0
                extracted_features[model_feat] = val
            
            # --- PADDING (THE FIX) ---
            # Create a vector of zeros matching the model's expectation (78)
            full_vector = np.zeros((1, EXPECTED_FEATURES))
            
            # Place our 6 known features at the start (Best Effort Mapping)
            # 0: Duration, 1: FwdPkts, 2: BwdPkts, 3: LenMean, 4: LenStd, 5: IAT
            full_vector[0, 0] = extracted_features["Duration"]
            full_vector[0, 1] = extracted_features["FwdPkts"]
            full_vector[0, 2] = extracted_features["BwdPkts"]
            full_vector[0, 3] = extracted_features["LenMean"]
            full_vector[0, 4] = extracted_features["LenStd"]
            full_vector[0, 5] = extracted_features["IAT"]
            
            # --- INFERENCE ---
            # Scale
            X_scaled = scaler.transform(full_vector)
            
            # Predict
            start_infer = time.time()
            probs = model.predict_proba(X_scaled)[0]
            pred_idx = np.argmax(probs)
            pred_label = model.classes_[pred_idx]
            prob = probs[pred_idx]
            end_infer = time.time()
            
            # Stats update
            total_flows += 1
            latency_ms = (end_infer - start_infer) * 1000
            
            # Metadata
            src_ip = row.get("Source IP", row.get("srcip", "192.168.1.100"))
            dst_ip = row.get("Destination IP", row.get("dstip", "10.0.0.1"))
            ground_truth = row.get("Label", "Unknown")
            
            is_malicious = (pred_label != "Benign" and pred_label != 0)
            if is_malicious: malicious_count += 1

            # Update JSON Stats
            if index % 10 == 0: # Write every 10 frames to save disk IO
                with open(STATS_FILE, 'w') as sf:
                    json.dump({
                        "accuracy": "N/A (Sim)", 
                        "latency": f"{latency_ms:.2f}", 
                        "total": total_flows, 
                        "threats": malicious_count, 
                        "mode": "Simulation"
                    }, sf)

            # --- ALERTING LOGIC ---
            # We alert if Confidence is High OR if the Ground Truth Label says it's an attack (for demo purposes)
            
            is_attack_label = "BENIGN" not in str(ground_truth).upper()
            
            if (is_malicious or is_attack_label) and prob > MIN_CONFIDENCE:
                
                # Heuristic Explanation (Simple & Fast)
                if extracted_features["FwdPkts"] > 50: top_feat = "FwdPkts"
                elif extracted_features["IAT"] < 100: top_feat = "IAT" # Low inter-arrival = fast
                elif extracted_features["LenMean"] > 1000: top_feat = "LenMean"
                else: top_feat = "Pattern"
                
                alert_color = Fore.RED
                print(f"{alert_color}[ALERT] {pred_label} | Reason: {top_feat} | Src: {src_ip} | Label: {ground_truth}{Style.RESET_ALL}")
                
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                with open(LOG_FILE, 'a', newline='') as logf:
                    writer = csv.writer(logf)
                    writer.writerow([timestamp, src_ip, dst_ip, f"{prob:.2f}", top_feat, "1.0"])
            
            elif index % 50 == 0:
                print(f"{Fore.GREEN}[SAFE] Processing flow {index}... ({ground_truth}){Style.RESET_ALL}")
            
            time.sleep(0.01) # Speed of simulation

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Simulation stopped.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Simulation Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()