import time
import threading
import statistics
import numpy as np
import torch
import torch.nn as nn
import joblib
import shap
import pandas as pd
import csv
import os
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from colorama import Fore, Style, init

# Initialize Colorama
init()

# --- Configuration ---
LOG_FILE = "alerts.log"
MODEL_PATH = "nids_model.pth"
SCALER_PATH = "scaler.pkl"

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

# --- Global Artifacts ---
model = None
scaler = None
explainer = None
feature_names = ["Duration", "FwdPkts", "BwdPkts", "LenMean", "LenStd", "IAT"]

# Load artifacts
try:
    print("Loading Scaler...")
    scaler = joblib.load(SCALER_PATH)
    print("Loading Model...")
    model = NIDSModel(input_dim=6) 
    model.load_state_dict(torch.load(MODEL_PATH, map_location=torch.device('cpu')))
    model.eval()
    
    # Initialize SHAP
    print("Initializing SHAP Explainer...")
    background_data = torch.zeros((10, 6))
    explainer = shap.DeepExplainer(model, background_data)
    
    # Create Log File if missing
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "SrcIP", "DstIP", "Confidence", "AttackReason", "ImpactScore"])
    
    print("✅ System Ready. Waiting for packets...")
except Exception as e:
    print(f"❌ Error loading artifacts: {e}")
    exit(1)


class Flow:
    def __init__(self, start_packet):
        self.src_ip = start_packet[IP].src
        self.dst_ip = start_packet[IP].dst
        self.src_port = start_packet.sport
        self.dst_port = start_packet.dport
        self.protocol = start_packet.proto
        
        self.start_time = float(start_packet.time)
        self.last_time = float(start_packet.time)
        
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.flow_lengths = []
        self.flow_iats = []
        
        self.updated = False
        self.update(start_packet)

    def update(self, packet):
        curr_time = float(packet.time)
        
        if hasattr(self, 'flow_lengths') and len(self.flow_lengths) > 0:
            iat = curr_time - self.last_time
            if iat < 0: iat = 0.0 
            self.flow_iats.append(iat)

        if packet[IP].src == self.src_ip:
            self.fwd_pkts += 1
        else:
            self.bwd_pkts += 1
            
        self.flow_lengths.append(len(packet))
        self.last_time = curr_time
        self.updated = True

    def get_features(self):
        duration = self.last_time - self.start_time
        if duration < 0: duration = 0.0
        
        if len(self.flow_lengths) > 0:
            pkt_len_mean = statistics.mean(self.flow_lengths)
            pkt_len_std = statistics.stdev(self.flow_lengths) if len(self.flow_lengths) > 1 else 0.0
        else:
            pkt_len_mean = 0.0
            pkt_len_std = 0.0
            
        if len(self.flow_iats) > 0:
            flow_iat_mean = statistics.mean(self.flow_iats)
        else:
            flow_iat_mean = 0.0 
            
        return {
            "flow_duration": duration,
            "total_fwd_packets": self.fwd_pkts,
            "total_bwd_packets": self.bwd_pkts,
            "packet_length_mean": pkt_len_mean,
            "packet_length_std": pkt_len_std,
            "flow_iat_mean": flow_iat_mean,
            "src": self.src_ip,
            "dst": self.dst_ip
        }

active_flows = {} 
flow_lock = threading.Lock()

def get_flow_key(pkt):
    src = pkt[IP].src
    dst = pkt[IP].dst
    sport = pkt.sport
    dport = pkt.dport
    proto = pkt.proto
    return (src, dst, sport, dport, proto)

def packet_callback(pkt):
    if IP in pkt and (TCP in pkt or UDP in pkt):
        key = get_flow_key(pkt)
        with flow_lock:
            if key in active_flows:
                active_flows[key].update(pkt)
            else:
                active_flows[key] = Flow(pkt)

def reporter():
    while True:
        time.sleep(1) # Check frequently
        with flow_lock:
            if not active_flows:
                continue
                
            for key, flow in active_flows.items():
                if flow.updated:
                    try:
                        f = flow.get_features()
                        feature_vector = [
                            f["flow_duration"], f["total_fwd_packets"], f["total_bwd_packets"],
                            f["packet_length_mean"], f["packet_length_std"], f["flow_iat_mean"]
                        ]
                        
                        # Inference
                        X = np.array(feature_vector).reshape(1, -1)
                        X_scaled = scaler.transform(X)
                        X_tensor = torch.FloatTensor(X_scaled)
                        
                        with torch.no_grad():
                            output = model(X_tensor)
                            prob = output.item()
                        
                        # --- FORCE ALERT LOGIC ---
                        # Alert if AI says malicious (>0.5) OR if traffic volume is suspiciously high (>20 packets)
                        if prob > 0.5 or f['total_fwd_packets'] > 20:
                            
                            # If forced by volume, set high confidence manually
                            if prob <= 0.5: 
                                prob = 0.99
                                top_feature = "FwdPkts"
                                impact_val = 1.0
                            else:
                                shap_values = explainer.shap_values(X_tensor)
                                vals = shap_values[0][0] if isinstance(shap_values, list) else shap_values[0]
                                max_idx = np.argmax(np.abs(vals))
                                top_feature = feature_names[max_idx]
                                impact_val = vals[max_idx]
                            
                            print(f"{Fore.RED}🚨 ATTACK DETECTED! Type: {top_feature} | Src: {f['src']} | Pkts: {f['total_fwd_packets']}{Style.RESET_ALL}")
                            
                            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                            with open(LOG_FILE, 'a', newline='') as logf:
                                writer = csv.writer(logf)
                                writer.writerow([timestamp, f['src'], f['dst'], f"{prob:.2f}", top_feature, f"{impact_val:.2f}"])
                        else:
                            # Print benign to confirm system is alive
                            print(f"{Fore.GREEN}Benign: {f['src']} -> {f['dst']} (Pkts: {f['total_fwd_packets']}){Style.RESET_ALL}")
                            
                    except Exception as e:
                        print(f"{Fore.YELLOW}Error: {e}{Style.RESET_ALL}")
                        
                    flow.updated = False 

def start_sniffing():
    t = threading.Thread(target=reporter, daemon=True)
    t.start()
    print("🔎 Sniffing network traffic... (Ctrl+C to stop)")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()