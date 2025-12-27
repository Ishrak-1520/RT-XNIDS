import time
import threading
import statistics
import numpy as np
import joblib
import csv
import os
import json
import warnings  # <--- ADDED
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from colorama import Fore, Style, init

# --- IGNORE WARNINGS ---
# This suppresses the "X does not have valid feature names" warning
warnings.filterwarnings("ignore", category=UserWarning)

# Initialize Colorama
init()

# --- Configuration ---
LOG_FILE = "alerts.log"
MODEL_PATH = "model.pkl"
SCALER_PATH = "scaler.pkl"

# --- Fine-Tuning ---
MIN_CONFIDENCE = 0.60
WHITELIST_IPS = ["127.0.0.1", "192.168.1.1", "192.168.0.1"]

# --- Global Artifacts ---
model = None
scaler = None
EXPECTED_FEATURES = 78 

# Load artifacts
try:
    print(f"{Fore.CYAN}[INFO] Loading Scaler...{Style.RESET_ALL}")
    scaler = joblib.load(SCALER_PATH)
    
    print(f"{Fore.CYAN}[INFO] Loading Model...{Style.RESET_ALL}")
    model = joblib.load(MODEL_PATH)
    
    if hasattr(model, "n_features_in_"):
        EXPECTED_FEATURES = model.n_features_in_
        print(f"{Fore.GREEN}[SUCCESS] Model loaded! Expecting {EXPECTED_FEATURES} features.{Style.RESET_ALL}")
    
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "SrcIP", "DstIP", "Confidence", "AttackReason", "ImpactScore"])
    
    print(f"{Fore.GREEN}[READY] System Waiting for packets...{Style.RESET_ALL}")

except Exception as e:
    print(f"{Fore.RED}[ERROR] Could not load artifacts: {e}")
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

total_flows = 0
total_latency = 0
malicious_count = 0
STATS_FILE = "live_stats.json"

def reporter():
    global total_flows, total_latency, malicious_count
    while True:
        time.sleep(1) 
        with flow_lock:
            if not active_flows:
                continue
            
            current_flows = list(active_flows.items())
            
            for key, flow in current_flows:
                if flow.updated:
                    try:
                        f = flow.get_features()
                        
                        # --- FEATURE PADDING ---
                        full_features = np.zeros(EXPECTED_FEATURES)
                        full_features[0] = f["flow_duration"]
                        full_features[1] = f["total_fwd_packets"]
                        full_features[2] = f["total_bwd_packets"]
                        full_features[3] = f["packet_length_mean"]
                        full_features[4] = f["packet_length_std"]
                        full_features[5] = f["flow_iat_mean"]
                        
                        X = full_features.reshape(1, -1)
                        X_scaled = scaler.transform(X)
                        
                        start_time_inf = time.time()
                        
                        probs = model.predict_proba(X_scaled)[0]
                        pred_class_idx = np.argmax(probs)
                        prob = probs[pred_class_idx]
                        pred_label = model.classes_[pred_class_idx] 
                        
                        end_time_inf = time.time()
                        
                        total_flows += 1
                        total_latency += (end_time_inf - start_time_inf)
                        
                        avg_latency = (total_latency / total_flows) * 1000 
                        try:
                            with open(STATS_FILE, 'w') as sf:
                                json.dump({
                                    "accuracy": "N/A (Live)", 
                                    "latency": f"{avg_latency:.2f}", 
                                    "total": total_flows, 
                                    "threats": malicious_count, 
                                    "mode": "Live Sniffer"
                                }, sf)
                        except:
                            pass 
                        
                        # --- ALERT LOGIC ---
                        # Check if label contains "Benign" (case insensitive)
                        is_benign = "BENIGN" in str(pred_label).upper()
                        is_malicious = not is_benign
                        
                        # Heuristic: High packet count -> Suspicious
                        if f['total_fwd_packets'] > 100:
                            # Only flag as malicious if it wasn't already purely benign
                            if is_benign:
                                pred_label = "High Volume (Heuristic)"
                                is_malicious = True
                            
                        if is_malicious and (prob >= MIN_CONFIDENCE) and (f['src'] not in WHITELIST_IPS):
                            malicious_count += 1
                            
                            if f['total_fwd_packets'] > 50: top_feature = "FwdPkts"
                            elif f['flow_iat_mean'] < 0.01: top_feature = "IAT"
                            else: top_feature = str(pred_label)

                            print(f"{Fore.RED}[ALERT] {pred_label} | {top_feature} | Src: {f['src']} | Conf: {prob:.2f}{Style.RESET_ALL}")
                            
                            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                            with open(LOG_FILE, 'a', newline='') as logf:
                                writer = csv.writer(logf)
                                writer.writerow([timestamp, f['src'], f['dst'], f"{prob:.2f}", top_feature])
                                
                        elif f['src'] in WHITELIST_IPS:
                             pass 
                        else:
                            # Print Green for Benign
                            print(f"{Fore.GREEN}[SAFE] {f['src']} -> {f['dst']} | {pred_label} ({prob:.2f}){Style.RESET_ALL}")
                            
                    except Exception as e:
                        # Silently ignore occasional math errors in threads
                        pass
                        
                    flow.updated = False 

def start_sniffing():
    t = threading.Thread(target=reporter, daemon=True)
    t.start()
    print(f"{Fore.CYAN} Sniffing network traffic... (Ctrl+C to stop){Style.RESET_ALL}")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()