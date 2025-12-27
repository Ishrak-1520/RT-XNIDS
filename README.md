# RT-XNIDS: Real-Time Explainable Network Intrusion Detection System

**RT-XNIDS** is a lightweight, Machine Learning-based Network Intrusion Detection System (NIDS) designed to detect cyber attacks in real-time. It leverages a Deep Neural Network (MLP) trained on the **CIC-IDS2017** dataset to classify network traffic as either **Safe** (Benign) or **Malicious** (e.g., DDoS, PortScan, Botnet).

Unlike traditional signature-based IDS, RT-XNIDS detects patterns in traffic flow, allowing it to identify zero-day threats. It includes a **Traffic Replay System** for simulation and a **Live Sniffer** for real-world monitoring.

<img width="1854" height="915" alt="dashboard " src="https://github.com/user-attachments/assets/e3331412-7908-465e-aa78-165982a154e2" />

---

## Key Features

* **Deep Learning Core:** Uses a Multi-Layer Perceptron (MLP) Classifier (Scikit-Learn) optimized for tabular network data.
* **"Safe" vs "Attack" Classification:** User-friendly output clearly distinguishes between Safe traffic and potential threats.
* **Dataset Replay Mode:** Simulates real-time network attacks by replaying .pcap CSV datasets (perfect for demonstrations).
* **Real-Time Sniffing:** Captures live packets (using Scapy) and feeds them into the ML model for instant analysis.
* **Performance Metrics:** Automated evaluation module generating Confusion Matrices, Accuracy, Precision, Recall, and F1-Scores.
* **Robust Error Handling:** Automatically handles feature mismatches (e.g., 6 live features vs 78 training features) via intelligent padding.

---

## Project Structure

| File | Description |
| --- | --- |
| **train_model.py** | Trains the MLP Neural Network using the CIC-IDS2017 dataset and saves model.pkl & scaler.pkl. |
| **dataset_replay.py** | **(Demo Mode)** Reads a historical CSV dataset line-by-line to simulate live network traffic and alerts. |
| **evaluate_system.py** | Loads the trained model and calculates accuracy metrics, generating a performance report and Confusion Matrix. |
| **flow_builder.py** | **(Live Mode)** Captures real network packets from your NIC, extracts features, and runs inference in real-time. |
| **model.pkl** | The trained Machine Learning model (Artifact). |
| **scaler.pkl** | The data scaler used to normalize input traffic (Artifact). |

---

## Installation

1. **Clone the Repository:**
```bash
git clone https://github.com/yourusername/RT-XNIDS.git
cd RT-XNIDS

```


2. **Install Dependencies:**
Ensure you have Python 3.8+ installed.
```bash
pip install pandas numpy scikit-learn matplotlib seaborn scapy joblib colorama

```


*(Note: If using Windows, you may need Npcap installed for Scapy to sniff live packets)*.

3. **Prepare the Dataset:**
* Download a CSV from the CIC-IDS2017 Dataset.
* Place it in `datasets/CICIDS2017/` (or update the path in the scripts).
* *Default used:* `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`



---

## Usage Guide

### 1. Train the Model

Before running any simulations, you must train the brain.

```bash
python train_model.py

```

* *Output:* Creates `model.pkl` and `scaler.pkl`.
* *Note:* If you don't have the dataset yet, the script acts in "Dummy Mode" to demonstrate functionality.

### 2. Evaluate Performance

Check how well the model detects "Safe" vs "Malicious" traffic.

```bash
python evaluate_system.py

```

* *Output:* Prints Accuracy, Precision, Recall, F1-Score, and saves `confusion_matrix.png`.

### 3. Run Simulation (Replay)

Simulate an attack scenario using historical data without needing a live attack.

```bash
python dataset_replay.py

```

* *Action:* Reads the CSV row-by-row and prints colored alerts to the console.
* *Green:* **[SAFE]** Traffic
* *Red:* **[ALERT]** Attack Detected

### 4. Live Detection (Optional)

Monitor your actual network interface.

```bash
python flow_builder.py

```

* *Requires:* Administrator/Root privileges to capture packets.

---

## Sample Output

**Console Output (Replay Mode):**

```text
Initializing Replay System...
[INFO] Model expects 78 features.
Dataset loaded: 286467 rows.
Simulation starting... (Ctrl+C to stop)

[SAFE] Processing flow 0... (SAFE)
[SAFE] Processing flow 50... (SAFE)
[ALERT] PortScan | Reason: FwdPkts | Src: 192.168.10.50 | Label: PortScan
[ALERT] PortScan | Reason: IAT     | Src: 192.168.10.50 | Label: PortScan

```

---

## Configuration

You can tweak the settings at the top of any script:

* `MIN_CONFIDENCE`: Threshold (0.0 - 1.0) to trigger an alert.
* `WHITELIST_IPS`: List of IPs to always mark as Safe.
* `DATASET_PATH`: Path to your specific CSV file.

---

## License & Disclaimer

This project is for **Educational and Research Purposes Only**.

* Do not use this system to monitor networks without authorization.
* The authors are not responsible for any misuse of this tool.
