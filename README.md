# RT-XNIDS: Real-Time Explainable Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red?logo=streamlit)
![PyTorch](https://img.shields.io/badge/PyTorch-Deep%20Learning-orange?logo=pytorch)
![License](https://img.shields.io/badge/License-MIT-green)

**RT-XNIDS** is a lightweight, real-time cybersecurity monitoring tool that uses Deep Learning to detect network attacks and Explainable AI (SHAP) to tell you *why* an attack was flagged. 
---

## Project Preview
> **Features:**
> * **Real-Time Sniffing:** Captures live packets using Scapy.
> * **AI Detection:** Uses a PyTorch Neural Network to classify benign vs. malicious flows.
> * **Explainability (XAI):** Uses SHAP values to identify the exact feature (e.g., "High Packet Count") that triggered the alert.
> * **Modern UI:** A custom-styled Streamlit dashboard with a professional dark mode design.

---

## Project Structure

```bash
RT-XNIDS/
├── attack_test.py      # Simulation script to generate dummy attack traffic
├── dashboard.py        # The SOC Monitor UI (Streamlit)
├── flow_builder.py     # The "Brain": Sniffer, Feature Extractor, & AI Model
├── nids_model.pth      # Pre-trained PyTorch model weights
├── scaler.pkl          # Scikit-learn scaler for feature normalization
├── logo.png            # Custom project icon
└── requirements.txt    # Python dependencies

```

---

## Installation

### 1. Clone the Repository

```bash
git clone [https://github.com/yourusername/RT-XNIDS.git](https://github.com/yourusername/RT-XNIDS.git)
cd RT-XNIDS

```

### 2. Install Dependencies

Ensure you have Python installed, then run:

```bash
pip install -r requirements.txt

```

*(If you don't have a `requirements.txt`, create one with: `scapy pandas numpy torch streamlit altair shap colorama joblib pill`)*

### 3. Setup (Optional)

If you are on Windows, you may need to install [Npcap](https://npcap.com/) (check "Install Npcap in WinPcap API-compatible Mode") for Scapy to sniff packets correctly.

---

## Usage Guide

Run the system in **three separate terminals** to see the full pipeline in action.

### Terminal 1: The Dashboard (UI)

Start the visualization interface.

```bash
python -m streamlit run dashboard.py

```

### Terminal 2: The Sensor (Brain)

Start the packet sniffer and AI detector.

```bash
python flow_builder.py

```

*Wait until you see: `✅ System Ready. Waiting for packets...*`

### Terminal 3: The Attacker (Simulation)

Simulate a DoS/Flooding attack to trigger the system.

```bash
python attack_test.py

```

---

## How It Works

1. **Packet Capture:** `flow_builder.py` listens to network traffic on your interface.
2. **Flow Aggregation:** Individual packets are grouped into "Flows" (src, dst, port, protocol).
3. **Feature Extraction:** The system calculates metrics like *Flow Duration*, *Packet Count*, and *Inter-Arrival Time (IAT)*.
4. **Inference:** The data is normalized (`scaler.pkl`) and passed to the Neural Network (`nids_model.pth`).
5. **Explainability:** If a threat is detected, SHAP calculates which feature contributed most to the decision.
6. **Visualization:** The alert is logged to `alerts.log`, which the Dashboard polls instantly to update the UI.

---

## Configuration

* **Sensitivity:** You can adjust the alert threshold in `flow_builder.py` inside the `reporter()` function.
* **Target IP:** Modify `attack_test.py` to target specific IP addresses on your local network.


## License

Distributed under the MIT License. See `LICENSE` for more information.

```

```
