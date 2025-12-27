# RT-XNIDS: Real-Time Explainable Network Intrusion Detection System

RT-XNIDS is a professional-grade Network Intrusion Detection System (NIDS) powered by Machine Learning. Unlike traditional "Black Box" AI, this system focuses on **Explainability (XAI)**, translating complex network anomalies into plain English for security analysts.

It features a "Command Center" dashboard with real-time visualization, forensic inspection tools, and dynamic sensitivity controls.


<img width="1854" height="915" alt="dashboard " src="https://github.com/user-attachments/assets/d40a508f-82d0-44f7-bb8f-5bb45a7fb076" />

## Key Features

* **Dual-Mode Operation:**
    * **Live Sniffer:** Captures and analyzes real network traffic in real-time.
    * **Simulation Mode:** Replays CIC-IDS2017 datasets to demonstrate detection capabilities safely.
* **Explainable AI (XAI):**
    * Translates technical features (e.g., FwdPkts, IAT) into human-readable explanations.
    * *Example:* "Traffic is arriving faster than a human could type, indicating a bot attack."
* **Forensic Inspector:**
    * Interactive tool to pause and investigate specific alerts from the history log.
    * Provides deep-dive analysis on specific IP addresses and attack vectors.
* **Dynamic Control Panel:**
    * **Sensitivity Slider:** Adjust confidence thresholds (0.60 - 1.0) live to filter noise.
    * **Vector Filters:** Isolate specific attacks (e.g., "Show me only DDoS").
    * **Performance Tuning:** Control history depth and refresh rates.
* **Professional Dashboard:**
    * Built with Streamlit and Altair.
    * Strict professional design standards (Material Design icons, Dark Mode).

---

## Project Structure

| File | Description |
| :--- | :--- |
| `dashboard.py` | The frontend "Command Center." Visualizes threats, stats, and explains alerts. |
| `dataset_replay.py` | **Simulation Engine.** Replays pre-recorded CSV datasets to mimic attacks. |
| `flow_builder.py` | **Live Engine.** Sniffs real network packets and builds flows for the AI model. |
| `model.pkl` | Pre-trained Machine Learning model (Random Forest / XGBoost). |
| `alerts.log` | Shared log file where detection events are recorded. |
| `live_stats.json` | Real-time system telemetry (Accuracy, Latency, Flow Counts). |

---

## Installation

### Prerequisites
* Python 3.8 or higher
* Npcap (for Windows users) or libpcap (for Linux/Mac users)

### Steps

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/your-username/RT-XNIDS.git](https://github.com/your-username/RT-XNIDS.git)
    cd RT-XNIDS
    ```

2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## Usage Guide

### Mode 1: Simulation (Safe Demo)
Use this to demonstrate the system using the CIC-IDS2017 dataset without needing real attacks.

1.  **Start the Backend:**
    ```bash
    python dataset_replay.py
    ```
2.  **Start the Dashboard (in a new terminal):**
    ```bash
    streamlit run dashboard.py
    ```

### Mode 2: Live Sniffing (Real Traffic)
Use this to monitor your actual network adapter. *(Requires Admin/Root privileges)*.

1.  **Start the Sniffer:**
    ```bash
    # Windows (Run as Administrator)
    python flow_builder.py
    
    # Linux/Mac (Sudo required)
    sudo python3 flow_builder.py
    ```
2.  **Start the Dashboard:**
    ```bash
    streamlit run dashboard.py
    ```

---

## Dashboard Controls

Once the dashboard is running, use the **Sidebar Control Panel** to interact with the system:

1.  **Sensitivity Threshold:**
    * Default: `0.60`.
    * Slide up to `0.90` to hide low-confidence alerts and reduce False Positives.
2.  **Attack Filter:**
    * Uncheck boxes to ignore specific attack types (e.g., hide "PortScan" to focus on "DDoS").
3.  **Forensic Analysis:**
    * Use the dropdown menu above the table to select *any* past alert.
    * The "Why did the AI block this?" panel will update to explain that specific event.

---

## Configuration

### Tuning False Positives
To permanently change the default sensitivity or whitelist trusted devices, edit `dataset_replay.py` or `flow_builder.py`:

```python
# Configuration Section
MIN_CONFIDENCE = 0.60         # Minimum probability to trigger an alert
WHITELIST_IPS = ["127.0.0.1", "192.168.1.1"]  # Trusted IPs (Router, Localhost)
