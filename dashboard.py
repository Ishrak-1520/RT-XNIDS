import streamlit as st
import pandas as pd
import altair as alt
import time
import os
import json

# 1. Page Config
st.set_page_config(
    page_title="RT-XNIDS Monitor",
    page_icon="page_icon.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. CSS Injection (Shadcn UI Dark Mode - Zinc)
st.markdown("""
<style>
    /* Global Settings */
    .stApp {
        background-color: #09090b;
        color: #fafafa;
        font-family: 'Space Grotesk', sans-serif;
    }
    
    /* Clean UI */
    /* header[data-testid="stHeader"] {visibility: hidden;} */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .block-container {padding-top: 2rem; padding-bottom: 2rem;}

    /* Table Styles */
    table.shadcn-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.875rem;
        border: 1px solid #27272a;
        border-radius: 0.5rem;
        overflow: hidden;
    }
    table.shadcn-table th {
        background-color: #09090b;
        color: #a1a1aa;
        font-weight: 500;
        text-align: left;
        padding: 0.75rem 1rem;
        border-bottom: 1px solid #27272a;
    }
    table.shadcn-table td {
        background-color: #09090b;
        color: #fafafa;
        padding: 0.75rem 1rem;
        border-bottom: 1px solid #27272a;
    }
    table.shadcn-table tr:last-child td {
        border-bottom: none;
    }
</style>
""", unsafe_allow_html=True)

# 3. Helper Functions

def card(title, value, sub_text, icon_svg):
    # Minified HTML to prevent markdown indentation issues
    return f"""
<div style="border: 1px solid #27272a; border-radius: 0.5rem; padding: 1.5rem; background-color: #09090b; margin-bottom: 1rem; height: 100%;">
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
        <span style="font-size: 0.875rem; font-weight: 500; color: #a1a1aa; letter-spacing: -0.025em;">{title}</span>
        {icon_svg}
    </div>
    <div style="font-size: 1.75rem; font-weight: 700; letter-spacing: -0.05em; color: #fafafa; margin-bottom: 0.25rem;">
        {value}
    </div>
    <div style="font-size: 0.75rem; color: #a1a1aa;">
        {sub_text}
    </div>
</div>
"""

def generate_html_table(df):
    if df.empty:
        return """<div style="border: 1px solid #27272a; border-radius: 0.5rem; padding: 2rem; text-align: center; color: #a1a1aa; font-size: 0.875rem;">No active threats detected. System secure.</div>"""
    
    # Start Table
    html = "<table class='shadcn-table'>"
    
    # Header
    html += "<thead><tr>"
    headers = ["Time", "Source", "Target", "Type", "Conf"]
    for h in headers:
        html += f"<th>{h}</th>"
    html += "</tr></thead>"
    
    # Body
    html += "<tbody>"
    # Show all data (sorted by latest first)
    for _, row in df.iterrows():
        # Format Timestamp
        try:
            ts = row['Timestamp'].split(' ')[1] # HH:MM:SS
        except:
            ts = row['Timestamp']
            
        # Format Confidence
        try:
            val = float(row['Confidence'])
            if val > 0.8:
                conf_html = f"<span style='color: #ef4444; font-weight: 600;'>{val:.2f}</span>"
            else:
                conf_html = f"<span style='color: #eab308; font-weight: 600;'>{val:.2f}</span>"
        except:
            conf_html = row['Confidence']

        row_html = f"<tr><td style='color: #a1a1aa;'>{ts}</td><td>{row['SrcIP']}</td><td>{row['DstIP']}</td><td>{row['AttackReason']}</td><td>{conf_html}</td></tr>"
        html += row_html
        
    html += "</tbody></table>"
    return html

# Icons
ICON_SHIELD = """<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#a1a1aa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>"""
ICON_TARGET = """<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#a1a1aa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>"""
ICON_ACTIVITY = """<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#a1a1aa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>"""

# 4. Data Loading
LOG_FILE = "alerts.log"

def load_data():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame(columns=["Timestamp", "SrcIP", "DstIP", "Confidence", "AttackReason", "ImpactScore"])
    try:
        df = pd.read_csv(LOG_FILE)
        return df
    except:
        return pd.DataFrame(columns=["Timestamp", "SrcIP", "DstIP", "Confidence", "AttackReason", "ImpactScore"])

def load_system_stats():
    STATS_FILE = "live_stats.json"
    if not os.path.exists(STATS_FILE):
        return {"accuracy": "0.00%", "latency": "0.00", "total": 0, "threats": 0, "mode": "Inactive"}
    try:
        with open(STATS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {"accuracy": "0.00%", "latency": "0.00", "total": 0, "threats": 0, "mode": "Inactive"}

def get_human_explanation(attack_type, top_feature, confidence):
    conf_pct = f"{float(confidence)*100:.0f}%" if confidence != "N/A" else "High"
    
    if top_feature in ['FwdPkts', 'BwdPkts', 'Total Fwd Packets', 'Total Backward Packets']:
        return f"This device is sending a massive amount of traffic in a short time. This is typical of 'Flooding' or DDoS attacks trying to crash the network. (Confidence: {conf_pct})"
    elif top_feature in ['Duration', 'Flow Duration']:
        return f"The connection was kept open for a suspiciously long time, which often indicates a hacker maintaining a link to steal data (Command & Control). (Confidence: {conf_pct})"
    elif top_feature in ['LenMean', 'LenStd', 'Fwd Packet Length Mean', 'Fwd Packet Length Std']:
        return f"The data packets are unusually large or small. This often happens when hackers hide malicious code inside files or scan the network for vulnerabilities. (Confidence: {conf_pct})"
    elif top_feature in ['IAT', 'Flow IAT Mean']:
        return f"The traffic is arriving faster than a human could type (machine speed). This indicates an automated bot is attacking the system. (Confidence: {conf_pct})"
    else:
        return f"The AI detected an anomaly based on network patterns that deviate significantly from normal user behavior. (Confidence: {conf_pct})"

# 5. Sidebar Configuration
with st.sidebar:
    st.header(":material/settings: Control Panel")
    
    # A. Sensitivity (Slider)
    st.subheader("Defense Logic")
    confidence_threshold = st.slider(
        ":material/tune: Sensitivity", 
        min_value=0.0, max_value=1.0, value=0.60, step=0.05,
        help="Alerts below this confidence are ignored."
    )
    
    # B. Attack Vector Filter (Multiselect)
    # We pre-define common vectors to avoid loop glitches
    known_vectors = ["FwdPkts", "BwdPkts", "Duration", "LenMean", "LenStd", "IAT"]
    selected_vectors = st.multiselect(
        ":material/filter_alt: Filter Attack Type",
        options=known_vectors,
        default=known_vectors,
        help="Focus on specific types of attacks."
    )

    # C. View Settings
    st.subheader("Dashboard View")
    history_depth = st.select_slider(
        ":material/history: History Depth",
        options=[10, 25, 50, 100],
        value=25,
        help="How many recent alerts to show."
    )
    
    refresh_rate = st.slider(
        ":material/timer: Refresh Rate (s)", 
        min_value=1, max_value=5, value=1
    )
    
    st.divider()
    st.markdown(":material/check_circle: System Status: **Active**")

# 6. Main Logic (Replaced 'while True' with st.rerun pattern)
df_raw = load_data()

# 1. Apply Logic Filters
if not df_raw.empty:
    df = df_raw[df_raw['Confidence'].astype(float) >= confidence_threshold]
else:
    df = df_raw.copy()

# 2. Apply Vector Filter
if not df.empty and selected_vectors:
    df = df[df['AttackReason'].isin(selected_vectors)]

# 3. Sort and Limit for View
if not df.empty:
    df_sorted = df.sort_index(ascending=False).head(history_depth)
else:
    df_sorted = pd.DataFrame(columns=["Timestamp", "SrcIP", "DstIP", "Confidence", "AttackReason", "ImpactScore"])

# --- UI Rendering ---

# Header
st.markdown("""
<h1 style="font-size: 1.5rem; font-weight: 600; letter-spacing: -0.05em; margin-bottom: 2rem; color: #fafafa;">Network Security Monitor</h1>
""", unsafe_allow_html=True)

# System Status Metrics
stats = load_system_stats()
m1, m2, m3, m4 = st.columns(4)
m1.metric(label=":material/dns: System Mode", value=stats["mode"])
m2.metric(label=":material/check_circle: Accuracy", value=stats["accuracy"])
m3.metric(label=":material/speed: Avg Latency", value=f"{stats['latency']} ms")
m4.metric(label=":material/query_stats: Processed Flows", value=f"{stats['total']:,}")

st.markdown("<div style='height: 1rem; border-bottom: 1px solid #27272a; margin-bottom: 2rem;'></div>", unsafe_allow_html=True)

# --- 🔎 INCIDENT INSPECTOR (Interactive Forensic Tool) ---
if not df_sorted.empty:
    st.subheader(":material/search: Forensic Analysis")
    
    # Create unique labels for selection
    df_sorted['Label'] = df_sorted.apply(
        lambda x: f"{x['Timestamp'].split(' ')[1] if ' ' in x['Timestamp'] else x['Timestamp']} | {x['SrcIP']} -> {x['DstIP']} | {x['AttackReason']}", 
        axis=1
    )
    
    c_sel, c_why = st.columns([1, 2])
    
    with c_sel:
        selected_alert_label = st.selectbox(
            "Select Alert to Investigate:",
            options=df_sorted['Label'].tolist(),
            index=0  # Latest by default
        )
    
    # Find selected row
    selected_row = df_sorted[df_sorted['Label'] == selected_alert_label].iloc[0]
    
    with c_why:
        explanation = get_human_explanation(
            selected_row['AttackReason'], 
            selected_row['AttackReason'], 
            selected_row['Confidence']
        )
        st.info(f"**Analysis of {selected_row['SrcIP']}**: {explanation}", icon=":material/lightbulb:")

st.divider()

# Total Threats Metrics
total_threats = len(df)
if not df.empty:
    # Use global df for metrics/cards
    last_target = df.iloc[-1]['DstIP']
    top_vector = df['AttackReason'].mode()[0] if not df['AttackReason'].empty else "N/A"
    high_conf = len(df[df['Confidence'] > 0.9])
    
    try:
        last_ts = df.iloc[-1]['Timestamp'].split(' ')[1]
    except:
        last_ts = "N/A"
else:
    last_target = "Safe"
    top_vector = "None"
    high_conf = 0
    last_ts = "--:--"
    
# Cards
c1, c2, c3 = st.columns(3)
with c1:
    st.markdown(card("Total Threats", str(total_threats), f"{high_conf} Critical", ICON_SHIELD), unsafe_allow_html=True)
with c2:
    st.markdown(card("Active Target", last_target, f"Last: {last_ts}", ICON_TARGET), unsafe_allow_html=True)
with c3:
    st.markdown(card("Top Vector", top_vector, "Most Frequent", ICON_ACTIVITY), unsafe_allow_html=True)
    
st.markdown("<div style='height: 2rem;'></div>", unsafe_allow_html=True)

# Main Content: Feed & Charts
c_table, c_chart = st.columns([2, 1])

with c_table:
    st.markdown(f"### Live Threat Feed (Last {history_depth})")
    table_html = generate_html_table(df_sorted)
    st.markdown(table_html, unsafe_allow_html=True)
    
with c_chart:
    st.markdown("### Attack Distribution")
    if not df.empty:
        chart = alt.Chart(df).mark_arc(innerRadius=60).encode(
            theta=alt.Theta("count()", stack=True),
            color=alt.Color("AttackReason", scale={'scheme': 'reds'}, legend=alt.Legend(orient="bottom", title=None, labelColor="#a1a1aa")),
            tooltip=["AttackReason", "count()"]
        ).properties(
            height=300,
            background='transparent'
        ).configure_view(
            strokeWidth=0
        )
        st.altair_chart(chart, use_container_width=True)
    else:
        st.markdown("<div style='color: #a1a1aa; font-size: 0.875rem;'>Waiting for data...</div>", unsafe_allow_html=True)

# Auto-refresh logic
time.sleep(refresh_rate)
st.rerun()
