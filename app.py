
import time
import pandas as pd
import streamlit as st
import plotly.express as px

from src.feature_engineering import build_features
from src.detector import detect_dataframe
from src.risk_scoring import add_risk_scores


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="AI Cyber Threat Detection",
    page_icon="🛡️",
    layout="wide",
)


# ---------------------------------------------------------
# TITLE
# ---------------------------------------------------------

st.title("🛡️ AI-Based Cyber Threat Detection")

st.caption(
    "Passive detection of cyber threats in unidirectional IP traffic "
    "using behavioural flow analytics and hybrid detection."
)


# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------

st.sidebar.header("Detection Controls")

scenario = st.sidebar.selectbox(
    "Traffic Scenario",
    [
        "All Traffic",
        "Normal Traffic",
        "SYN Flood",
        "UDP Reflection",
        "C2 Beaconing",
        "DGA / DNS Tunnelling",
        "Encrypted Malware",
        "Reconnaissance",
        "Data Exfiltration",
    ],
)

run_detection = st.sidebar.button(
    "▶ Run Detection",
    use_container_width=True,
)


# ---------------------------------------------------------
# LOAD DATA
# ---------------------------------------------------------

@st.cache_data
def load_data():
    try:
        return pd.read_csv("data/sample_flows.csv")
    except FileNotFoundError:
        return pd.DataFrame()


df = load_data()


# ---------------------------------------------------------
# DEMO DATA FALLBACK
# ---------------------------------------------------------

def create_demo_data():
    """
    Creates a small synthetic dataset if sample_flows.csv
    is not yet populated.
    """

    return pd.DataFrame(
        [
            {
                "flow_id": "FLOW-001",
                "src_ip": "10.0.0.10",
                "dst_ip": "10.0.0.20",
                "protocol": "TCP",
                "duration": 10,
                "packets": 80,
                "bytes": 8000,
                "src_bytes": 4000,
                "dst_bytes": 4000,
                "dst_port": 443,
                "fan_out": 2,
                "destination_diversity": 2,
                "inter_arrival_time": 30,
                "domain": "",
                "tls_fingerprint": "JA4-DEMO-001",
            },
            {
                "flow_id": "FLOW-002",
                "src_ip": "10.0.0.50",
                "dst_ip": "10.0.0.60",
                "protocol": "TCP",
                "duration": 2,
                "packets": 3000,
                "bytes": 300000,
                "src_bytes": 150000,
                "dst_bytes": 150000,
                "dst_port": 80,
                "fan_out": 80,
                "destination_diversity": 60,
                "inter_arrival_time": 0.01,
                "domain": "",
                "tls_fingerprint": "",
            },
            {
                "flow_id": "FLOW-003",
                "src_ip": "10.0.0.70",
                "dst_ip": "10.0.0.80",
                "protocol": "TCP",
                "duration": 120,
                "packets": 40,
                "bytes": 6000,
                "src_bytes": 3000,
                "dst_bytes": 3000,
                "dst_port": 443,
                "fan_out": 1,
                "destination_diversity": 2,
                "inter_arrival_time": 60,
                "domain": "",
                "tls_fingerprint": "JA4-C2-DEMO",
            },
            {
                "flow_id": "FLOW-004",
                "src_ip": "10.0.0.90",
                "dst_ip": "10.0.0.53",
                "protocol": "UDP",
                "duration": 5,
                "packets": 120,
                "bytes": 50000,
                "src_bytes": 45000,
                "dst_bytes": 5000,
                "dst_port": 53,
                "fan_out": 3,
                "destination_diversity": 2,
                "inter_arrival_time": 2,
                "domain": "xj29akq91m2zq8p7.example",
                "tls_fingerprint": "",
            },
            {
                "flow_id": "FLOW-005",
                "src_ip": "10.0.0.100",
                "dst_ip": "10.0.0.200",
                "protocol": "TCP",
                "duration": 300,
                "packets": 500,
                "bytes": 8000000,
                "src_bytes": 7800000,
                "dst_bytes": 200000,
                "dst_port": 443,
                "fan_out": 1,
                "destination_diversity": 1,
                "inter_arrival_time": 1,
                "domain": "",
                "tls_fingerprint": "JA4-EXFIL-DEMO",
            },
        ]
    )


if df.empty:
    df = create_demo_data()


# ---------------------------------------------------------
# SCENARIO FILTER
# ---------------------------------------------------------

scenario_map = {
    "Normal Traffic": "Normal",
    "SYN Flood": "DDoS",
    "UDP Reflection": "DDoS",
    "C2 Beaconing": "C2 Beaconing",
    "DGA / DNS Tunnelling": "DGA / DNS Tunnelling",
    "Encrypted Malware": "Encrypted Malware",
    "Reconnaissance": "Reconnaissance",
    "Data Exfiltration": "Data Exfiltration",
}


# ---------------------------------------------------------
# DETECTION PIPELINE
# ---------------------------------------------------------

features = build_features(df)

detections = detect_dataframe(features)

results = add_risk_scores(detections)


if scenario != "All Traffic":

    # We run detection first and then filter by the
    # requested scenario.

    target = scenario_map.get(scenario)

    if target:
        filtered = results[
            results["threat_class"] == target
        ]

        # If no matching threat exists in the dataset,
        # keep the complete dataset so the demo remains useful.
        if not filtered.empty:
            results = filtered


# ---------------------------------------------------------
# RUN BUTTON
# ---------------------------------------------------------

if run_detection:

    progress = st.progress(0)

    for value in range(0, 101, 20):
        time.sleep(0.05)
        progress.progress(value)

    st.success(
        "Streaming detection completed successfully."
    )


# ---------------------------------------------------------
# KPI CARDS
# ---------------------------------------------------------

total_flows = len(results)

threats = results[
    results["threat_class"] != "Normal"
]

high_risk = results[
    results["severity"] == "HIGH"
]

avg_risk = (
    results["risk_score"].mean()
    if not results.empty
    else 0
)


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Flows Processed",
    total_flows,
)

col2.metric(
    "Threats Detected",
    len(threats),
)

col3.metric(
    "High-Risk Alerts",
    len(high_risk),
)

col4.metric(
    "Average Risk",
    f"{avg_risk:.1f}/100",
)


st.divider()


# ---------------------------------------------------------
# THREAT DISTRIBUTION
# ---------------------------------------------------------

left, right = st.columns(2)


with left:

    st.subheader("Threat Distribution")

    threat_counts = (
        results["threat_class"]
        .value_counts()
        .reset_index()
    )

    threat_counts.columns = [
        "Threat",
        "Count",
    ]

    fig = px.bar(
        threat_counts,
        x="Threat",
        y="Count",
        title="Detected Threat Classes",
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
    )


with right:

    st.subheader("Risk Distribution")

    fig = px.histogram(
        results,
        x="risk_score",
        nbins=10,
        title="Risk Score Distribution",
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
    )


# ---------------------------------------------------------
# ALERT TABLE
# ---------------------------------------------------------

st.subheader("🚨 Threat Alerts")

display_columns = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "protocol",
    "threat_class",
    "severity",
    "confidence",
    "risk_score",
    "evidence",
]

available_columns = [
    col for col in display_columns
    if col in results.columns
]

st.dataframe(
    results[available_columns],
    use_container_width=True,
    hide_index=True,
)


# ---------------------------------------------------------
# SUPPORTING EVIDENCE
# ---------------------------------------------------------

st.subheader("🔎 Supporting Evidence")

if not threats.empty:

    selected_flow = st.selectbox(
        "Select an alert",
        threats["flow_id"].astype(str).tolist(),
    )

    selected = threats[
        threats["flow_id"].astype(str)
        == selected_flow
    ].iloc[0]

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "Threat Class",
        selected["threat_class"],
    )

    c2.metric(
        "Severity",
        selected["severity"],
    )

    c3.metric(
        "Risk Score",
        f"{selected['risk_score']}/100",
    )

    st.write(
        "**Supporting evidence:**"
    )

    evidence = str(
        selected["evidence"]
    ).split(";")

    for item in evidence:

        if item.strip():
            st.write(
                f"• {item.strip()}"
            )

else:

    st.info(
        "No threat alerts detected for the selected scenario."
    )


# ---------------------------------------------------------
# SECURITY CONSTRAINTS
# ---------------------------------------------------------

st.divider()

st.subheader("🔒 Monitoring Constraints")

c1, c2, c3, c4 = st.columns(4)

c1.info("NO RETURN PATH")
c2.info("NO ACTIVE PROBING")
c3.info("NO INLINE BLOCKING")
c4.info("NO PAYLOAD DECRYPTION")


st.caption(
    "Prototype: passive, metadata-based traffic analysis "
    "for controlled laboratory / replayed traffic."
)
