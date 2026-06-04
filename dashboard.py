import sys
import streamlit as st

# Safety check for bare python execution
if "streamlit" not in sys.modules:
    print("\n[!] ERROR: Dashboard must be run with Streamlit.")
    print("    Run:  streamlit run dashboard.py\n")
    sys.exit(1)

import os
import json
import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import joblib
import ipaddress
from datetime import datetime
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
from ids_ips_trainer import engineer_features
from feedback_loop import FeedbackCollector

# Real-time IDS engine alert log (written by realtime_ids.py)
ALERTS_JSONL = "ids_alerts.jsonl"
MANUAL_ACTIONS_JSONL = os.path.join("data", "manual_actions.jsonl")

# ---------- CONFIG ----------
OUTPUT_DIR = "ids_output"          # must match trainer CONFIG
ANOMALY_CSV = os.path.join(OUTPUT_DIR, "anomaly_results.csv")
MODEL_PATH = os.path.join(OUTPUT_DIR, "ids_model.pkl")
SCALER_PATH = os.path.join(OUTPUT_DIR, "ids_scaler.pkl")
META_PATH = os.path.join(OUTPUT_DIR, "ids_metadata.pkl")

st.set_page_config(
    page_title="SudoSOC | AI-Powered IDS/IPS",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ══════════════════════════════════════════════════════════════════════════════
#  PREMIUM CSS - SudoSOC Red & Black Design System
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
    /* ── Import Professional Font ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    /* ── Root Variables ── */
    :root {
        --bg-primary: #0a0a0a;
        --bg-secondary: #111111;
        --bg-card: #161616;
        --bg-card-hover: #1a1a1a;
        --bg-elevated: #1e1e1e;
        --border-subtle: rgba(255, 255, 255, 0.06);
        --border-accent: rgba(220, 38, 38, 0.3);
        --text-primary: #f5f5f5;
        --text-secondary: #a3a3a3;
        --text-muted: #737373;
        --red-primary: #dc2626;
        --red-light: #ef4444;
        --red-dark: #991b1b;
        --red-glow: rgba(220, 38, 38, 0.15);
        --red-subtle: rgba(220, 38, 38, 0.08);
        --green-accent: #22c55e;
        --yellow-accent: #eab308;
        --blue-accent: #3b82f6;
        --glass-bg: rgba(22, 22, 22, 0.8);
        --glass-border: rgba(255, 255, 255, 0.08);
    }
    
    /* ── Global Styles ── */
    .stApp {
        background: var(--bg-primary) !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
        color: var(--text-primary) !important;
    }
    
    .stApp > header {
        background: transparent !important;
    }
    
    /* ── Main Content Area ── */
    .main .block-container {
        padding-top: 1rem !important;
        max-width: 1400px !important;
    }
    
    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d0d0d 0%, #111111 50%, #0d0d0d 100%) !important;
        border-right: 1px solid var(--border-subtle) !important;
    }
    
    [data-testid="stSidebar"] .stMarkdown p,
    [data-testid="stSidebar"] .stMarkdown li {
        color: var(--text-secondary) !important;
        font-size: 0.85rem !important;
    }
    
    [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, 
    [data-testid="stSidebar"] h3 {
        color: var(--text-primary) !important;
        font-weight: 600 !important;
    }
    
    /* ── Headers ── */
    h1 {
        font-weight: 800 !important;
        letter-spacing: -0.03em !important;
        color: var(--text-primary) !important;
    }
    
    h2 {
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
        color: var(--text-primary) !important;
        border-bottom: 2px solid var(--red-primary) !important;
        padding-bottom: 0.5rem !important;
        margin-top: 2rem !important;
    }
    
    h3 {
        font-weight: 600 !important;
        color: var(--text-secondary) !important;
    }
    
    /* ── Metric Cards ── */
    [data-testid="stMetric"] {
        background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-elevated) 100%) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 12px !important;
        padding: 1.2rem 1.5rem !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3) !important;
    }
    
    [data-testid="stMetric"]:hover {
        border-color: var(--border-accent) !important;
        box-shadow: 0 8px 32px rgba(220, 38, 38, 0.1), 0 4px 24px rgba(0, 0, 0, 0.4) !important;
        transform: translateY(-2px) !important;
    }
    
    [data-testid="stMetricLabel"] {
        color: var(--text-muted) !important;
        font-size: 0.75rem !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.08em !important;
    }
    
    [data-testid="stMetricValue"] {
        color: var(--text-primary) !important;
        font-weight: 800 !important;
        font-size: 1.8rem !important;
        font-family: 'Inter', sans-serif !important;
    }
    
    [data-testid="stMetricDelta"] {
        font-weight: 600 !important;
    }
    
    /* ── Tab Styling ── */
    .stTabs [data-baseweb="tab-list"] {
        background: var(--bg-secondary) !important;
        border-radius: 12px !important;
        padding: 4px !important;
        gap: 4px !important;
        border: 1px solid var(--border-subtle) !important;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: transparent !important;
        border-radius: 8px !important;
        color: var(--text-muted) !important;
        font-weight: 500 !important;
        font-size: 0.85rem !important;
        padding: 0.6rem 1.2rem !important;
        transition: all 0.2s ease !important;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        color: var(--text-primary) !important;
        background: var(--bg-card) !important;
    }
    
    .stTabs [aria-selected="true"] {
        background: var(--red-primary) !important;
        color: white !important;
        font-weight: 600 !important;
    }
    
    .stTabs [data-baseweb="tab-highlight"] {
        display: none !important;
    }
    
    .stTabs [data-baseweb="tab-border"] {
        display: none !important;
    }
    
    /* ── DataFrame / Table ── */
    [data-testid="stDataFrame"] {
        border-radius: 12px !important;
        overflow: hidden !important;
        border: 1px solid var(--border-subtle) !important;
    }
    
    /* ── Buttons ── */
    .stButton > button {
        background: linear-gradient(135deg, var(--red-primary) 0%, var(--red-dark) 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        padding: 0.6rem 1.5rem !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
        box-shadow: 0 4px 16px rgba(220, 38, 38, 0.25) !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 24px rgba(220, 38, 38, 0.35) !important;
        background: linear-gradient(135deg, var(--red-light) 0%, var(--red-primary) 100%) !important;
    }
    
    .stButton > button:active {
        transform: translateY(0) !important;
    }
    
    /* ── Form Inputs ── */
    .stTextInput input, .stNumberInput input, .stSelectbox select {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 8px !important;
        color: var(--text-primary) !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.85rem !important;
    }
    
    .stTextInput input:focus, .stNumberInput input:focus {
        border-color: var(--red-primary) !important;
        box-shadow: 0 0 0 2px var(--red-glow) !important;
    }
    
    /* ── Expander ── */
    .streamlit-expanderHeader {
        background: var(--bg-card) !important;
        border-radius: 8px !important;
        border: 1px solid var(--border-subtle) !important;
        font-weight: 500 !important;
        color: var(--text-secondary) !important;
    }
    
    .streamlit-expanderHeader:hover {
        border-color: var(--border-accent) !important;
        color: var(--text-primary) !important;
    }
    
    /* ── Info / Warning / Error Boxes ── */
    .stAlert {
        background: var(--bg-card) !important;
        border-radius: 8px !important;
        border-left: 4px solid var(--red-primary) !important;
        color: var(--text-secondary) !important;
    }
    
    /* ── Slider ── */
    .stSlider [data-baseweb="slider"] [role="slider"] {
        background: var(--red-primary) !important;
    }
    
    /* ── Divider ── */
    hr {
        border-color: var(--border-subtle) !important;
        margin: 2rem 0 !important;
    }
    
    /* ── Caption ── */
    .stCaption, small {
        color: var(--text-muted) !important;
        font-size: 0.75rem !important;
    }
    
    /* ── Custom Section Headers ── */
    .section-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin: 2rem 0 1rem 0;
        padding-bottom: 0.75rem;
        border-bottom: 2px solid var(--red-primary);
    }
    
    .section-header .icon {
        width: 32px;
        height: 32px;
        background: linear-gradient(135deg, var(--red-primary), var(--red-dark));
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1rem;
    }
    
    .section-header h2 {
        margin: 0 !important;
        padding: 0 !important;
        border: none !important;
        font-size: 1.3rem !important;
    }
    
    /* ── Hero Banner ── */
    .hero-banner {
        background: linear-gradient(135deg, #0d0d0d 0%, #1a0a0a 30%, #0d0d0d 60%, #0a0d0d 100%);
        border: 1px solid var(--border-subtle);
        border-radius: 16px;
        padding: 2rem 2.5rem;
        margin-bottom: 2rem;
        position: relative;
        overflow: hidden;
    }
    
    .hero-banner::before {
        content: '';
        position: absolute;
        top: 0;
        right: 0;
        width: 300px;
        height: 100%;
        background: linear-gradient(135deg, transparent, rgba(220, 38, 38, 0.05));
        border-radius: 0 16px 16px 0;
    }
    
    .hero-banner::after {
        content: '';
        position: absolute;
        top: -50%;
        right: -10%;
        width: 200px;
        height: 200%;
        background: radial-gradient(ellipse, rgba(220, 38, 38, 0.03) 0%, transparent 70%);
    }
    
    .hero-title {
        font-size: 2.2rem;
        font-weight: 900;
        letter-spacing: -0.04em;
        margin: 0 0 0.3rem 0;
        color: var(--text-primary);
        position: relative;
        z-index: 1;
    }
    
    .hero-title span {
        background: linear-gradient(135deg, var(--red-primary), var(--red-light));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    
    .hero-subtitle {
        font-size: 0.9rem;
        color: var(--text-muted);
        font-weight: 400;
        margin: 0;
        position: relative;
        z-index: 1;
    }
    
    .hero-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: var(--red-subtle);
        border: 1px solid var(--border-accent);
        border-radius: 20px;
        padding: 4px 14px;
        font-size: 0.7rem;
        color: var(--red-light);
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 0.8rem;
    }
    
    .hero-badge .pulse {
        width: 6px;
        height: 6px;
        background: var(--red-primary);
        border-radius: 50%;
        animation: pulse-glow 2s infinite;
    }
    
    @keyframes pulse-glow {
        0%, 100% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0.4); }
        50% { box-shadow: 0 0 0 6px rgba(220, 38, 38, 0); }
    }
    
    /* ── Status Indicator ── */
    .status-bar {
        display: flex;
        align-items: center;
        gap: 1.5rem;
        margin-top: 1rem;
        padding-top: 1rem;
        border-top: 1px solid var(--border-subtle);
        position: relative;
        z-index: 1;
    }
    
    .status-item {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 0.75rem;
        color: var(--text-muted);
    }
    
    .status-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        animation: pulse-glow 2s infinite;
    }
    
    .status-dot.active { background: var(--green-accent); }
    .status-dot.warning { background: var(--yellow-accent); }
    .status-dot.error { background: var(--red-primary); }
    
    /* ── Severity Tags ── */
    .severity-critical {
        color: #dc2626;
        font-weight: 700;
    }
    .severity-high {
        color: #ea580c;
        font-weight: 600;
    }
    .severity-medium {
        color: #eab308;
        font-weight: 500;
    }
    .severity-low {
        color: #22c55e;
        font-weight: 400;
    }
    
    /* ── Scrollbar ── */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: var(--bg-primary);
    }
    ::-webkit-scrollbar-thumb {
        background: var(--border-subtle);
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: var(--text-muted);
    }
    
    /* ── Footer ── */
    .dashboard-footer {
        text-align: center;
        padding: 2rem 0 1rem 0;
        color: var(--text-muted);
        font-size: 0.75rem;
        border-top: 1px solid var(--border-subtle);
        margin-top: 3rem;
    }
    
    .dashboard-footer .brand {
        color: var(--red-primary);
        font-weight: 700;
    }
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  PLOTLY THEME - Consistent Dark Red/Black
# ══════════════════════════════════════════════════════════════════════════════
PLOTLY_TEMPLATE = {
    "layout": {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(22,22,22,0.6)",
        "font": {"family": "Inter, sans-serif", "color": "#a3a3a3", "size": 12},
        "title": {"font": {"color": "#f5f5f5", "size": 16, "family": "Inter, sans-serif"}},
        "xaxis": {
            "gridcolor": "rgba(255,255,255,0.04)",
            "linecolor": "rgba(255,255,255,0.06)",
            "zerolinecolor": "rgba(255,255,255,0.04)",
        },
        "yaxis": {
            "gridcolor": "rgba(255,255,255,0.04)",
            "linecolor": "rgba(255,255,255,0.06)",
            "zerolinecolor": "rgba(255,255,255,0.04)",
        },
        "colorway": [
            "#dc2626", "#ef4444", "#f87171", "#991b1b",
            "#7f1d1d", "#b91c1c", "#fca5a5", "#450a0a",
            "#f5f5f5", "#a3a3a3"
        ],
        "margin": {"l": 60, "r": 20, "t": 50, "b": 40},
    }
}

SUDOSOC_COLORS = ["#dc2626", "#ef4444", "#991b1b", "#f87171", "#b91c1c", "#7f1d1d", "#fca5a5"]
SUDOSOC_RED_SCALE = [[0, "#1a0000"], [0.25, "#4a0000"], [0.5, "#991b1b"], [0.75, "#dc2626"], [1, "#ef4444"]]

def apply_chart_theme(fig):
    """Apply consistent SudoSOC dark theme to any Plotly figure."""
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(22,22,22,0.6)",
        font=dict(family="Inter, sans-serif", color="#a3a3a3", size=12),
        title_font=dict(color="#f5f5f5", size=15, family="Inter, sans-serif"),
        xaxis=dict(
            gridcolor="rgba(255,255,255,0.04)",
            linecolor="rgba(255,255,255,0.06)",
            zerolinecolor="rgba(255,255,255,0.04)",
        ),
        yaxis=dict(
            gridcolor="rgba(255,255,255,0.04)",
            linecolor="rgba(255,255,255,0.06)",
            zerolinecolor="rgba(255,255,255,0.04)",
        ),
        margin=dict(l=60, r=20, t=50, b=40),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            bordercolor="rgba(255,255,255,0.06)",
            font=dict(color="#a3a3a3", size=11),
        ),
    )
    return fig


# ---------- Helper functions ----------
@st.cache_resource
def load_model_assets():
    """Load model, scaler, metadata, and results dataframe."""
    if not os.path.exists(MODEL_PATH):
        st.error("Model files not found. Please run ids_ips_trainer.py first.")
        st.stop()

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    meta = joblib.load(META_PATH)

    df = None
    if os.path.exists(ANOMALY_CSV):
        df = pd.read_csv(ANOMALY_CSV)
    elif meta["mode"] == "supervised":
        st.warning("No annotated results CSV found. Only model predictions available.")

    return model, scaler, meta, df

def ip_to_int(ip_str: str) -> int:
    try:
        return int(ipaddress.ip_address(str(ip_str)))
    except:
        return 0

def is_private_ip(ip_str: str) -> int:
    try:
        return int(ipaddress.ip_address(str(ip_str)).is_private)
    except:
        return 0

def engineer_single_flow(flow_dict):
    """Apply the shared feature engineering from ids_ips_trainer.py."""
    df = pd.DataFrame([flow_dict])
    return engineer_features(df, verbose=False)

# ══════════════════════════════════════════════════════════════════════════════
#  HERO BANNER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="hero-banner">
    <div class="hero-badge">
        <div class="pulse"></div>
        ACTIVE MONITORING
    </div>
    <h1 class="hero-title">
        <span>SudoSOC</span> Threat Intelligence
    </h1>
    <p class="hero-subtitle">
        AI-Powered Intrusion Detection & Prevention System  |  Real-time Network Security Operations Center
    </p>
    <div class="status-bar">
        <div class="status-item">
            <div class="status-dot active"></div>
            IDS Engine
        </div>
        <div class="status-item">
            <div class="status-dot active"></div>
            ML Model
        </div>
        <div class="status-item">
            <div class="status-dot warning"></div>
            LLM Analyzer
        </div>
        <div class="status-item">
            <div class="status-dot active"></div>
            Firewall Integration
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ---------- Load assets ----------
model, scaler, meta, df_results = load_model_assets()
feature_cols = meta["feature_cols"]
mode = meta["mode"]

# ---------- Sidebar ----------
st.sidebar.markdown("""
<div style="text-align: center; padding: 1rem 0 1.5rem 0; border-bottom: 1px solid rgba(255,255,255,0.06);">
    <div style="font-size: 1.6rem; font-weight: 900; letter-spacing: -0.04em;">
        <span style="color: #dc2626;">sudo</span><span style="color: #f5f5f5;">SOC</span>
    </div>
    <div style="font-size: 0.65rem; color: #737373; text-transform: uppercase; letter-spacing: 0.15em; margin-top: 4px;">
        Security Operations
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.markdown("### System Configuration")
st.sidebar.markdown(f"**Detection Mode:** `{mode.capitalize()}`")
if mode == "unsupervised":
    st.sidebar.markdown("**Algorithm:** Isolation Forest")
else:
    algo = meta.get("model_name", "xgboost").upper()
    st.sidebar.markdown(f"**Algorithm:** `{algo}`")
st.sidebar.markdown(f"**Feature Count:** `{len(feature_cols)}`")
st.sidebar.markdown(f"**Last Updated:** `{datetime.now().strftime('%Y-%m-%d %H:%M')}`")

st.sidebar.markdown("---")
st.sidebar.markdown("### Quick Actions")
auto_refresh = st.sidebar.toggle("Auto Refresh", value=True, help="Enable automatic data refresh")
dark_charts = st.sidebar.toggle("High Contrast", value=False, help="Enhance chart contrast")

st.sidebar.markdown("---")
st.sidebar.markdown("""
<div style="padding: 0.8rem; background: rgba(220, 38, 38, 0.06); border: 1px solid rgba(220, 38, 38, 0.15); border-radius: 8px; margin-top: 0.5rem;">
    <div style="font-size: 0.7rem; color: #dc2626; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px;">
        SudoSOC 2026
    </div>
    <div style="font-size: 0.7rem; color: #737373;">
        Enterprise-grade threat detection powered by machine learning and heuristic analysis.
    </div>
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  KEY METRICS OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
if df_results is not None:
    col1, col2, col3, col4 = st.columns(4)
    total = len(df_results)
    
    if mode == "unsupervised" and "is_attack" in df_results.columns:
        attacks = df_results["is_attack"].sum()
        normal = total - attacks
        threat_rate = attacks / total if total > 0 else 0
        col1.metric("Total Flows Analyzed", f"{total:,}")
        col2.metric("Threats Detected", f"{attacks:,}", delta=f"{threat_rate:.1%} of traffic")
        col3.metric("Clean Traffic", f"{normal:,}")
        col4.metric("Threat Rate", f"{threat_rate:.2%}")
    elif mode == "supervised":
        attack_count = 0
        trusted_count = 0
        if "label" in df_results.columns:
            attack_count = (df_results["label"].str.upper().isin(["ATTACK", "ANOMALY", "MALICIOUS"])).sum()
            trusted_count = (df_results["label"].str.upper() == "TRUSTED_AGENCY").sum()
        
        threat_rate = attack_count / total if total > 0 else 0
        col1.metric("Total Flows Analyzed", f"{total:,}")
        col2.metric("Attacks Identified", f"{attack_count:,}")
        col3.metric("Trusted Agency", f"{trusted_count:,}")
        col4.metric("Threat Rate", f"{threat_rate:.2%}")
    else:
        col1.metric("Total Flows Analyzed", f"{total:,}")

# ══════════════════════════════════════════════════════════════════════════════
#  NETWORK FLOW ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("## Network Flow Analysis")

if df_results is not None:
    tab1, tab2, tab3 = st.tabs(["Distributions", "Attack Breakdown", "Model Insights"])

    with tab1:
        col_left, col_right = st.columns(2)

        with col_left:
            # Protocol distribution - donut
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_counts = df_results["protocol"].map(proto_map).fillna("Other").value_counts().reset_index()
            proto_counts.columns = ["Protocol", "Count"]
            fig = go.Figure(data=[go.Pie(
                labels=proto_counts["Protocol"],
                values=proto_counts["Count"],
                hole=0.55,
                marker=dict(colors=SUDOSOC_COLORS, line=dict(color="#0a0a0a", width=2)),
                textfont=dict(size=12, color="#f5f5f5"),
                textinfo="label+percent",
                hoverinfo="label+value+percent",
            )])
            fig.update_layout(
                title=dict(text="Protocol Distribution", font=dict(size=15, color="#f5f5f5")),
                showlegend=True,
                legend=dict(font=dict(color="#a3a3a3", size=11), bgcolor="rgba(0,0,0,0)"),
            )
            fig = apply_chart_theme(fig)
            st.plotly_chart(fig, use_container_width=True)

        with col_right:
            # Byte histogram
            fig = go.Figure(data=[go.Histogram(
                x=np.log1p(df_results["bidirectional_bytes"]),
                nbinsx=50,
                marker=dict(
                    color="#dc2626",
                    line=dict(color="#991b1b", width=0.5),
                ),
                opacity=0.85,
            )])
            fig.update_layout(
                title="Byte Volume Distribution (log scale)",
                xaxis_title="log(Bytes)",
                yaxis_title="Frequency",
                bargap=0.05,
            )
            fig = apply_chart_theme(fig)
            st.plotly_chart(fig, use_container_width=True)

        # Packet vs Bytes scatter
        st.markdown("### Packets vs Bytes Correlation")
        sample = df_results.sample(min(5000, len(df_results)), random_state=42)
        color_col = None
        scatter_colors = None
        
        if "is_attack" in df_results.columns:
            sample["Classification"] = sample["is_attack"].map({1: "Threat", 0: "Normal"})
            color_col = "Classification"
            scatter_colors = {"Threat": "#dc2626", "Normal": "#374151"}
        elif "anomaly_prediction" in df_results.columns:
            sample["Classification"] = sample["anomaly_prediction"].map({-1: "Anomaly", 1: "Normal"})
            color_col = "Classification"
            scatter_colors = {"Anomaly": "#dc2626", "Normal": "#374151"}
        elif "label" in df_results.columns:
            sample["Classification"] = sample["label"].apply(
                lambda x: "Threat" if x.upper() in ["ATTACK", "MALICIOUS", "ANOMALY"]
                else ("Trusted" if x.upper() == "TRUSTED_AGENCY" else "Normal")
            )
            color_col = "Classification"
            scatter_colors = {"Threat": "#dc2626", "Trusted": "#22c55e", "Normal": "#374151"}

        fig = px.scatter(
            sample,
            x=np.log1p(sample["bidirectional_packets"]),
            y=np.log1p(sample["bidirectional_bytes"]),
            color=color_col,
            color_discrete_map=scatter_colors,
            opacity=0.6,
            labels={"x": "log(Packets)", "y": "log(Bytes)"},
            title="Packet vs Byte Volume (sample of 5,000)",
        )
        fig = apply_chart_theme(fig)
        fig.update_traces(marker=dict(size=5, line=dict(width=0)))
        st.plotly_chart(fig, use_container_width=True)

        # Top ports
        st.markdown("### Top 10 Destination Ports")
        top_ports = df_results["dst_port"].value_counts().nlargest(10).reset_index()
        top_ports.columns = ["Port", "Count"]
        fig = go.Figure(data=[go.Bar(
            y=top_ports["Port"].astype(str),
            x=top_ports["Count"],
            orientation="h",
            marker=dict(
                color=top_ports["Count"],
                colorscale=SUDOSOC_RED_SCALE,
                line=dict(color="#0a0a0a", width=0.5),
            ),
        )])
        fig.update_layout(
            title="Most Frequent Destination Ports",
            xaxis_title="Connection Count",
            yaxis_title="Port",
            yaxis=dict(autorange="reversed"),
        )
        fig = apply_chart_theme(fig)
        st.plotly_chart(fig, use_container_width=True)

    with tab2:
        if mode == "unsupervised" and "is_attack" in df_results.columns:
            attacks_df = df_results[df_results["is_attack"] == 1]
            
            st.markdown("### Attack Source IP Analysis")
            if "src_ip" in attacks_df.columns:
                src_counts = attacks_df["src_ip"].value_counts().nlargest(10).reset_index()
                src_counts.columns = ["Source IP", "Count"]
                fig = go.Figure(data=[go.Bar(
                    y=src_counts["Source IP"],
                    x=src_counts["Count"],
                    orientation="h",
                    marker=dict(
                        color=src_counts["Count"],
                        colorscale=SUDOSOC_RED_SCALE,
                        line=dict(color="#0a0a0a", width=0.5),
                    ),
                )])
                fig.update_layout(
                    title="Top Attack Source IPs",
                    yaxis=dict(autorange="reversed"),
                )
                fig = apply_chart_theme(fig)
                st.plotly_chart(fig, use_container_width=True)

            st.markdown("### Attack Target Ports")
            port_counts = attacks_df["dst_port"].value_counts().nlargest(10).reset_index()
            port_counts.columns = ["Port", "Count"]
            fig = go.Figure(data=[go.Bar(
                y=port_counts["Port"].astype(str),
                x=port_counts["Count"],
                orientation="h",
                marker=dict(
                    color=port_counts["Count"],
                    colorscale=SUDOSOC_RED_SCALE,
                    line=dict(color="#0a0a0a", width=0.5),
                ),
            )])
            fig.update_layout(
                title="Most Targeted Ports",
                yaxis=dict(autorange="reversed"),
            )
            fig = apply_chart_theme(fig)
            st.plotly_chart(fig, use_container_width=True)

        elif mode == "supervised":
            st.info("Supervised mode - review the confusion matrix and feature importance in the Model Insights tab.")

    with tab3:
        if mode == "supervised":
            st.markdown("### Feature Importance")
            if hasattr(model, "feature_importances_"):
                imp_df = pd.DataFrame({
                    "feature": feature_cols,
                    "importance": model.feature_importances_
                }).sort_values("importance", ascending=False).head(15)
                
                fig = go.Figure(data=[go.Bar(
                    y=imp_df["feature"],
                    x=imp_df["importance"],
                    orientation="h",
                    marker=dict(
                        color=imp_df["importance"],
                        colorscale=SUDOSOC_RED_SCALE,
                        line=dict(color="#0a0a0a", width=0.5),
                    ),
                )])
                fig.update_layout(
                    title="Top 15 Feature Importances",
                    yaxis=dict(autorange="reversed"),
                    xaxis_title="Importance Score",
                )
                fig = apply_chart_theme(fig)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Feature importance not available for this model type.")

            st.info("Confusion matrix can be generated during training (see output folder).")
        else:
            st.info("Unsupervised mode - confusion matrix is not applicable.")

# ══════════════════════════════════════════════════════════════════════════════
#  LIVE IDS ALERTS
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("## Live IDS Alerts")
st.caption("Real-time threat feed from the IDS engine  |  Source: ids_alerts.jsonl")

@st.cache_data(ttl=2, show_spinner=False)
def _load_alerts_jsonl(path: str, limit: int, file_mtime: float):
    if not os.path.exists(path):
        return None
    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
        if not rows:
            return None
        df = pd.DataFrame(rows)
        # Keep last N by timestamp if present
        if "timestamp" in df.columns:
            df = df.sort_values("timestamp")
        return df.tail(limit)
    except Exception:
        return None

col_a, col_b = st.columns([3, 1])
with col_a:
    st.caption("Alert data auto-refreshes every 2 seconds when new events are detected.")
with col_b:
    limit = st.number_input("Display limit", min_value=50, max_value=2000, value=200, step=50, label_visibility="collapsed")

mtime = os.path.getmtime(ALERTS_JSONL) if os.path.exists(ALERTS_JSONL) else 0.0
alerts_df = _load_alerts_jsonl(ALERTS_JSONL, int(limit), float(mtime))
if alerts_df is None:
    st.info("No alerts recorded yet. Start the IDS engine with: python realtime_ids.py")
else:
    # Metrics row
    total_alerts = len(alerts_df)
    blocked = int(alerts_df.get("blocked", pd.Series([False]*len(alerts_df))).fillna(False).astype(bool).sum())
    critical = int((alerts_df.get("severity", "").astype(str).str.upper() == "CRITICAL").sum()) if "severity" in alerts_df.columns else 0
    high_sev = int((alerts_df.get("severity", "").astype(str).str.upper() == "HIGH").sum()) if "severity" in alerts_df.columns else 0
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Alerts", f"{total_alerts:,}")
    m2.metric("Blocked", f"{blocked:,}")
    m3.metric("Critical Severity", f"{critical:,}")
    m4.metric("High Severity", f"{high_sev:,}")

    show_cols = [c for c in ["timestamp","severity","attack_type","src_ip","src_port","dst_ip","dst_port","proto","confidence","heuristic_confidence","ml_confidence","genai_confidence","blocked","llm_summary","rule"] if c in alerts_df.columns]
    disp_df = alerts_df[show_cols].copy()
    rename_dict = {
        "timestamp": "Timestamp",
        "severity": "Severity",
        "attack_type": "Attack Type",
        "src_ip": "Source IP",
        "src_port": "Src Port",
        "dst_ip": "Dest IP",
        "dst_port": "Dst Port",
        "proto": "Protocol",
        "confidence": "Hybrid Conf",
        "heuristic_confidence": "Heur Conf",
        "ml_confidence": "ML Conf",
        "genai_confidence": "GenAI Conf",
        "blocked": "Blocked",
        "llm_summary": "GenAI Threat Summary",
        "rule": "Trigger Rule"
    }
    present_rename = {k: v for k, v in rename_dict.items() if k in disp_df.columns}
    disp_df = disp_df.rename(columns=present_rename)
    for col_name in ["Hybrid Conf", "Heur Conf", "ML Conf", "GenAI Conf"]:
        if col_name in disp_df.columns:
            disp_df[col_name] = disp_df[col_name].apply(lambda x: f"{x * 100:.0f}%" if pd.notnull(x) else "0%")
    st.dataframe(disp_df, use_container_width=True, hide_index=True)

    # Real-time trend charts
    try:
        gdf = alerts_df.copy()
        if "timestamp" in gdf.columns:
            gdf["ts"] = pd.to_datetime(gdf["timestamp"], errors="coerce")
            gdf = gdf.dropna(subset=["ts"])
            if len(gdf) > 0:
                st.markdown("### Real-Time Alert Trends")
                window_mins = st.slider("Analysis Window (minutes)", min_value=1, max_value=120, value=15, step=1)
                cutoff = pd.Timestamp.utcnow() - pd.Timedelta(minutes=int(window_mins))
                gdfw = gdf[gdf["ts"] >= cutoff].copy()
                if len(gdfw) == 0:
                    gdfw = gdf.tail(200).copy()

                # Alerts per minute
                gdfw["minute"] = gdfw["ts"].dt.floor("min")
                per_min = gdfw.groupby(["minute", gdfw.get("severity", pd.Series(["UNKNOWN"]*len(gdfw))).astype(str)]) \
                             .size().reset_index(name="count")
                per_min.columns = ["minute", "severity", "count"]
                
                severity_colors = {
                    "CRITICAL": "#dc2626",
                    "HIGH": "#ef4444",
                    "MEDIUM": "#eab308",
                    "LOW": "#22c55e",
                    "UNKNOWN": "#6b7280",
                }
                
                fig1 = px.line(
                    per_min, x="minute", y="count", color="severity",
                    markers=True, title="Alerts per Minute by Severity",
                    color_discrete_map=severity_colors,
                )
                fig1.update_traces(line=dict(width=2), marker=dict(size=6))
                fig1 = apply_chart_theme(fig1)
                st.plotly_chart(fig1, use_container_width=True)

                # Response tier distribution
                if "response_tier" in gdfw.columns:
                    tier_counts = gdfw["response_tier"].astype(str).value_counts().reset_index()
                    tier_counts.columns = ["response_tier", "count"]
                    fig2 = go.Figure(data=[go.Bar(
                        y=tier_counts["response_tier"],
                        x=tier_counts["count"],
                        orientation="h",
                        marker=dict(
                            color=tier_counts["count"],
                            colorscale=SUDOSOC_RED_SCALE,
                        ),
                    )])
                    fig2.update_layout(title="Response Actions (Recent Window)")
                    fig2 = apply_chart_theme(fig2)
                    st.plotly_chart(fig2, use_container_width=True)

                # Confidence histogram
                if "confidence" in gdfw.columns:
                    fig3 = go.Figure(data=[go.Histogram(
                        x=gdfw["confidence"],
                        nbinsx=20,
                        marker=dict(color="#dc2626", line=dict(color="#991b1b", width=0.5)),
                        opacity=0.85,
                    )])
                    fig3.update_layout(
                        title="Detection Confidence Distribution",
                        xaxis_title="Confidence Score",
                        yaxis_title="Alert Count",
                    )
                    fig3 = apply_chart_theme(fig3)
                    st.plotly_chart(fig3, use_container_width=True)
    except Exception:
        pass

    # Payload viewer
    if "payload_sample_text" in alerts_df.columns or "payload_sample_b64" in alerts_df.columns:
        with st.expander("Payload Inspector - View raw payload data for selected alert"):
            _a = alerts_df.copy()
            if "timestamp" in _a.columns:
                _a = _a.sort_values("timestamp", ascending=False)
            _a = _a.head(500)

            def _row_label2(r):
                ts = str(r.get("timestamp", ""))[:19]
                atk = str(r.get("attack_type", ""))
                src = f"{r.get('src_ip','?')}:{r.get('src_port','?')}"
                dst = f"{r.get('dst_ip','?')}:{r.get('dst_port','?')}"
                return f"{ts}  {atk}  {src} -> {dst}"

            options2 = list(range(len(_a)))
            labels2 = [_row_label2(_a.iloc[i]) for i in options2]
            sel2 = st.selectbox("Select alert to inspect payload", options=options2, format_func=lambda i: labels2[i])
            rr = _a.iloc[int(sel2)].to_dict()
            st.caption("Payload is truncated (first ~512 bytes) and sanitized for display.")
            if "payload_sample_text" in rr and str(rr.get("payload_sample_text", "")).strip():
                st.code(str(rr.get("payload_sample_text", "")), language="text")
            if "payload_sample_b64" in rr and str(rr.get("payload_sample_b64", "")).strip():
                st.text_area("Base64 encoded payload", value=str(rr.get("payload_sample_b64", "")), height=120)

# ══════════════════════════════════════════════════════════════════════════════
#  REAL-TIME FLOW PREDICTION
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("## Real-Time Flow Prediction")
st.markdown("Submit flow parameters for instant classification by the trained model.")

with st.form("prediction_form"):
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("##### Source / Destination")
        src_ip = st.text_input("Source IP", "192.168.1.100")
        dst_ip = st.text_input("Destination IP", "8.8.8.8")
        src_port = st.number_input("Source Port", 0, 65535, 54321)
        dst_port = st.number_input("Destination Port", 0, 65535, 80)
    with col2:
        st.markdown("##### Flow Characteristics")
        protocol = st.selectbox("Protocol", options=[("TCP", 6), ("UDP", 17), ("ICMP", 1)], format_func=lambda x: x[0])
        packets = st.number_input("Bidirectional Packets", 0, 1000000, 20)
        bytes_ = st.number_input("Bidirectional Bytes", 0, 1000000000, 8000)
        duration_ms = st.number_input("Duration (ms)", 0.0, 3600000.0, 350.0, step=100.0)
        payload_entropy = st.slider("Payload Entropy", 0.0, 8.0, 0.0)
        payload_len_var = st.slider("Payload Length Variance", 0.0, 10000.0, 0.0)
        is_high_volume = st.checkbox("Force High Volume Flag", False)

    submitted = st.form_submit_button("ANALYZE FLOW")

if submitted:
    flow = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol[1],
        "bidirectional_packets": packets,
        "bidirectional_bytes": bytes_,
        "bidirectional_duration_ms": duration_ms,
        "payload_entropy": payload_entropy,
        "payload_len_var": payload_len_var,
        "is_high_volume": int(is_high_volume)
    }
    # Engineer features
    df_flow = engineer_single_flow(flow)
    X = df_flow[feature_cols].fillna(0)
    X_scaled = scaler.transform(X)

    if mode == "unsupervised":
        pred = model.predict(X_scaled)[0]
        score = model.score_samples(X_scaled)[0]
        if pred == -1:
            st.error(f"THREAT DETECTED  |  Anomaly Score: {score:.3f}")
        else:
            st.success(f"NORMAL TRAFFIC  |  Anomaly Score: {score:.3f}")
    else:
        proba = model.predict_proba(X_scaled)[0]
        idx = int(np.argmax(proba))
        label = meta["label_encoder"].inverse_transform([idx])[0]
        conf = proba[idx]
        if label.upper() not in {"NORMAL", "BENIGN"}:
            st.error(f"THREAT: {label}  |  Confidence: {conf:.2%}")
        else:
            st.success(f"VERDICT: {label}  |  Confidence: {conf:.2%}")
        # Show all class probabilities
        prob_df = pd.DataFrame({
            "Class": meta["label_encoder"].classes_,
            "Probability": proba
        }).sort_values("Probability", ascending=False)
        
        fig = go.Figure(data=[go.Bar(
            y=prob_df["Class"],
            x=prob_df["Probability"],
            orientation="h",
            marker=dict(
                color=prob_df["Probability"],
                colorscale=SUDOSOC_RED_SCALE,
                line=dict(color="#0a0a0a", width=0.5),
            ),
        )])
        fig.update_layout(
            title="Prediction Probability Distribution",
            xaxis_title="Probability",
            yaxis=dict(autorange="reversed"),
        )
        fig = apply_chart_theme(fig)
        st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# ══════════════════════════════════════════════════════════════════════════════
#  ADAPTIVE SECURITY INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("## Adaptive Security Intelligence")

tab_ol, tab_mitre, tab_rules, tab_enc = st.tabs([
    "Online Learning", "MITRE ATT&CK", "Detection Rules", "Encrypted Traffic"
])

# ---------- Online Learning Tab ----------
with tab_ol:
    st.markdown("### Online Learning & Drift Status")

    col_a, col_b, col_c = st.columns(3)

    # Show last retrain info from metadata
    last_retrain = meta.get("last_retrain", "Never")
    retrain_type = meta.get("retrain_type", "batch")
    sample_count = meta.get("sample_count", 0)
    col_a.metric("Last Retrain", str(last_retrain)[:19])
    col_b.metric("Retrain Type", retrain_type)
    col_c.metric("Training Samples", f"{sample_count:,}")

    # Feedback file stats
    feedback_path = "data/online_learning.csv"
    if os.path.exists(feedback_path):
        try:
            fb_df = pd.read_csv(feedback_path)
            st.metric("Pending Feedback Samples", len(fb_df))
            if len(fb_df) > 0:
                st.dataframe(fb_df.tail(20), use_container_width=True, hide_index=True)
        except Exception:
            st.info("No feedback data available yet.")
    else:
        st.info("No feedback file found. Feedback will be collected during IDS operation.")

    st.markdown("---")
    st.markdown("### Interactive Simulation & Training Control Plane")
    st.caption("Control live threat simulations and trigger model retraining directly from the dashboard.")
    
    col_sim1, col_sim2, col_sim3 = st.columns(3)
    
    with col_sim1:
        if st.button("RUN SCENARIOS & RETRAIN"):
            with st.spinner("Executing Scenario Harness & XGBoost Retraining..."):
                try:
                    import subprocess
                    import sys
                    proc = subprocess.run([sys.executable, "test_scenarios.py"], capture_output=True, text=True, timeout=300)
                    if proc.returncode == 0:
                        st.success("Retraining complete!")
                        st.text_area("Console Output", value=proc.stdout, height=200)
                    else:
                        st.error(f"Retraining failed (Exit {proc.returncode})")
                        st.text_area("Console Error", value=proc.stderr, height=200)
                except Exception as e:
                    st.error(f"Error: {e}")
                    
    with col_sim2:
        if st.button("TRIGGER LIVE ATTACKS"):
            try:
                import subprocess
                import sys
                subprocess.Popen([sys.executable, "attack_test_suite.py", "--target", "127.0.0.1", "--intensity", "medium"])
                st.success("Live Attack Suite launched in background!")
            except Exception as e:
                st.error(f"Error starting simulation: {e}")
                
    with col_sim3:
        if st.button("TRIGGER LIVE OBFUSCATED"):
            try:
                import subprocess
                import sys
                subprocess.Popen([sys.executable, "wired_attack_sim.py", "--target", "127.0.0.1", "--attack", "2", "--repeat", "3"])
                st.success("Obfuscated Attack Sim launched in background!")
            except Exception as e:
                st.error(f"Error starting simulation: {e}")
                
    # Display the latest confidence report if available
    report_path = "test_results/confidence_report.md"
    if os.path.exists(report_path):
        with st.expander("View Latest Scenario Confidence Report", expanded=False):
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    st.markdown(f.read())
            except Exception as e:
                st.error(f"Could not load report: {e}")

    st.markdown("---")
    st.markdown("### Manual Alert Feedback")
    st.caption("Select an alert and mark it as False Positive (NORMAL) or True Positive (confirm). This reduces false positives in future detections.")

    if alerts_df is None or len(alerts_df) == 0:
        st.info("No recent alerts available to label yet.")
    else:
        # Keep a stable, recent view
        _alerts = alerts_df.copy()
        if "timestamp" in _alerts.columns:
            _alerts = _alerts.sort_values("timestamp", ascending=False)
        _alerts = _alerts.head(500)

        # Show a compact pick-list
        pick_cols = [c for c in ["timestamp", "severity", "attack_type", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "confidence", "rule"] if c in _alerts.columns]
        st.dataframe(_alerts[pick_cols].head(50), use_container_width=True, hide_index=True)

        # Build selection labels
        def _row_label(r):
            ts = str(r.get("timestamp", ""))[:19]
            atk = str(r.get("attack_type", ""))
            src = f"{r.get('src_ip','?')}:{r.get('src_port','?')}"
            dst = f"{r.get('dst_ip','?')}:{r.get('dst_port','?')}"
            sev = str(r.get("severity", ""))
            return f"{ts}  [{sev}]  {atk}  {src} -> {dst}"

        options = list(range(len(_alerts)))
        labels = [_row_label(_alerts.iloc[i]) for i in options]
        sel = st.selectbox("Pick an alert to label", options=options, format_func=lambda i: labels[i])

        verdict = st.radio("Your verdict", options=["False Positive (NORMAL)", "True Positive (confirm)"], horizontal=True)
        notes = st.text_input("Notes (optional)", "")

        if st.button("Submit Feedback"):
            r = _alerts.iloc[int(sel)].to_dict()
            # Convert proto text to numeric protocol for the trainer schema
            proto_name = str(r.get("proto", "")).upper().strip()
            proto_num = 6 if proto_name == "TCP" else 17 if proto_name == "UDP" else 1 if proto_name == "ICMP" else 0

            # Build a minimal flow feature row compatible with `data/online_learning.csv`
            try:
                dur_ms = float(r.get("bidirectional_duration_ms", 0.0) or 0.0)
            except Exception:
                dur_ms = 0.0
            try:
                ent = float(r.get("payload_entropy", 0.0) or 0.0)
            except Exception:
                ent = 0.0
            try:
                pvar = float(r.get("payload_len_var", 0.0) or 0.0)
            except Exception:
                pvar = 0.0

            flow_features = {
                "src_ip": r.get("src_ip", ""),
                "dst_ip": r.get("dst_ip", ""),
                "src_port": int(r.get("src_port", 0) or 0),
                "dst_port": int(r.get("dst_port", 0) or 0),
                "protocol": int(proto_num),
                "bidirectional_packets": int(r.get("pkt_count", 0) or 0),
                "bidirectional_bytes": int(r.get("byte_count", 0) or 0),
                "bidirectional_duration_ms": dur_ms,
                "payload_entropy": ent,
                "payload_len_var": pvar,
                "is_high_volume": int(int(r.get("byte_count", 0) or 0) > 1_000_000),
            }

            original_label = str(r.get("attack_type", "UNKNOWN")).upper().strip() or "UNKNOWN"
            alert_rule = str(r.get("rule", ""))[:200]

            fc = FeedbackCollector(feedback_path=feedback_path)
            if verdict.startswith("False"):
                fc.record_false_positive(flow_features, original_label=original_label, alert_rule=alert_rule)
                st.success("Recorded: False Positive -- NORMAL. Future detections for this pattern will be suppressed.")
            else:
                fc.record_true_positive(flow_features, original_label=original_label, alert_rule=alert_rule)
                st.success("Recorded: True Positive confirmation. Pattern reinforced.")

        st.markdown("---")
        st.markdown("### Manual Response: Isolate / Release")
        st.caption("Override engine decisions. Actions require the IDS engine running as Administrator.")

        # Action uses the same selected alert row `sel`
        r_act = _alerts.iloc[int(sel)].to_dict()
        src_ip_act = str(r_act.get("src_ip", "")).strip()
        reason_default = f"{r_act.get('attack_type','?')} {r_act.get('rule','')}".strip()[:180]
        action_reason = st.text_input("Reason", value=reason_default)

        colx, coly = st.columns(2)
        with colx:
            if st.button("ISOLATE SOURCE IP"):
                os.makedirs(os.path.dirname(MANUAL_ACTIONS_JSONL) or ".", exist_ok=True)
                evt = {
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "action": "ISOLATE",
                    "src_ip": src_ip_act,
                    "reason": action_reason,
                }
                with open(MANUAL_ACTIONS_JSONL, "a", encoding="utf-8") as f:
                    f.write(json.dumps(evt, ensure_ascii=False) + "\n")
                st.success(f"Isolation request queued for {src_ip_act}.")
        with coly:
            if st.button("RELEASE SOURCE IP"):
                os.makedirs(os.path.dirname(MANUAL_ACTIONS_JSONL) or ".", exist_ok=True)
                evt = {
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "action": "RELEASE",
                    "src_ip": src_ip_act,
                    "reason": action_reason,
                }
                with open(MANUAL_ACTIONS_JSONL, "a", encoding="utf-8") as f:
                    f.write(json.dumps(evt, ensure_ascii=False) + "\n")
                st.success(f"Release request queued for {src_ip_act}.")

    # Drift reference info
    ref_path = os.path.join(OUTPUT_DIR, "reference_dist.pkl")
    if os.path.exists(ref_path):
        st.success("Drift reference distribution loaded")
        try:
            ref = joblib.load(ref_path)
            st.caption(f"Monitoring {len(ref)} features: {', '.join(list(ref.keys())[:8])}...")
        except Exception:
            pass
    else:
        st.warning("No drift reference available. Will be built from first live session.")

    # Model snapshots
    snap_dir = os.path.join(OUTPUT_DIR, "snapshots")
    if os.path.exists(snap_dir):
        snaps = sorted([f for f in os.listdir(snap_dir) if f.endswith(".pkl")])
        st.metric("Model Snapshots", len(snaps) // 3)  # 3 files per snapshot

# ---------- MITRE ATT&CK Tab ----------
with tab_mitre:
    st.markdown("### MITRE ATT&CK Coverage Map")

    if alerts_df is not None and "mitre_tactic" in alerts_df.columns:
        mitre_data = alerts_df[alerts_df["mitre_tactic"].astype(str).str.len() > 2]
        if len(mitre_data) > 0:
            tactic_counts = mitre_data["mitre_tactic"].value_counts().reset_index()
            tactic_counts.columns = ["Tactic", "Count"]
            fig = go.Figure(data=[go.Bar(
                y=tactic_counts["Tactic"],
                x=tactic_counts["Count"],
                orientation="h",
                marker=dict(
                    color=tactic_counts["Count"],
                    colorscale=SUDOSOC_RED_SCALE,
                    line=dict(color="#0a0a0a", width=0.5),
                ),
            )])
            fig.update_layout(
                title="Alerts per MITRE ATT&CK Tactic",
                yaxis=dict(autorange="reversed"),
            )
            fig = apply_chart_theme(fig)
            st.plotly_chart(fig, use_container_width=True)

            if "mitre_technique" in mitre_data.columns:
                tech_counts = mitre_data["mitre_technique"].value_counts().head(15).reset_index()
                tech_counts.columns = ["Technique", "Count"]
                fig2 = go.Figure(data=[go.Bar(
                    y=tech_counts["Technique"],
                    x=tech_counts["Count"],
                    orientation="h",
                    marker=dict(
                        color=tech_counts["Count"],
                        colorscale=SUDOSOC_RED_SCALE,
                        line=dict(color="#0a0a0a", width=0.5),
                    ),
                )])
                fig2.update_layout(
                    title="Top 15 MITRE Techniques Detected",
                    yaxis=dict(autorange="reversed"),
                )
                fig2 = apply_chart_theme(fig2)
                st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No MITRE-tagged alerts yet.")
    else:
        st.info("MITRE ATT&CK mapping will appear once alerts with MITRE tags are generated.")

    # Show the mapping table
    with st.expander("Built-in MITRE Mapping Table"):
        try:
            from llm_analyzer import MITRE_MAP
            mitre_df = pd.DataFrame([
                {"Attack Type": k, "Tactic": v["tactic"], "Tactic Name": v["tactic_name"],
                 "Technique": v["technique"], "Technique Name": v["technique_name"]}
                for k, v in MITRE_MAP.items()
            ])
            st.dataframe(mitre_df, use_container_width=True, hide_index=True)
        except Exception:
            st.info("MITRE mapping table not available.")

# ---------- Generated Rules Tab ----------
with tab_rules:
    st.markdown("### Auto-Generated Detection Rules")

    sigma_dir = "rules/sigma"
    suricata_dir = "rules/suricata"

    col_s, col_r = st.columns(2)

    with col_s:
        st.markdown("#### Sigma Rules")
        if os.path.exists(sigma_dir):
            sigma_files = sorted([f for f in os.listdir(sigma_dir) if f.endswith(".yml")])
            st.metric("Sigma Rules", len(sigma_files))
            for sf in sigma_files[-5:]:  # Show last 5
                with st.expander(sf):
                    try:
                        with open(os.path.join(sigma_dir, sf), "r") as fh:
                            st.code(fh.read(), language="yaml")
                    except Exception:
                        st.error("Could not read rule file.")
        else:
            st.info("No Sigma rules generated yet.")

    with col_r:
        st.markdown("#### Suricata Rules")
        if os.path.exists(suricata_dir):
            sur_files = sorted([f for f in os.listdir(suricata_dir) if f.endswith(".rules")])
            st.metric("Suricata Rules", len(sur_files))
            for rf in sur_files[-5:]:
                with st.expander(rf):
                    try:
                        with open(os.path.join(suricata_dir, rf), "r") as fh:
                            st.code(fh.read(), language="text")
                    except Exception:
                        st.error("Could not read rule file.")
        else:
            st.info("No Suricata rules generated yet.")

# ---------- Encrypted Traffic Tab ----------
with tab_enc:
    st.markdown("### Encrypted Traffic Analysis")

    dec_path = "decrypted_flows.jsonl"
    if os.path.exists(dec_path) and os.path.getsize(dec_path) > 0:
        try:
            dec_rows = []
            with open(dec_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            dec_rows.append(json.loads(line))
                        except Exception:
                            pass

            if dec_rows:
                dec_df = pd.DataFrame(dec_rows[-500:])  # Last 500

                col1, col2, col3 = st.columns(3)
                col1.metric("Decrypted Flows", f"{len(dec_rows):,}")
                if "is_https" in dec_df.columns:
                    col2.metric("HTTPS Flows", int(dec_df["is_https"].sum()))
                if "payload_entropy" in dec_df.columns:
                    col3.metric("Avg Entropy", f"{dec_df['payload_entropy'].mean():.2f}")

                # TLS version distribution
                if "tls_version" in dec_df.columns:
                    tls_counts = dec_df["tls_version"].value_counts().head(5).reset_index()
                    tls_counts.columns = ["TLS Version", "Count"]
                    fig = go.Figure(data=[go.Pie(
                        labels=tls_counts["TLS Version"],
                        values=tls_counts["Count"],
                        hole=0.55,
                        marker=dict(colors=SUDOSOC_COLORS, line=dict(color="#0a0a0a", width=2)),
                        textfont=dict(size=12, color="#f5f5f5"),
                    )])
                    fig.update_layout(title="TLS Version Distribution")
                    fig = apply_chart_theme(fig)
                    st.plotly_chart(fig, use_container_width=True)

                # Top hosts
                if "host" in dec_df.columns:
                    host_counts = dec_df["host"].value_counts().head(15).reset_index()
                    host_counts.columns = ["Host", "Count"]
                    fig = go.Figure(data=[go.Bar(
                        y=host_counts["Host"],
                        x=host_counts["Count"],
                        orientation="h",
                        marker=dict(
                            color=host_counts["Count"],
                            colorscale=SUDOSOC_RED_SCALE,
                            line=dict(color="#0a0a0a", width=0.5),
                        ),
                    )])
                    fig.update_layout(
                        title="Top 15 Decrypted Hosts",
                        yaxis=dict(autorange="reversed"),
                    )
                    fig = apply_chart_theme(fig)
                    st.plotly_chart(fig, use_container_width=True)

                # Recent flows table
                show_cols = [c for c in ["timestamp", "host", "method", "status_code",
                             "payload_entropy", "bidirectional_bytes", "sni", "tls_version"]
                             if c in dec_df.columns]
                st.dataframe(dec_df[show_cols].tail(50), use_container_width=True, hide_index=True)
            else:
                st.info("Decrypted flows file exists but is empty.")
        except Exception as e:
            st.error(f"Error reading decrypted flows: {e}")
    else:
        st.info("No decrypted flows yet. Start the IDS engine to auto-deploy the sniffer.")
        st.markdown("""
        **Setup steps:**
        1. Install mitmproxy: `pip install mitmproxy`
        2. Install the mitmproxy CA cert on your device
        3. The IDS engine will auto-start the sniffer
        """)

# ---------- Response Tier Distribution ----------
if alerts_df is not None and "response_tier" in alerts_df.columns:
    st.markdown("## Adaptive Response Distribution")
    tier_counts = alerts_df["response_tier"].value_counts().reset_index()
    tier_counts.columns = ["Response Tier", "Count"]
    color_map = {"AUTO_BLOCK": "#dc2626", "ISOLATE": "#ef4444",
                 "RATE_LIMIT": "#eab308", "LOG": "#22c55e"}
    fig = go.Figure(data=[go.Pie(
        labels=tier_counts["Response Tier"],
        values=tier_counts["Count"],
        hole=0.55,
        marker=dict(
            colors=[color_map.get(t, "#6b7280") for t in tier_counts["Response Tier"]],
            line=dict(color="#0a0a0a", width=2),
        ),
        textfont=dict(size=12, color="#f5f5f5"),
        textinfo="label+percent",
    )])
    fig.update_layout(title="Response Actions Taken")
    fig = apply_chart_theme(fig)
    st.plotly_chart(fig, use_container_width=True)

# ══════════════════════════════════════════════════════════════════════════════
#  FOOTER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="dashboard-footer">
    <span class="brand">SudoSOC</span> &mdash; AI-Powered Adaptive IDS/IPS  |  Security Operations Center  |  2026
</div>
""", unsafe_allow_html=True)