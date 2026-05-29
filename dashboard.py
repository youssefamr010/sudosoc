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

st.set_page_config(page_title="IDS/IPS Dashboard", layout="wide")
st.title("🛡️ AI‑Powered IDS/IPS Dashboard")

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

# 

# ---------- Load assets ----------
model, scaler, meta, df_results = load_model_assets()
feature_cols = meta["feature_cols"]
mode = meta["mode"]

# ---------- Sidebar ----------
st.sidebar.header("ℹ️ About")
st.sidebar.markdown(f"**Mode:** {mode.capitalize()}")
if mode == "unsupervised":
    st.sidebar.markdown("**Algorithm:** Isolation Forest")
else:
    algo = meta.get("model_name", "xgboost").upper()
    st.sidebar.markdown(f"**Algorithm:** {algo}")
st.sidebar.markdown(f"**Features used:** {len(feature_cols)}")

# ---------- Main dashboard ----------
if df_results is not None:
    col1, col2, col3 = st.columns(3)
    total = len(df_results)
    if mode == "unsupervised" and "is_attack" in df_results.columns:
        attacks = df_results["is_attack"].sum()
        normal = total - attacks
        col1.metric("Total Flows", f"{total:,}")
        col2.metric("🚨 Attacks", f"{attacks:,}", delta=f"{attacks/total:.1%}")
        col3.metric("✅ Normal", f"{normal:,}")
    elif mode == "supervised":
        attack_count = 0
        trusted_count = 0
        if "label" in df_results.columns:
            attack_count = (df_results["label"].str.upper().isin(["ATTACK", "ANOMALY", "MALICIOUS"])).sum()
            trusted_count = (df_results["label"].str.upper() == "TRUSTED_AGENCY").sum()
        
        col1.metric("Total Flows", f"{total:,}")
        col2.metric(" Attacks", f"{attack_count:,}")
        col3.metric(" Trusted Agency", f"{trusted_count:,}")
    else:
        col1.metric("Total Flows", f"{total:,}")

# ---------- Charts ----------
st.header("📊 Network Flow Analysis")

if df_results is not None:
    tab1, tab2, tab3 = st.tabs(["📈 Distributions", "🔍 Attack Breakdown", "📉 Model Insights"])

    with tab1:
        col_left, col_right = st.columns(2)

        with col_left:
            # Protocol pie
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_counts = df_results["protocol"].map(proto_map).fillna("Other").value_counts().reset_index()
            proto_counts.columns = ["Protocol", "Count"]
            fig = px.pie(proto_counts, values="Count", names="Protocol",
                         title="Protocol Distribution", hole=0.4)
            st.plotly_chart(fig, use_container_width=True)

        with col_right:
            # Byte histogram (log)
            fig = px.histogram(df_results, x=np.log1p(df_results["bidirectional_bytes"]),
                               nbins=50, title="Byte Volume (log scale)",
                               labels={"value": "log(Bytes)"})
            fig.update_layout(bargap=0.1)
            st.plotly_chart(fig, use_container_width=True)

        # Packet vs Bytes scatter
        st.subheader("Packets vs Bytes")
        sample = df_results.sample(min(5000, len(df_results)), random_state=42)
        color_col = None
        if "is_attack" in df_results.columns:
            sample["Attack"] = sample["is_attack"].map({1: "Attack", 0: "Normal"})
            color_col = "Attack"
        elif "anomaly_prediction" in df_results.columns:
            sample["Anomaly"] = sample["anomaly_prediction"].map({-1: "Anomaly", 1: "Normal"})
            color_col = "Anomaly"
        elif "label" in df_results.columns:
            sample["LabelType"] = sample["label"].apply(lambda x: "Attack" if x.upper() in ["ATTACK", "MALICIOUS", "ANOMALY"] else ("Trusted" if x.upper() == "TRUSTED_AGENCY" else "Normal"))
            color_col = "LabelType"

        fig = px.scatter(sample, x=np.log1p(sample["bidirectional_packets"]),
                         y=np.log1p(sample["bidirectional_bytes"]),
                         color=color_col, opacity=0.5,
                         labels={"x": "log(Packets)", "y": "log(Bytes)"},
                         title="Packet vs Byte Volume (sample of 5,000)")
        st.plotly_chart(fig, use_container_width=True)

        # Top ports
        st.subheader("Top 10 Destination Ports")
        top_ports = df_results["dst_port"].value_counts().nlargest(10).reset_index()
        top_ports.columns = ["Port", "Count"]
        fig = px.bar(top_ports, x="Count", y="Port", orientation='h',
                     title="Most Frequent Destination Ports")
        st.plotly_chart(fig, use_container_width=True)

    with tab2:
        if mode == "unsupervised" and "is_attack" in df_results.columns:
            attacks_df = df_results[df_results["is_attack"] == 1]
            st.subheader("Attack Source IPs")
            if "src_ip" in attacks_df.columns:
                src_counts = attacks_df["src_ip"].value_counts().nlargest(10).reset_index()
                src_counts.columns = ["Source IP", "Count"]
                fig = px.bar(src_counts, x="Count", y="Source IP", orientation='h')
                st.plotly_chart(fig, use_container_width=True)

            st.subheader("Attack Destination Ports")
            port_counts = attacks_df["dst_port"].value_counts().nlargest(10).reset_index()
            port_counts.columns = ["Port", "Count"]
            fig = px.bar(port_counts, x="Count", y="Port", orientation='h')
            st.plotly_chart(fig, use_container_width=True)

        elif mode == "supervised":
            st.info("Supervised mode – see confusion matrix and feature importance in the next tab.")

    with tab3:
        if mode == "supervised":
            # Show confusion matrix if we have y_test and predictions
            # Not stored in CSV; we can optionally load from metadata if saved.
            # For simplicity, we'll show feature importance if available.
            st.subheader("Feature Importance")
            if hasattr(model, "feature_importances_"):
                imp_df = pd.DataFrame({
                    "feature": feature_cols,
                    "importance": model.feature_importances_
                }).sort_values("importance", ascending=False).head(15)
                fig = px.bar(imp_df, x="importance", y="feature", orientation='h',
                             title="Top 15 Feature Importances")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Feature importance not available for this model.")

            # Confusion matrix placeholder (would need test set)
            st.info("Confusion matrix can be generated during training (see output folder).")
        else:
            st.info("Unsupervised mode – no confusion matrix available.")

# ---------- Live Alerts (Real-time IDS) ----------
st.header("🚨 Live IDS Alerts (Real-time Engine)")
st.caption("Reads from `ids_alerts.jsonl` produced by `python realtime_ids.py`.")

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

col_a, col_b, col_c = st.columns([1, 1, 2])
with col_a:
    st.caption("Updates every ~2s when `ids_alerts.jsonl` changes.")
with col_b:
    limit = st.number_input("Rows", min_value=50, max_value=2000, value=200, step=50)
with col_c:
    st.write("If you don’t see alerts: run the engine as Administrator and generate traffic from another device.")

mtime = os.path.getmtime(ALERTS_JSONL) if os.path.exists(ALERTS_JSONL) else 0.0
alerts_df = _load_alerts_jsonl(ALERTS_JSONL, int(limit), float(mtime))
if alerts_df is None:
    st.info("No alerts yet (or `ids_alerts.jsonl` not found).")
else:
    # Metrics
    total_alerts = len(alerts_df)
    blocked = int(alerts_df.get("blocked", pd.Series([False]*len(alerts_df))).fillna(False).astype(bool).sum())
    critical = int((alerts_df.get("severity", "").astype(str).str.upper() == "CRITICAL").sum()) if "severity" in alerts_df.columns else 0
    m1, m2, m3 = st.columns(3)
    m1.metric("Recent Alerts", f"{total_alerts:,}")
    m2.metric("Blocked", f"{blocked:,}")
    m3.metric("Critical", f"{critical:,}")

    show_cols = [c for c in ["timestamp","severity","attack_type","src_ip","src_port","dst_ip","dst_port","proto","confidence","blocked","llm_summary","rule"] if c in alerts_df.columns]
    st.dataframe(alerts_df[show_cols], use_container_width=True, hide_index=True)

    # ── Real-time graphs (auto-refresh via alerts cache ttl) ─────────────────
    try:
        gdf = alerts_df.copy()
        if "timestamp" in gdf.columns:
            gdf["ts"] = pd.to_datetime(gdf["timestamp"], errors="coerce")
            gdf = gdf.dropna(subset=["ts"])
            if len(gdf) > 0:
                st.subheader("📈 Real-time alert trends (recent window)")
                window_mins = st.slider("Window (minutes)", min_value=1, max_value=120, value=15, step=1)
                cutoff = pd.Timestamp.utcnow() - pd.Timedelta(minutes=int(window_mins))
                gdfw = gdf[gdf["ts"] >= cutoff].copy()
                if len(gdfw) == 0:
                    gdfw = gdf.tail(200).copy()

                # Alerts per minute
                gdfw["minute"] = gdfw["ts"].dt.floor("min")
                per_min = gdfw.groupby(["minute", gdfw.get("severity", pd.Series(["UNKNOWN"]*len(gdfw))).astype(str)]) \
                             .size().reset_index(name="count")
                per_min.columns = ["minute", "severity", "count"]
                fig1 = px.line(per_min, x="minute", y="count", color="severity",
                               markers=True, title="Alerts per minute by severity")
                st.plotly_chart(fig1, use_container_width=True)

                # Response tier distribution
                if "response_tier" in gdfw.columns:
                    tier_counts = gdfw["response_tier"].astype(str).value_counts().reset_index()
                    tier_counts.columns = ["response_tier", "count"]
                    fig2 = px.bar(tier_counts, x="count", y="response_tier", orientation="h",
                                  title="Response actions (recent)")
                    st.plotly_chart(fig2, use_container_width=True)

                # Confidence histogram (recent)
                if "confidence" in gdfw.columns:
                    fig3 = px.histogram(gdfw, x="confidence", nbins=20, title="Confidence distribution (recent)")
                    st.plotly_chart(fig3, use_container_width=True)
    except Exception:
        pass

    # Payload viewer (if engine provides payload sample)
    if "payload_sample_text" in alerts_df.columns or "payload_sample_b64" in alerts_df.columns:
        with st.expander("🔎 View payload sample for a selected alert"):
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
            sel2 = st.selectbox("Pick an alert to inspect payload", options=options2, format_func=lambda i: labels2[i])
            rr = _a.iloc[int(sel2)].to_dict()
            st.caption("Payload is truncated (first ~512 bytes) and sanitized.")
            if "payload_sample_text" in rr and str(rr.get("payload_sample_text", "")).strip():
                st.code(str(rr.get("payload_sample_text", "")), language="text")
            if "payload_sample_b64" in rr and str(rr.get("payload_sample_b64", "")).strip():
                st.text_area("Base64 (first bytes)", value=str(rr.get("payload_sample_b64", "")), height=120)

# ---------- Real-time Prediction ----------
st.header("⚡ Real‑time Flow Prediction")
st.markdown("Enter flow details to get an instant verdict.")

with st.form("prediction_form"):
    col1, col2 = st.columns(2)
    with col1:
        src_ip = st.text_input("Source IP", "192.168.1.100")
        dst_ip = st.text_input("Destination IP", "8.8.8.8")
        src_port = st.number_input("Source Port", 0, 65535, 54321)
        dst_port = st.number_input("Destination Port", 0, 65535, 80)
    with col2:
        protocol = st.selectbox("Protocol", options=[("TCP", 6), ("UDP", 17), ("ICMP", 1)], format_func=lambda x: x[0])
        packets = st.number_input("Bidirectional Packets", 0, 1000000, 20)
        bytes_ = st.number_input("Bidirectional Bytes", 0, 1000000000, 8000)
        duration_ms = st.number_input("Duration (ms)", 0.0, 3600000.0, 350.0, step=100.0)
        payload_entropy = st.slider("Payload Entropy", 0.0, 8.0, 0.0)
        payload_len_var = st.slider("Payload Length Var", 0.0, 10000.0, 0.0)
        is_high_volume = st.checkbox("Force High Volume Flag", False)

    submitted = st.form_submit_button("🔍 Predict")

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
            st.error(f"🚨 **ATTACK DETECTED** (score: {score:.3f})")
        else:
            st.success(f"✅ **NORMAL TRAFFIC** (score: {score:.3f})")
    else:
        proba = model.predict_proba(X_scaled)[0]
        idx = int(np.argmax(proba))
        label = meta["label_encoder"].inverse_transform([idx])[0]
        conf = proba[idx]
        if label.upper() not in {"NORMAL", "BENIGN"}:
            st.error(f"🚨 **{label}** (confidence: {conf:.2%})")
        else:
            st.success(f"✅ **{label}** (confidence: {conf:.2%})")
        # Show all class probabilities
        prob_df = pd.DataFrame({
            "Class": meta["label_encoder"].classes_,
            "Probability": proba
        }).sort_values("Probability", ascending=False)
        fig = px.bar(prob_df, x="Probability", y="Class", orientation='h',
                     title="Prediction Probabilities", color="Class")
        st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# ══════════════════════════════════════════════════════════════════════════════
#  NEW: Adaptive Security Tabs
# ══════════════════════════════════════════════════════════════════════════════
st.header("🧠 Adaptive Security Intelligence")

tab_ol, tab_mitre, tab_rules, tab_enc = st.tabs([
    "🔄 Online Learning", "🎯 MITRE ATT&CK", "📜 Generated Rules", "🔐 Encrypted Traffic"
])

# ---------- Online Learning Tab ----------
with tab_ol:
    st.subheader("Online Learning & Drift Status")

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
    st.subheader("Manual Alert Feedback (reduces false positives immediately)")
    st.caption("Select an alert and mark it as False Positive (NORMAL) or True Positive (confirm).")

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

        if st.button("Submit feedback"):
            r = _alerts.iloc[int(sel)].to_dict()
            # Convert proto text to numeric protocol for the trainer schema
            proto_name = str(r.get("proto", "")).upper().strip()
            proto_num = 6 if proto_name == "TCP" else 17 if proto_name == "UDP" else 1 if proto_name == "ICMP" else 0

            # Build a minimal flow feature row compatible with `data/online_learning.csv`
            # Prefer fields emitted by the IDS engine (real-time features), fallback to safe defaults.
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
                st.success("Saved: False Positive → NORMAL. The real-time engine will suppress repeats quickly.")
            else:
                fc.record_true_positive(flow_features, original_label=original_label, alert_rule=alert_rule)
                st.success("Saved: True Positive confirmation.")

        st.markdown("---")
        st.subheader("Manual Response: Isolate / Release (even if ML confidence is low)")
        st.caption("This writes an action request; the IDS engine applies it if running as Administrator.")

        # Action uses the same selected alert row `sel`
        r_act = _alerts.iloc[int(sel)].to_dict()
        src_ip_act = str(r_act.get("src_ip", "")).strip()
        reason_default = f"{r_act.get('attack_type','?')} {r_act.get('rule','')}".strip()[:180]
        action_reason = st.text_input("Reason", value=reason_default)

        colx, coly = st.columns(2)
        with colx:
            if st.button("🧱 ISOLATE source IP"):
                os.makedirs(os.path.dirname(MANUAL_ACTIONS_JSONL) or ".", exist_ok=True)
                evt = {
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "action": "ISOLATE",
                    "src_ip": src_ip_act,
                    "reason": action_reason,
                }
                with open(MANUAL_ACTIONS_JSONL, "a", encoding="utf-8") as f:
                    f.write(json.dumps(evt, ensure_ascii=False) + "\n")
                st.success(f"Queued isolate request for {src_ip_act}.")
        with coly:
            if st.button("✅ RELEASE source IP"):
                os.makedirs(os.path.dirname(MANUAL_ACTIONS_JSONL) or ".", exist_ok=True)
                evt = {
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "action": "RELEASE",
                    "src_ip": src_ip_act,
                    "reason": action_reason,
                }
                with open(MANUAL_ACTIONS_JSONL, "a", encoding="utf-8") as f:
                    f.write(json.dumps(evt, ensure_ascii=False) + "\n")
                st.success(f"Queued release request for {src_ip_act}.")

    # Drift reference info
    ref_path = os.path.join(OUTPUT_DIR, "reference_dist.pkl")
    if os.path.exists(ref_path):
        st.success("✅ Drift reference distribution loaded")
        try:
            ref = joblib.load(ref_path)
            st.caption(f"Monitoring {len(ref)} features: {', '.join(list(ref.keys())[:8])}...")
        except Exception:
            pass
    else:
        st.warning("⚠️ No drift reference — will be built from first live session")

    # Model snapshots
    snap_dir = os.path.join(OUTPUT_DIR, "snapshots")
    if os.path.exists(snap_dir):
        snaps = sorted([f for f in os.listdir(snap_dir) if f.endswith(".pkl")])
        st.metric("Model Snapshots", len(snaps) // 3)  # 3 files per snapshot

# ---------- MITRE ATT&CK Tab ----------
with tab_mitre:
    st.subheader("MITRE ATT&CK Coverage")

    if alerts_df is not None and "mitre_tactic" in alerts_df.columns:
        mitre_data = alerts_df[alerts_df["mitre_tactic"].astype(str).str.len() > 2]
        if len(mitre_data) > 0:
            tactic_counts = mitre_data["mitre_tactic"].value_counts().reset_index()
            tactic_counts.columns = ["Tactic", "Count"]
            fig = px.bar(tactic_counts, x="Count", y="Tactic", orientation="h",
                         title="Alerts per MITRE ATT&CK Tactic",
                         color="Count", color_continuous_scale="Reds")
            st.plotly_chart(fig, use_container_width=True)

            if "mitre_technique" in mitre_data.columns:
                tech_counts = mitre_data["mitre_technique"].value_counts().head(15).reset_index()
                tech_counts.columns = ["Technique", "Count"]
                fig2 = px.bar(tech_counts, x="Count", y="Technique", orientation="h",
                              title="Top 15 MITRE Techniques Detected")
                st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No MITRE-tagged alerts yet.")
    else:
        st.info("MITRE ATT&CK mapping will appear once alerts with MITRE tags are generated.")

    # Show the mapping table
    with st.expander("📋 Built-in MITRE Mapping Table"):
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
    st.subheader("Auto-Generated Detection Rules")

    sigma_dir = "rules/sigma"
    suricata_dir = "rules/suricata"

    col_s, col_r = st.columns(2)

    with col_s:
        st.markdown("#### Sigma Rules")
        if os.path.exists(sigma_dir):
            sigma_files = sorted([f for f in os.listdir(sigma_dir) if f.endswith(".yml")])
            st.metric("Sigma Rules", len(sigma_files))
            for sf in sigma_files[-5:]:  # Show last 5
                with st.expander(f"📄 {sf}"):
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
                with st.expander(f"📄 {rf}"):
                    try:
                        with open(os.path.join(suricata_dir, rf), "r") as fh:
                            st.code(fh.read(), language="text")
                    except Exception:
                        st.error("Could not read rule file.")
        else:
            st.info("No Suricata rules generated yet.")

# ---------- Encrypted Traffic Tab ----------
with tab_enc:
    st.subheader("Encrypted Traffic Analysis (via mitmproxy)")

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
                    fig = px.pie(tls_counts, values="Count", names="TLS Version",
                                 title="TLS Version Distribution", hole=0.4)
                    st.plotly_chart(fig, use_container_width=True)

                # Top hosts
                if "host" in dec_df.columns:
                    host_counts = dec_df["host"].value_counts().head(15).reset_index()
                    host_counts.columns = ["Host", "Count"]
                    fig = px.bar(host_counts, x="Count", y="Host", orientation="h",
                                 title="Top 15 Decrypted Hosts")
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
    st.header("🎯 Adaptive Response Distribution")
    tier_counts = alerts_df["response_tier"].value_counts().reset_index()
    tier_counts.columns = ["Response Tier", "Count"]
    color_map = {"AUTO_BLOCK": "#e74c3c", "ISOLATE": "#f39c12",
                 "RATE_LIMIT": "#3498db", "LOG": "#2ecc71"}
    fig = px.pie(tier_counts, values="Count", names="Response Tier",
                 title="Response Actions Taken", hole=0.4,
                 color="Response Tier", color_discrete_map=color_map)
    st.plotly_chart(fig, use_container_width=True)

st.markdown("---")
st.caption("Dashboard for AI‑Powered Adaptive IDS/IPS — SudoSOC 2026")