"""
Streamlit Dashboard for AI Network Attack Forecasting.
Title: AI Network Attack Forecasting
Subtitle: Predicting short-term attack risk from network traffic behaviour
"""

import sys
import time
import json
from pathlib import Path
import numpy as np
import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import joblib

# Resolve project path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import (
    DEFAULT_RISK_THRESHOLDS,
    PRIORITY_ACTION_MAP,
    PROTOTYPE_DISCLAIMER,
    MODELS_DIR,
    DATA_PROCESSED_DIR,
)
from src.mitre_mapping import get_mitre_investigation_context

# Streamlit Page Setup
st.set_page_config(
    page_title="AI Network Attack Forecasting",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for clean presentation styling
st.markdown(
    """
    <style>
    .metric-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px 20px;
        color: #f8fafc;
        margin-bottom: 12px;
    }
    .metric-label {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94a3b8;
    }
    .metric-value {
        font-size: 2.1rem;
        font-weight: 700;
        margin: 4px 0;
    }
    .badge-critical { color: #f87171; }
    .badge-high { color: #fb923c; }
    .badge-medium { color: #facc15; }
    .badge-low { color: #4ade80; }
    .disclaimer-banner {
        background-color: #0f172a;
        border-left: 4px solid #38bdf8;
        padding: 10px 14px;
        margin-bottom: 20px;
        border-radius: 4px;
        font-size: 0.85rem;
        color: #cbd5e1;
    }
    .replay-banner {
        background-color: #1e1b4b;
        border: 1px solid #6366f1;
        border-radius: 8px;
        padding: 8px 14px;
        margin-bottom: 16px;
        color: #c7d2fe;
        font-weight: 600;
        text-align: center;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def load_cached_artifacts():
    """Loads models, feature names, metrics, and precomputed replay sequences."""
    replay_path = DATA_PROCESSED_DIR / "test_replay_windows.npz"
    metrics_path = MODELS_DIR / "model_metrics.json"
    feat_path = MODELS_DIR / "feature_names.joblib"
    explainer_path = MODELS_DIR / "shap_explainer.joblib"

    if not replay_path.exists():
        return None, None, None, None

    replay_data = np.load(replay_path)
    feature_names = joblib.load(feat_path) if feat_path.exists() else []

    metrics = {}
    if metrics_path.exists():
        with open(metrics_path, "r", encoding="utf-8") as f:
            metrics = json.load(f)

    explainer = joblib.load(explainer_path) if explainer_path.exists() else None

    return replay_data, feature_names, metrics, explainer


def determine_risk_level(prob: float, thresholds: dict) -> tuple[str, str, str]:
    """Maps continuous probability into risk tier, color class, and priority text."""
    p = prob * 100.0
    low_t = thresholds["LOW"]
    med_t = thresholds["MEDIUM"]
    high_t = thresholds["HIGH"]

    if p >= high_t:
        return "CRITICAL", "badge-critical", PRIORITY_ACTION_MAP["CRITICAL"]
    elif p >= med_t:
        return "HIGH", "badge-high", PRIORITY_ACTION_MAP["HIGH"]
    elif p >= low_t:
        return "MEDIUM", "badge-medium", PRIORITY_ACTION_MAP["MEDIUM"]
    else:
        return "LOW", "badge-low", PRIORITY_ACTION_MAP["LOW"]


# ---------------- SIDEBAR CONTROLS ----------------
st.sidebar.title("⚙️ System Configuration")

st.sidebar.subheader("Adjust Risk Thresholds (%)")
low_cutoff = st.sidebar.slider("LOW / MEDIUM Cutoff", min_value=10, max_value=40, value=25, step=5)
med_cutoff = st.sidebar.slider("MEDIUM / HIGH Cutoff", min_value=30, max_value=65, value=50, step=5)
high_cutoff = st.sidebar.slider("HIGH / CRITICAL Cutoff", min_value=60, max_value=90, value=75, step=5)

threshold_cfg = {
    "LOW": low_cutoff,
    "MEDIUM": med_cutoff,
    "HIGH": high_cutoff,
}

st.sidebar.markdown("---")
st.sidebar.subheader("Forecasting Engine")
primary_model = st.sidebar.radio(
    "Active Forecast Model",
    ["LSTM Temporal Model (Primary)", "Logistic Regression (Baseline)"],
    index=0,
)
is_lstm = "LSTM" in primary_model

st.sidebar.markdown("---")
st.sidebar.info(PROTOTYPE_DISCLAIMER)

# ---------------- HEADER ----------------
st.title("AI Network Attack Forecasting")
st.markdown("##### *Predicting short-term attack risk from network traffic behaviour*")

st.markdown(
    """
    <div class="disclaimer-banner">
        <strong>Research Prototype Context:</strong> Demonstrating short-term attack risk forecasting
        using temporal sliding-window analysis on the <strong>CICIDS2017 Tuesday-WorkingHours</strong> benchmark dataset.
    </div>
    """,
    unsafe_allow_html=True,
)

# Load artifacts
replay_data, feature_names, metrics, explainer = load_cached_artifacts()

if replay_data is None:
    st.error(
        "⚠️ Model artifacts and replay dataset not found in `models/` and `data/processed/`. "
        "Please execute the training script first:\n\n"
        "```bash\npython train.py\n```"
    )
    st.stop()

# Replay state initialization
total_windows = len(replay_data["X_seq"])
if "current_index" not in st.session_state:
    st.session_state.current_index = 0
if "is_replaying" not in st.session_state:
    st.session_state.is_replaying = False

# ---------------- HISTORICAL REPLAY CONTROLS ----------------
st.markdown(
    '<div class="replay-banner">Historical Dataset Replay — Not Live Network Traffic</div>',
    unsafe_allow_html=True,
)

ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4 = st.columns([2, 2, 2, 4])

with ctrl_col1:
    if st.button("▶ Start Historical Replay" if not st.session_state.is_replaying else "⏸ Pause Replay"):
        st.session_state.is_replaying = not st.session_state.is_replaying

with ctrl_col2:
    if st.button("⏭ Next Window (Step)"):
        st.session_state.current_index = (st.session_state.current_index + 1) % total_windows
        st.session_state.is_replaying = False

with ctrl_col3:
    if st.button("⏮ Reset to Start"):
        st.session_state.current_index = 0
        st.session_state.is_replaying = False

with ctrl_col4:
    replay_speed = st.slider("Replay Rate (delay seconds)", min_value=0.2, max_value=2.0, value=0.6, step=0.2)

# Sequence window slider
window_slider_val = st.slider(
    "Jump to Traffic Window:",
    min_value=0,
    max_value=total_windows - 1,
    value=st.session_state.current_index,
    key="window_scrubber",
)
if window_slider_val != st.session_state.current_index and not st.session_state.is_replaying:
    st.session_state.current_index = window_slider_val

idx = st.session_state.current_index

# Fetch probabilities
probs_array = replay_data["lstm_probs"] if is_lstm else replay_data["lr_probs"]
current_prob = float(probs_array[idx])
current_risk_pct = current_prob * 100.0

risk_level, badge_class, investigation_priority = determine_risk_level(current_prob, threshold_cfg)

# ---------------- 1. CURRENT RISK CARDS ----------------
st.markdown("### 1. Current Risk State")
c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Forecasted Risk</div>
            <div class="metric-value {badge_class}">{current_risk_pct:.1f}%</div>
            <div style="font-size:0.8rem; color:#94a3b8;">Window index: #{idx} / {total_windows}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c2:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Risk Level</div>
            <div class="metric-value {badge_class}">{risk_level}</div>
            <div style="font-size:0.8rem; color:#94a3b8;">Threshold: &ge; {threshold_cfg.get(risk_level, 0)}%</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c3:
    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-label">Forecast Horizon</div>
            <div class="metric-value" style="color: #38bdf8;">Next Window</div>
            <div style="font-size:0.8rem; color:#94a3b8;">Temporal lookback = 5 steps</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c4:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Investigation Priority</div>
            <div class="metric-value {badge_class}" style="font-size:1.6rem;">{risk_level} PRIORITY</div>
            <div style="font-size:0.8rem; color:#94a3b8;">{investigation_priority.split('(')[0]}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ---------------- 2. RISK TREND (PLOTLY) ----------------
st.markdown("### 2. Temporal Risk Trend")
trend_x = list(range(max(0, idx - 40), min(total_windows, idx + 40)))
trend_y = [float(probs_array[i]) * 100.0 for i in trend_x]

fig_trend = go.Figure()

# Background Threshold Bands
fig_trend.add_hrect(y0=threshold_cfg["HIGH"], y1=100, fillcolor="rgba(239, 68, 68, 0.12)", line_width=0, annotation_text="CRITICAL", annotation_position="top left")
fig_trend.add_hrect(y0=threshold_cfg["MEDIUM"], y1=threshold_cfg["HIGH"], fillcolor="rgba(249, 115, 22, 0.12)", line_width=0, annotation_text="HIGH", annotation_position="top left")
fig_trend.add_hrect(y0=threshold_cfg["LOW"], y1=threshold_cfg["MEDIUM"], fillcolor="rgba(234, 179, 8, 0.12)", line_width=0, annotation_text="MEDIUM", annotation_position="top left")
fig_trend.add_hrect(y0=0, y1=threshold_cfg["LOW"], fillcolor="rgba(34, 197, 94, 0.12)", line_width=0, annotation_text="LOW", annotation_position="top left")

# Main Risk Line
fig_trend.add_trace(go.Scatter(
    x=trend_x,
    y=trend_y,
    mode="lines+markers",
    name="Forecasted Risk %",
    line=dict(color="#38bdf8", width=3),
    marker=dict(size=4),
))

# Active Window Indicator
fig_trend.add_trace(go.Scatter(
    x=[idx],
    y=[current_risk_pct],
    mode="markers",
    name="Current Window",
    marker=dict(color="#ef4444" if current_risk_pct >= 50 else "#38bdf8", size=14, symbol="circle-open-dot", line=dict(width=3)),
))

fig_trend.update_layout(
    title=f"Time Series Attack Risk Forecast ({'LSTM' if is_lstm else 'Logistic Regression'})",
    xaxis_title="Chronological Traffic Window (#)",
    yaxis_title="Attack Probability (%)",
    yaxis=dict(range=[0, 105]),
    margin=dict(l=20, r=20, t=40, b=20),
    template="plotly_dark",
    height=340,
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
)
st.plotly_chart(fig_trend, use_container_width=True)

# ---------------- 3. WHY IS IT RISKY? (SHAP) & MITRE ATT&CK ----------------
col_shap, col_mitre = st.columns([1, 1])

current_base_vector = replay_data["X_base"][idx]

# Calculate Real SHAP Contributions
top_features_list = []
with col_shap:
    st.markdown("### 3. Why Is It Risky? (SHAP Explainability)")
    if explainer is not None and len(feature_names) > 0:
        shap_df, methodology_note = explainer.explain_window(current_base_vector, top_k=6)
        top_features_list = shap_df["Feature"].tolist()

        # Horizontal bar chart of contributions
        bar_colors = ["#ef4444" if s > 0 else "#22c55e" for s in shap_df["SHAP_Value"]]
        fig_shap = go.Figure(go.Bar(
            x=shap_df["SHAP_Value"],
            y=shap_df["Feature"],
            orientation="h",
            marker_color=bar_colors,
            text=[f"{v:+.3f}" for v in shap_df["SHAP_Value"]],
            textposition="auto",
        ))
        fig_shap.update_layout(
            title="Real Feature Contributions to Risk (SHAP)",
            xaxis_title="SHAP Value (Positive: Increases Risk | Negative: Decreases Risk)",
            yaxis=dict(autorange="reversed"),
            template="plotly_dark",
            height=280,
            margin=dict(l=10, r=10, t=35, b=10),
        )
        st.plotly_chart(fig_shap, use_container_width=True)

        # Tabular contribution breakdown
        st.dataframe(
            shap_df[["Feature", "Contribution", "Direction", "Value"]],
            use_container_width=True,
            hide_index=True,
        )
        st.caption(methodology_note)
    else:
        st.info("SHAP explainer or feature schema unavailable.")

with col_mitre:
    st.markdown("### 4. Possible MITRE ATT&CK Investigation Context")
    mitre_contexts = get_mitre_investigation_context(risk_level, top_features_list)

    st.caption("ℹ️ *Notice: Displays potential investigation hypotheses based on flow attributes, NOT definitive attribution.*")

    for ctx in mitre_contexts:
        tech_id = ctx.get("technique_id", "N/A")
        tech_name = ctx.get("name", "Unknown")
        tactic = ctx.get("tactic", "N/A")
        rationale = ctx.get("rationale", "")
        actions = ctx.get("triage_actions", [])

        st.markdown(
            f"""
            <div style="background:#1e293b; border-left: 4px solid #f59e0b; padding:12px; border-radius:6px; margin-bottom:12px;">
                <div style="font-weight:700; color:#fbbf24; font-size:1.05rem;">{tech_id} — {tech_name}</div>
                <div style="font-size:0.8rem; color:#94a3b8; margin-bottom:6px;">Tactic: {tactic}</div>
                <div style="font-size:0.85rem; color:#e2e8f0; margin-bottom:8px;">{rationale}</div>
                <div style="font-size:0.8rem; font-weight:600; color:#cbd5e1;">Recommended Triage Steps:</div>
                <ul style="font-size:0.8rem; color:#94a3b8; margin-bottom:2px; padding-left:18px;">
                    {''.join([f'<li>{a}</li>' for a in actions])}
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ---------------- 5. MODEL COMPARISON ----------------
st.markdown("### 5. Model Comparison: Baseline vs. Temporal")

if metrics:
    lr_m = metrics.get("Logistic Regression (Baseline)", {})
    lstm_m = metrics.get("LSTM Temporal Model", {})

    comp_data = {
        "Metric": ["Accuracy", "Precision", "Recall", "F1 Score", "ROC-AUC"],
        "Logistic Regression (Baseline)": [
            f"{lr_m.get('accuracy', 0):.4f}",
            f"{lr_m.get('precision', 0):.4f}",
            f"{lr_m.get('recall', 0):.4f}",
            f"{lr_m.get('f1', 0):.4f}",
            f"{lr_m.get('roc_auc', 0):.4f}",
        ],
        "LSTM Temporal Model": [
            f"{lstm_m.get('accuracy', 0):.4f}",
            f"{lstm_m.get('precision', 0):.4f}",
            f"{lstm_m.get('recall', 0):.4f}",
            f"{lstm_m.get('f1', 0):.4f}",
            f"{lstm_m.get('roc_auc', 0):.4f}",
        ],
        "Delta (LSTM vs LR)": [
            f"{(lstm_m.get('accuracy', 0) - lr_m.get('accuracy', 0)):+.4f}",
            f"{(lstm_m.get('precision', 0) - lr_m.get('precision', 0)):+.4f}",
            f"{(lstm_m.get('recall', 0) - lr_m.get('recall', 0)):+.4f}",
            f"{(lstm_m.get('f1', 0) - lr_m.get('f1', 0)):+.4f}",
            f"{(lstm_m.get('roc_auc', 0) - lr_m.get('roc_auc', 0)):+.4f}",
        ],
    }
    st.table(pd.DataFrame(comp_data))

    cm_col1, cm_col2 = st.columns(2)
    with cm_col1:
        st.markdown("**Logistic Regression Confusion Matrix:**")
        st.json(lr_m.get("confusion_matrix", []))
    with cm_col2:
        st.markdown("**LSTM Temporal Confusion Matrix:**")
        st.json(lstm_m.get("confusion_matrix", []))
else:
    st.info("Model performance metrics not loaded.")

# ---------------- 6. INVESTIGATION PRIORITY MATRIX ----------------
st.markdown("### 6. Investigation Priority Matrix (SOC Decision Support)")
p_col1, p_col2, p_col3, p_col4 = st.columns(4)

with p_col1:
    st.markdown(
        """
        <div style="background:#450a0a; border:1px solid #ef4444; border-radius:6px; padding:12px;">
            <div style="font-weight:700; color:#f87171;">CRITICAL (&ge; 75%)</div>
            <div style="font-size:0.85rem; color:#fca5a5;">Investigate immediately</div>
            <div style="font-size:0.75rem; color:#cbd5e1; margin-top:4px;">Direct page to Tier 2 SOC, isolate host, verify credentials.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with p_col2:
    st.markdown(
        """
        <div style="background:#431407; border:1px solid #f97316; border-radius:6px; padding:12px;">
            <div style="font-weight:700; color:#fb923c;">HIGH (50 - 75%)</div>
            <div style="font-size:0.85rem; color:#fdba74;">Investigate soon</div>
            <div style="font-size:0.75rem; color:#cbd5e1; margin-top:4px;">Elevate SIEM rule sensitivity, inspect outbound connection rate.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with p_col3:
    st.markdown(
        """
        <div style="background:#422006; border:1px solid #eab308; border-radius:6px; padding:12px;">
            <div style="font-weight:700; color:#facc15;">MEDIUM (25 - 50%)</div>
            <div style="font-size:0.85rem; color:#fde047;">Monitor closely</div>
            <div style="font-size:0.75rem; color:#cbd5e1; margin-top:4px;">Track IP reputation, log telemetry without disruption.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with p_col4:
    st.markdown(
        """
        <div style="background:#052e16; border:1px solid #22c55e; border-radius:6px; padding:12px;">
            <div style="font-weight:700; color:#4ade80;">LOW (&lt; 25%)</div>
            <div style="font-size:0.85rem; color:#86efac;">Normal monitoring</div>
            <div style="font-size:0.75rem; color:#cbd5e1; margin-top:4px;">Standard periodic audit and baseline retention.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Replay animation loop handler
if st.session_state.is_replaying:
    time.sleep(replay_speed)
    st.session_state.current_index = (st.session_state.current_index + 1) % total_windows
    st.rerun()
