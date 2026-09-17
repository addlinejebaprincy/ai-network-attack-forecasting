export interface ProjectFile {
  path: string;
  name: string;
  language: string;
  category: "Pipeline" | "Streamlit App" | "Source Module" | "Docs & Config";
  code: string;
}

export const PROJECT_FILES: ProjectFile[] = [
  {
    path: "train.py",
    name: "train.py",
    language: "python",
    category: "Pipeline",
    code: `"""
Training pipeline for netpredict:
1. Loads CICIDS2017 Tuesday traffic dataset (or generates benchmark sample)
2. Strips identifiers (Flow ID, IPs, Ports, Timestamps) to prevent leakage
3. Performs strictly chronological temporal train/test split
4. Fits RobustScaler on training partition only
5. Generates sliding window sequences (lookback=5, horizon=1)
6. Trains Logistic Regression baseline & CPU-friendly Temporal LSTM
7. Evaluates both models (Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix)
8. Builds and validates real SHAP Explainer
9. Exports all models, preprocessors, and test replay windows for Streamlit
"""

import sys
import json
from pathlib import Path
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.config import (
    DEFAULT_RAW_FILE,
    DATA_RAW_DIR,
    DATA_PROCESSED_DIR,
    MODELS_DIR,
    SEQUENCE_LENGTH,
    FORECAST_HORIZON,
    EPOCHS,
    BATCH_SIZE,
)
from src.preprocessing import (
    load_raw_dataset,
    preprocess_traffic,
    chronological_split,
    fit_and_scale,
    create_sliding_windows,
)
from src.models import (
    train_logistic_regression,
    build_lstm_model,
    train_lstm_model,
    evaluate_predictions,
    save_models_and_metrics,
)
from src.explainability import build_and_cache_explainer

def main():
    print("=" * 70)
    print(" AI-Based Network Attack Forecasting: Model Training Pipeline")
    print(" Dataset: CICIDS2017 Tuesday-WorkingHours (Patator Brute-Force & Benign)")
    print("=" * 70)

    # 1. Load raw dataset
    df_raw = load_raw_dataset(str(DEFAULT_RAW_FILE))
    print(f"[*] Loaded raw dataset shape: {df_raw.shape[0]} rows, {df_raw.shape[1]} columns")

    # 2. Preprocess traffic
    X_df, y_series, feature_names = preprocess_traffic(df_raw)
    print(f"[*] Cleaned feature count: {len(feature_names)} features")

    # 3. Chronological train/test split (Strict temporal order preservation)
    X_train_df, X_test_df, y_train_s, y_test_s = chronological_split(X_df, y_series, train_ratio=0.80)

    # 4. Scale features (Fit exclusively on training partition)
    scaler_path = MODELS_DIR / "scaler.joblib"
    X_train_scaled, X_test_scaled, scaler = fit_and_scale(X_train_df, X_test_df, scaler_save_path=scaler_path)

    # 5. Create sliding temporal windows (sequence_length=5, forecast_horizon=1)
    X_train_seq, y_train_seq, X_train_base = create_sliding_windows(
        X_train_scaled, y_train_s.values, SEQUENCE_LENGTH, FORECAST_HORIZON
    )
    X_test_seq, y_test_seq, X_test_base = create_sliding_windows(
        X_test_scaled, y_test_s.values, SEQUENCE_LENGTH, FORECAST_HORIZON
    )

    # 6. Train Baseline Model (Logistic Regression)
    lr_model = train_logistic_regression(X_train_base, y_train_seq)
    lr_probs = lr_model.predict_proba(X_test_base)[:, 1]
    lr_metrics = evaluate_predictions(y_test_seq, lr_probs)

    # 7. Train Temporal Model (LSTM)
    input_shape = (SEQUENCE_LENGTH, X_train_seq.shape[2])
    lstm_model = build_lstm_model(input_shape)
    lstm_model, history = train_lstm_model(
        lstm_model, X_train_seq, y_train_seq, X_test_seq, y_test_seq,
        epochs=EPOCHS, batch_size=BATCH_SIZE
    )
    lstm_probs = lstm_model.predict(X_test_seq, batch_size=64).flatten()
    lstm_metrics = evaluate_predictions(y_test_seq, lstm_probs)

    # 8. Print Comparative Metrics
    metrics_summary = {
        "Logistic Regression (Baseline)": lr_metrics,
        "LSTM Temporal Model": lstm_metrics,
    }

    # 9. Build SHAP Explainer
    explainer = build_and_cache_explainer(
        lr_model, X_train_base[:100], feature_names, save_path=MODELS_DIR / "shap_explainer.joblib"
    )

    # 10. Persist models and test replay data for Streamlit
    save_models_and_metrics(
        lr_model=lr_model, lstm_model=lstm_model, metrics=metrics_summary,
        feature_names=feature_names, output_dir=MODELS_DIR
    )
    print("✓ Training complete. Run 'streamlit run app/streamlit_app.py' to launch dashboard.")

if __name__ == "__main__":
    main()`,
  },
  {
    path: "app/streamlit_app.py",
    name: "streamlit_app.py",
    language: "python",
    category: "Streamlit App",
    code: `"""
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
import joblib

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

st.set_page_config(
    page_title="AI Network Attack Forecasting",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Sidebar configuration
st.sidebar.title("⚙️ System Configuration")
low_cutoff = st.sidebar.slider("LOW / MEDIUM Cutoff", min_value=10, max_value=40, value=25, step=5)
med_cutoff = st.sidebar.slider("MEDIUM / HIGH Cutoff", min_value=30, max_value=65, value=50, step=5)
high_cutoff = st.sidebar.slider("HIGH / CRITICAL Cutoff", min_value=60, max_value=90, value=75, step=5)
threshold_cfg = {"LOW": low_cutoff, "MEDIUM": med_cutoff, "HIGH": high_cutoff}

primary_model = st.sidebar.radio(
    "Active Forecast Model",
    ["LSTM Temporal Model (Primary)", "Logistic Regression (Baseline)"],
)
is_lstm = "LSTM" in primary_model

st.title("AI Network Attack Forecasting")
st.markdown("##### *Predicting short-term attack risk from network traffic behaviour*")

# Historical Replay Section
st.markdown("### Historical Dataset Replay — Not Live Network Traffic")
# ... Replay Controls, Plotly Trend Line, SHAP Waterfall, MITRE ATT&CK Context, Model Metrics`,
  },
  {
    path: "src/models.py",
    name: "models.py",
    language: "python",
    category: "Source Module",
    code: `import json
from pathlib import Path
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import joblib
import tensorflow as tf
from tensorflow.keras import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.optimizers import Adam

def build_lstm_model(input_shape: tuple[int, int]) -> Sequential:
    """Lightweight, CPU-friendly LSTM temporal forecasting network."""
    model = Sequential([
        LSTM(32, input_shape=input_shape, return_sequences=False, name="temporal_lstm"),
        Dropout(0.2, name="lstm_dropout"),
        Dense(16, activation="relu", name="dense_latent"),
        Dense(1, activation="sigmoid", name="risk_probability_output"),
    ])
    model.compile(optimizer=Adam(learning_rate=0.001), loss="binary_crossentropy", metrics=["accuracy"])
    return model`,
  },
  {
    path: "src/preprocessing.py",
    name: "preprocessing.py",
    language: "python",
    category: "Source Module",
    code: `import pandas as pd
import numpy as np
from sklearn.preprocessing import RobustScaler

def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip() for c in df.columns]
    return df

def chronological_split(X_df: pd.DataFrame, y: pd.Series, train_ratio: float = 0.8):
    """Preserves strict time ordering without random shuffling to prevent data leakage."""
    n_samples = len(X_df)
    split_idx = int(n_samples * train_ratio)
    return X_df.iloc[:split_idx], X_df.iloc[split_idx:], y.iloc[:split_idx], y.iloc[split_idx:]`,
  },
  {
    path: "src/explainability.py",
    name: "explainability.py",
    language: "python",
    category: "Source Module",
    code: `import shap
import numpy as np
import pandas as pd

class TrafficExplainer:
    def __init__(self, model, background_data, feature_names, explainer_type="linear"):
        self.model = model
        self.feature_names = feature_names
        self.bg_sample = background_data[:50]
        self.explainer = shap.LinearExplainer(self.model, self.bg_sample)

    def explain_window(self, window_vector, top_k=5):
        # Computes exact Shapley attributions for active network traffic window
        raw_shap = self.explainer.shap_values(window_vector.reshape(1, -1))
        # Formats contributions into High / Medium / Low tiers
        return df_explanations, methodology_note`,
  },
  {
    path: "src/mitre_mapping.py",
    name: "mitre_mapping.py",
    language: "python",
    category: "Source Module",
    code: `"""
MITRE ATT&CK Contextual Mapping Module.
Displays 'Possible MITRE ATT&CK investigation context', NOT definitive attribution.
"""
MITRE_KNOWLEDGE_BASE = {
    "T1046": {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery (TA0007)",
        "traffic_indicators": ["SYN Flag Count", "Flow Packets/s", "Flow Duration"],
    },
    "T1110.001": {
        "technique_id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access (TA0006)",
        "traffic_indicators": ["Flow Duration", "Total Backward Packets", "Packet Length Mean"],
    },
    "T1498": {
        "technique_id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact (TA0040)",
        "traffic_indicators": ["Flow Bytes/s", "Flow Packets/s", "Subflow Fwd Bytes"],
    },
}`,
  },
  {
    path: "requirements.txt",
    name: "requirements.txt",
    language: "text",
    category: "Docs & Config",
    code: `numpy>=1.24.0,<2.0.0
pandas>=2.0.0
scikit-learn>=1.3.0
tensorflow>=2.15.0
shap>=0.43.0
streamlit>=1.32.0
plotly>=5.18.0
joblib>=1.3.0`,
  },
  {
    path: "README.md",
    name: "README.md",
    language: "markdown",
    category: "Docs & Config",
    code: `# NetPredict: AI-Based Network Attack Forecasting
Predicting short-term attack risk from network traffic behaviour.

Install:
pip install -r requirements.txt

Train:
python train.py

Run Dashboard:
streamlit run app/streamlit_app.py`,
  },
];
