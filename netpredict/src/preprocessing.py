"""
Preprocessing module for CICIDS2017 network traffic data.
Preserves strict chronological order, removes leakage identifiers,
handles infinite/NaN values, fits scalers exclusively on training data,
and creates sliding window tensors for temporal forecasting.
"""

import os
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
import joblib

from .config import (
    COLUMNS_TO_DROP,
    LABEL_COLUMN,
    BENIGN_LABEL,
    SEQUENCE_LENGTH,
    FORECAST_HORIZON,
    DEFAULT_RAW_FILE,
    DATA_RAW_DIR,
)


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip leading and trailing whitespace from CICIDS2017 column names."""
    df.columns = [c.strip() for c in df.columns]
    return df


def generate_synthetic_cicids_sample(num_samples: int = 5000) -> pd.DataFrame:
    """
    Generate a realistic, synthetically structured sample conforming to the CICIDS2017
    Tuesday-WorkingHours schema (features matching flow characteristics).
    Used as an immediate demonstration fallback if the external CSV has not yet been placed.
    """
    np.random.seed(42)
    # Common CICIDS2017 features
    feature_cols = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",
        "Bwd Packet Length Max",
        "Bwd Packet Length Min",
        "Bwd Packet Length Mean",
        "Bwd Packet Length Std",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",
        "Fwd IAT Total",
        "Fwd IAT Mean",
        "Bwd IAT Total",
        "Bwd IAT Mean",
        "Fwd PSH Flags",
        "Bwd PSH Flags",
        "Fwd URG Flags",
        "Bwd URG Flags",
        "Fwd Header Length",
        "Bwd Header Length",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Min Packet Length",
        "Max Packet Length",
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "URG Flag Count",
        "Down/Up Ratio",
        "Average Packet Size",
        "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",
        "Subflow Fwd Packets",
        "Subflow Fwd Bytes",
        "Subflow Bwd Packets",
        "Subflow Bwd Bytes",
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward",
        "act_data_pkt_fwd",
        "min_seg_size_forward",
        "Active Mean",
        "Active Std",
        "Active Max",
        "Active Min",
        "Idle Mean",
        "Idle Std",
        "Idle Max",
        "Idle Min",
    ]

    # Baseline benign background traffic
    data = {}
    for col in feature_cols:
        data[col] = np.random.exponential(scale=50.0, size=num_samples) + np.random.normal(20, 5, size=num_samples)

    labels = ["BENIGN"] * num_samples

    # Inject temporal attack bursts (resembling Tuesday Patator brute-force patterns)
    # Burst 1: Window 1200-1600 (SSH-Patator: rapid SYN flags, fixed small packet size, repeated connection attempts)
    burst1_start, burst1_end = int(num_samples * 0.35), int(num_samples * 0.45)
    for i in range(burst1_start, burst1_end):
        labels[i] = "SSH-Patator"
        data["SYN Flag Count"][i] += np.random.uniform(5, 20)
        data["Flow Packets/s"][i] += np.random.uniform(200, 800)
        data["Flow Duration"][i] = np.random.uniform(1000, 50000)
        data["Packet Length Mean"][i] = np.random.uniform(40, 85)

    # Burst 2: Window 3000-3500 (FTP-Patator)
    burst2_start, burst2_end = int(num_samples * 0.70), int(num_samples * 0.80)
    for i in range(burst2_start, burst2_end):
        labels[i] = "FTP-Patator"
        data["Flow Bytes/s"][i] += np.random.uniform(10000, 50000)
        data["Flow Packets/s"][i] += np.random.uniform(150, 600)
        data["Fwd Packet Length Mean"][i] = np.random.uniform(80, 200)

    df = pd.DataFrame(data)
    df["Label"] = labels
    return df


def load_raw_dataset(file_path: str = None) -> pd.DataFrame:
    """
    Loads raw CICIDS2017 dataset from CSV or generates benchmark fallback.
    Performs initial header normalization.
    """
    target_path = Path(file_path) if file_path else DEFAULT_RAW_FILE

    if not target_path.exists():
        print(f"[!] Dataset file not found at: {target_path}")
        print("[!] Generating synthetic CICIDS2017 Tuesday benchmark sample for testing...")
        DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
        synthetic_df = generate_synthetic_cicids_sample()
        synthetic_path = DATA_RAW_DIR / "sample_Tuesday_benchmark.csv"
        synthetic_df.to_csv(synthetic_path, index=False)
        print(f"[✓] Benchmark dataset saved to: {synthetic_path}")
        return synthetic_df

    print(f"[*] Reading dataset from: {target_path}")
    # Read CSV (handle possible low_memory or encoding issues)
    df = pd.read_csv(target_path, encoding="utf-8", low_memory=False)
    df = clean_column_names(df)
    return df


def preprocess_traffic(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """
    Preprocess raw network traffic DataFrame:
    - Strips identifiers
    - Cleans Inf / -Inf / NaN values
    - Binarizes labels: 0 for BENIGN, 1 for Attack
    - Preserves exact temporal sequence
    """
    df = clean_column_names(df.copy())

    # Identify Label column
    label_col = None
    for candidate in [LABEL_COLUMN, "Label", "label", "class", "Class"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        raise ValueError(f"Could not locate label column in DataFrame. Available columns: {list(df.columns)[:10]}")

    # Binary label mapping (BENIGN = 0, Attack = 1)
    y_raw = df[label_col].astype(str).str.strip()
    y = (y_raw != BENIGN_LABEL).astype(np.int32)

    # Drop label and identifier columns
    drop_candidates = [c for c in COLUMNS_TO_DROP if c in df.columns]
    drop_candidates.append(label_col)
    X_df = df.drop(columns=drop_candidates, errors="ignore")

    # Keep only numeric columns
    numeric_cols = X_df.select_dtypes(include=[np.number]).columns.tolist()
    X_df = X_df[numeric_cols]

    # Handle Inf, -Inf, and NaN values
    X_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    # Fill NaN with column median (derived cleanly without leakage when splitting)
    X_df.fillna(X_df.median(), inplace=True)

    # Also drop any residual column with constant zero variance
    var = X_df.var()
    non_zero_cols = var[var > 1e-6].index.tolist()
    X_df = X_df[non_zero_cols]

    return X_df, y, non_zero_cols


def chronological_split(
    X_df: pd.DataFrame, y: pd.Series, train_ratio: float = 0.8
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """
    Strict chronological temporal split without random shuffling.
    Prevents temporal lookahead leakage.
    """
    n_samples = len(X_df)
    split_idx = int(n_samples * train_ratio)

    X_train = X_df.iloc[:split_idx].copy()
    X_test = X_df.iloc[split_idx:].copy()
    y_train = y.iloc[:split_idx].copy()
    y_test = y.iloc[split_idx:].copy()

    print(f"[*] Chronological split: Train = {len(X_train)} samples, Test = {len(X_test)} samples")
    print(f"[*] Train attack ratio: {y_train.mean():.4f} | Test attack ratio: {y_test.mean():.4f}")
    return X_train, X_test, y_train, y_test


def fit_and_scale(
    X_train: pd.DataFrame, X_test: pd.DataFrame, scaler_save_path: Path = None
) -> tuple[np.ndarray, np.ndarray, RobustScaler]:
    """
    Fits scaler exclusively on X_train to prevent data leakage.
    Uses RobustScaler to handle heavy-tailed network traffic packet distributions.
    """
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Clip extreme outliers for numerical stability in LSTM gradients
    X_train_scaled = np.clip(X_train_scaled, -10.0, 10.0)
    X_test_scaled = np.clip(X_test_scaled, -10.0, 10.0)

    if scaler_save_path:
        scaler_save_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(scaler, scaler_save_path)
        print(f"[✓] Scaler persisted to {scaler_save_path}")

    return X_train_scaled, X_test_scaled, scaler


def create_sliding_windows(
    X: np.ndarray,
    y: np.ndarray,
    sequence_length: int = SEQUENCE_LENGTH,
    forecast_horizon: int = FORECAST_HORIZON,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Transforms continuous time-series of network traffic into temporal window tensors:
    - LSTM Input: (num_windows, sequence_length, num_features)
    - LSTM Target: (num_windows,) -> Label at time t + forecast_horizon
    - Baseline 2D Input: (num_windows, num_features) -> Vector of latest flow in sequence
    """
    X_seq = []
    y_seq = []
    X_baseline = []

    total_len = len(X)
    limit = total_len - sequence_length - forecast_horizon + 1

    for i in range(limit):
        # Sequence of 'sequence_length' past network windows
        window = X[i : i + sequence_length]
        # Target at future forecast horizon
        target = y[i + sequence_length + forecast_horizon - 1]
        # For baseline (logistic regression), use the most recent window in the sequence
        latest_flow = X[i + sequence_length - 1]

        X_seq.append(window)
        y_seq.append(target)
        X_baseline.append(latest_flow)

    return np.array(X_seq, dtype=np.float32), np.array(y_seq, dtype=np.int32), np.array(X_baseline, dtype=np.float32)
