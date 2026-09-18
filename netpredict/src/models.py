"""
Machine learning models module:
1. Logistic Regression (Baseline)
2. Small CPU-friendly Temporal LSTM for attack-risk probability forecasting
3. Comprehensive evaluation suite (Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix)
"""

import json
from pathlib import Path
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)
from sklearn.utils.class_weight import compute_class_weight
import joblib

# Suppress TensorFlow verbose logging for clean hackathon console
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
import tensorflow as tf
from tensorflow.keras import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.optimizers import Adam

from .config import (
    SEQUENCE_LENGTH,
    FORECAST_HORIZON,
    BATCH_SIZE,
    EPOCHS,
    LR_MAX_ITER,
    RANDOM_STATE,
    MODELS_DIR,
)


def train_logistic_regression(
    X_train: np.ndarray, y_train: np.ndarray
) -> LogisticRegression:
    """
    Trains a Logistic Regression baseline model.
    Uses balanced class weighting to handle benign/attack class imbalances.
    """
    print("[*] Training Baseline: Logistic Regression...")
    model = LogisticRegression(
        max_iter=LR_MAX_ITER,
        class_weight="balanced",
        solver="lbfgs",
        random_state=RANDOM_STATE,
    )
    model.fit(X_train, y_train)
    print("[✓] Logistic Regression baseline trained successfully.")
    return model


def build_lstm_model(input_shape: tuple[int, int]) -> Sequential:
    """
    Constructs a lightweight, CPU-friendly LSTM temporal forecasting network.
    Architecture:
      - LSTM(32 units): Captures temporal dependencies across packet sequence windows
      - Dropout(0.2): Regularization against overfitting
      - Dense(16 units, ReLU): Latent temporal feature combination
      - Dense(1 unit, Sigmoid): Calibrated attack risk probability output [0.0, 1.0]
    """
    model = Sequential([
        LSTM(32, input_shape=input_shape, return_sequences=False, name="temporal_lstm"),
        Dropout(0.2, name="lstm_dropout"),
        Dense(16, activation="relu", name="dense_latent"),
        Dense(1, activation="sigmoid", name="risk_probability_output"),
    ])

    optimizer = Adam(learning_rate=0.001)
    model.compile(
        optimizer=optimizer,
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


def train_lstm_model(
    model: Sequential,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    epochs: int = EPOCHS,
    batch_size: int = BATCH_SIZE,
) -> tuple[Sequential, dict]:
    """
    Trains the LSTM temporal model using EarlyStopping to avoid laptop CPU overload.
    """
    print(f"[*] Training Temporal LSTM on CPU ({epochs} epochs max, batch_size={batch_size})...")
    classes = np.unique(y_train)
    class_weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=y_train,
    )
    class_weight = dict(zip(classes.tolist(), class_weights.tolist()))

    early_stop = EarlyStopping(
        monitor="val_loss",
        patience=3,
        restore_best_weights=True,
        verbose=1,
    )

    history = model.fit(
        X_train,
        y_train,
        validation_data=(X_val, y_val),
        epochs=epochs,
        batch_size=batch_size,
        callbacks=[early_stop],
        class_weight=class_weight,
        shuffle=False,
        verbose=1,
    )
    print("[✓] LSTM temporal model trained successfully.")
    return model, history.history


def evaluate_predictions(
    y_true: np.ndarray, y_probs: np.ndarray, threshold: float = 0.5
) -> dict:
    """
    Calculates standard cybersecurity evaluation metrics:
    Accuracy, Precision, Recall, F1, ROC-AUC, and Confusion Matrix.
    """
    y_pred = (y_probs >= threshold).astype(int)

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    try:
        auc = float(roc_auc_score(y_true, y_probs))
    except Exception:
        auc = 0.0

    cm = confusion_matrix(y_true, y_pred).tolist()

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(auc, 4),
        "confusion_matrix": cm,
    }


def save_models_and_metrics(
    lr_model: LogisticRegression,
    lstm_model: Sequential,
    metrics: dict,
    feature_names: list[str],
    output_dir: Path = MODELS_DIR,
):
    """
    Persists trained weights, metrics, and feature references for the Streamlit dashboard.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Logistic Regression
    lr_path = output_dir / "logistic_regression.joblib"
    joblib.dump(lr_model, lr_path)

    # 2. LSTM
    lstm_path = output_dir / "lstm_model.h5"
    lstm_model.save(str(lstm_path))

    # 3. Feature names
    feat_path = output_dir / "feature_names.joblib"
    joblib.dump(feature_names, feat_path)

    # 4. Metrics JSON
    metrics_path = output_dir / "model_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"[✓] All models and metrics exported to: {output_dir}")


def load_trained_models(models_dir: Path = MODELS_DIR):
    """
    Loads all saved models, feature definitions, and metrics for deployment.
    """
    lr_path = models_dir / "logistic_regression.joblib"
    lstm_path = models_dir / "lstm_model.h5"
    feat_path = models_dir / "feature_names.joblib"
    metrics_path = models_dir / "model_metrics.json"

    if not (lr_path.exists() and lstm_path.exists()):
        raise FileNotFoundError(
            f"Saved models not found in {models_dir}. Please run 'python train.py' first."
        )

    lr_model = joblib.load(lr_path)
    lstm_model = tf.keras.models.load_model(str(lstm_path))
    feature_names = joblib.load(feat_path) if feat_path.exists() else []

    metrics = {}
    if metrics_path.exists():
        with open(metrics_path, "r", encoding="utf-8") as f:
            metrics = json.load(f)

    return lr_model, lstm_model, feature_names, metrics
