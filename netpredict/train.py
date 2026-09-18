"""
Training pipeline for netpredict:
1. Loads CICIDS2017 Tuesday traffic dataset (or generates benchmark sample if raw file is not yet placed)
2. Cleans columns and removes identifiers (prevents leakage)
3. Performs strictly chronological temporal train/test split
4. Fits RobustScaler on training partition only
5. Generates sliding window sequences (lookback=5, horizon=1)
6. Trains Logistic Regression baseline
7. Trains CPU-friendly Temporal LSTM
8. Evaluates both models (Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix)
9. Builds and validates real SHAP Explainer
10. Exports all models, preprocessors, and test replay windows for the Streamlit dashboard
"""

import sys
import json
from pathlib import Path
import numpy as np
import pandas as pd

# Add src to path for direct invocation
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
    print("[*] Preprocessing network flows and removing leakage identifiers...")
    X_df, y_series, feature_names = preprocess_traffic(df_raw)
    print(f"[*] Cleaned feature count: {len(feature_names)} features")
    print(f"[*] Class distribution: {dict(y_series.value_counts())} (0: Benign, 1: Attack)")

    # 3. Chronological train/test split (Strict temporal order preservation)
    X_train_df, X_test_df, y_train_s, y_test_s = chronological_split(X_df, y_series, train_ratio=0.80)

    # 4. Scale features (Fit exclusively on training partition)
    scaler_path = MODELS_DIR / "scaler.joblib"
    X_train_scaled, X_test_scaled, scaler = fit_and_scale(X_train_df, X_test_df, scaler_save_path=scaler_path)

    # 5. Create sliding temporal windows (sequence_length=5, forecast_horizon=1)
    print(f"[*] Constructing temporal window tensors (lookback={SEQUENCE_LENGTH}, horizon={FORECAST_HORIZON})...")
    X_train_seq, y_train_seq, X_train_base = create_sliding_windows(
        X_train_scaled, y_train_s.values, SEQUENCE_LENGTH, FORECAST_HORIZON
    )
    X_test_seq, y_test_seq, X_test_base = create_sliding_windows(
        X_test_scaled, y_test_s.values, SEQUENCE_LENGTH, FORECAST_HORIZON
    )

    # Keep the test windows for final evaluation only. Use the latest training
    # windows as a chronological validation partition for LSTM early stopping.
    validation_start = int(len(X_train_seq) * 0.9)
    X_lstm_train = X_train_seq[:validation_start]
    y_lstm_train = y_train_seq[:validation_start]
    X_lstm_val = X_train_seq[validation_start:]
    y_lstm_val = y_train_seq[validation_start:]

    print(f"[*] LSTM Train Windows: {X_train_seq.shape} | Baseline Train: {X_train_base.shape}")
    print(f"[*] LSTM Test Windows:  {X_test_seq.shape} | Baseline Test:  {X_test_base.shape}")

    # 6. Train Baseline Model (Logistic Regression)
    lr_model = train_logistic_regression(X_train_base, y_train_seq)

    # Evaluate Baseline
    lr_probs = lr_model.predict_proba(X_test_base)[:, 1]
    lr_metrics = evaluate_predictions(y_test_seq, lr_probs)

    # 7. Train Temporal Model (LSTM)
    input_shape = (SEQUENCE_LENGTH, X_train_seq.shape[2])
    lstm_model = build_lstm_model(input_shape)

    # Train LSTM on CPU
    lstm_model, history = train_lstm_model(
        lstm_model,
        X_lstm_train,
        y_lstm_train,
        X_lstm_val,
        y_lstm_val,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
    )

    # Evaluate LSTM
    lstm_probs = lstm_model.predict(X_test_seq, batch_size=64).flatten()
    lstm_metrics = evaluate_predictions(y_test_seq, lstm_probs)

    # 8. Print Comparative Metrics
    print("\n" + "=" * 70)
    print(" MODEL PERFORMANCE EVALUATION COMPARISON")
    print("=" * 70)
    metrics_summary = {
        "Logistic Regression (Baseline)": lr_metrics,
        "LSTM Temporal Model": lstm_metrics,
    }

    comparison_df = pd.DataFrame({
        "Metric": ["Accuracy", "Precision", "Recall", "F1 Score", "ROC-AUC"],
        "Logistic Regression": [
            f"{lr_metrics['accuracy']:.4f}",
            f"{lr_metrics['precision']:.4f}",
            f"{lr_metrics['recall']:.4f}",
            f"{lr_metrics['f1']:.4f}",
            f"{lr_metrics['roc_auc']:.4f}",
        ],
        "LSTM Temporal": [
            f"{lstm_metrics['accuracy']:.4f}",
            f"{lstm_metrics['precision']:.4f}",
            f"{lstm_metrics['recall']:.4f}",
            f"{lstm_metrics['f1']:.4f}",
            f"{lstm_metrics['roc_auc']:.4f}",
        ],
    })
    print(comparison_df.to_string(index=False))
    print("\nConfusion Matrices [TN, FP], [FN, TP]:")
    print(f" - Baseline LR: {lr_metrics['confusion_matrix']}")
    print(f" - LSTM Temporal: {lstm_metrics['confusion_matrix']}")
    print("=" * 70)

    # 9. Build SHAP Explainer
    print("\n[*] Initializing SHAP explainer on baseline background distribution...")
    explainer = build_and_cache_explainer(
        lr_model,
        X_train_base[:100],
        feature_names,
        save_path=MODELS_DIR / "shap_explainer.joblib",
    )

    # Quick test explanation
    sample_exp_df, note = explainer.explain_window(X_test_base[0], top_k=5)
    print(f"[✓] SHAP sanity check on test sample 0:\n{sample_exp_df}")

    # 10. Persist models and test replay data for Streamlit
    save_models_and_metrics(
        lr_model=lr_model,
        lstm_model=lstm_model,
        metrics=metrics_summary,
        feature_names=feature_names,
        output_dir=MODELS_DIR,
    )

    # Save a slice of test windows for instant Historical Replay in Streamlit
    DATA_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    replay_cache_path = DATA_PROCESSED_DIR / "test_replay_windows.npz"
    # Take up to 200 consecutive test windows for smooth interactive replay
    replay_limit = min(200, len(X_test_seq))
    np.savez_compressed(
        replay_cache_path,
        X_seq=X_test_seq[:replay_limit],
        X_base=X_test_base[:replay_limit],
        y_true=y_test_seq[:replay_limit],
        lstm_probs=lstm_probs[:replay_limit],
        lr_probs=lr_probs[:replay_limit],
    )
    print(f"[✓] Historical replay sequence cache saved to: {replay_cache_path}")

    print("\n" + "=" * 70)
    print(" TRAINING COMPLETE!")
    print(" Launch the dashboard with:")
    print("   streamlit run app/streamlit_app.py")
    print("=" * 70)


if __name__ == "__main__":
    main()
