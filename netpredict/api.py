"""FastAPI backend for the NetPredict local prototype."""

from contextlib import asynccontextmanager
import json
from pathlib import Path
import sys
from typing import Any

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent
MODELS_DIR = PROJECT_ROOT / "models"
REPLAY_PATH = PROJECT_ROOT / "data" / "processed" / "test_replay_windows.npz"
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import DEFAULT_RISK_THRESHOLDS


class PredictionRequest(BaseModel):
    features: list[float]


class ArtifactStore:
    """Artifacts loaded once when the application starts."""

    def __init__(self) -> None:
        required_paths = {
            "scaler": MODELS_DIR / "scaler.joblib",
            "logistic regression model": MODELS_DIR / "logistic_regression.joblib",
            "feature names": MODELS_DIR / "feature_names.joblib",
            "metrics": MODELS_DIR / "model_metrics.json",
            "SHAP explainer": MODELS_DIR / "shap_explainer.joblib",
            "replay data": REPLAY_PATH,
        }
        missing = [f"{name}: {path}" for name, path in required_paths.items() if not path.exists()]
        if missing:
            raise FileNotFoundError(
                "Required NetPredict artifact files are missing: " + "; ".join(missing)
            )

        self.scaler = joblib.load(required_paths["scaler"])
        self.lr_model = joblib.load(required_paths["logistic regression model"])
        self.feature_names = joblib.load(required_paths["feature names"])
        with required_paths["metrics"].open("r", encoding="utf-8") as metrics_file:
            self.metrics = json.load(metrics_file)
        self.explainer = joblib.load(required_paths["SHAP explainer"])

        with np.load(required_paths["replay data"]) as replay_data:
            self.replay = {
                "y_true": replay_data["y_true"][:200].tolist(),
                "lr_probs": replay_data["lr_probs"][:200].tolist(),
                "lstm_probs": replay_data["lstm_probs"][:200].tolist(),
                "features": replay_data["X_base"][:200].tolist(),
            }


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.artifacts = ArtifactStore()
    yield


app = FastAPI(title="NetPredict API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_artifacts() -> ArtifactStore:
    artifacts = getattr(app.state, "artifacts", None)
    if artifacts is None:
        raise HTTPException(status_code=503, detail="Model artifacts are not loaded")
    return artifacts


def validate_features(features: list[float], artifacts: ArtifactStore) -> np.ndarray:
    expected_count = len(artifacts.feature_names)
    if len(features) != expected_count:
        raise HTTPException(
            status_code=400,
            detail=f"Expected {expected_count} features, received {len(features)}",
        )
    if not all(np.isfinite(value) for value in features):
        raise HTTPException(status_code=400, detail="Features must be finite numbers")
    return np.asarray(features, dtype=np.float64).reshape(1, -1)


def determine_risk_level(probability: float) -> str:
    if probability >= DEFAULT_RISK_THRESHOLDS["CRITICAL"][0]:
        return "CRITICAL"
    if probability >= DEFAULT_RISK_THRESHOLDS["HIGH"][0]:
        return "HIGH"
    if probability >= DEFAULT_RISK_THRESHOLDS["MEDIUM"][0]:
        return "MEDIUM"
    return "LOW"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/metrics")
def metrics() -> dict[str, Any]:
    return get_artifacts().metrics


@app.get("/replay")
def replay() -> dict[str, list[Any]]:
    return get_artifacts().replay


@app.post("/predict")
def predict(request: PredictionRequest) -> dict[str, Any]:
    artifacts = get_artifacts()
    features = validate_features(request.features, artifacts)
    scaled_features = artifacts.scaler.transform(features)
    probability = float(artifacts.lr_model.predict_proba(scaled_features)[0, 1])

    return {
        "probability": probability,
        "predicted_label": "ATTACK" if probability >= 0.5 else "BENIGN",
        "risk_level": determine_risk_level(probability),
    }


@app.get("/shap")
def shap_explanation(
    features: list[float] = Query(..., description="Raw feature values, in trained feature order"),
) -> dict[str, Any]:
    artifacts = get_artifacts()
    feature_array = validate_features(features, artifacts)
    scaled_features = artifacts.scaler.transform(feature_array)
    try:
        explanation, methodology_note = artifacts.explainer.explain_window(scaled_features)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to calculate SHAP explanation: {exc}") from exc

    return {
        "explanations": explanation.to_dict(orient="records"),
        "methodology_note": methodology_note,
    }