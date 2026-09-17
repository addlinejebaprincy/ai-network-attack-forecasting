"""
Explainability module using SHAP (SHapley Additive exPlanations).
Answers: "Why is this traffic window considered risky?"
Computes real SHAP feature contributions, ranks top contributors,
and formats them for dashboard presentation.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import shap
import joblib

from .config import MODELS_DIR


class TrafficExplainer:
    """
    Computes real local SHAP explanations for traffic windows against a benign baseline.
    """

    def __init__(
        self,
        model,
        background_data: np.ndarray,
        feature_names: list[str],
        explainer_type: str = "linear",
    ):
        """
        Args:
            model: Trained classifier (LogisticRegression or surrogate)
            background_data: Representative background sample (e.g. 50-100 benign flows)
            feature_names: List of column names
            explainer_type: 'linear' for instant exact SHAP, or 'kernel'
        """
        self.model = model
        self.feature_names = feature_names
        self.background_data = background_data
        self.explainer_type = explainer_type

        # Use 50 representative background instances for stable baseline expectations
        if len(background_data) > 50:
            sample_indices = np.random.RandomState(42).choice(
                len(background_data), size=50, replace=False
            )
            self.bg_sample = background_data[sample_indices]
        else:
            self.bg_sample = background_data

        if explainer_type == "linear":
            # Exact, mathematically guaranteed Shapley values for linear decision boundaries
            self.explainer = shap.LinearExplainer(self.model, self.bg_sample)
        else:
            # Model-agnostic KernelExplainer
            predict_fn = getattr(model, "predict_proba", model.predict)
            self.explainer = shap.KernelExplainer(predict_fn, self.bg_sample)

    def explain_window(
        self, window_vector: np.ndarray, top_k: int = 5
    ) -> tuple[pd.DataFrame, str]:
        """
        Calculates real SHAP attributions for a single traffic window vector.
        Returns a sorted DataFrame of top features, their actual values,
        SHAP contribution value, and contribution intensity (High/Medium/Low).
        """
        if window_vector.ndim == 1:
            vec = window_vector.reshape(1, -1)
        else:
            vec = window_vector

        # Calculate real SHAP values
        raw_shap = self.explainer.shap_values(vec)

        # Handle binary classification output formats (array or list)
        if isinstance(raw_shap, list):
            # Class 1 (Attack) SHAP values
            shap_vals = raw_shap[1][0] if len(raw_shap) > 1 else raw_shap[0][0]
        elif isinstance(raw_shap, np.ndarray) and raw_shap.ndim == 2:
            shap_vals = raw_shap[0]
        else:
            shap_vals = np.array(raw_shap).flatten()

        raw_features = vec[0]
        abs_shap = np.abs(shap_vals)

        # Classify contribution intensity based on relative magnitude
        max_abs = np.max(abs_shap) if len(abs_shap) > 0 and np.max(abs_shap) > 0 else 1.0
        ratios = abs_shap / max_abs

        def get_intensity(ratio: float) -> str:
            if ratio >= 0.65:
                return "High"
            elif ratio >= 0.30:
                return "Medium"
            return "Low"

        # Build structured contribution records
        records = []
        for feat_name, feat_val, s_val, ratio in zip(
            self.feature_names, raw_features, shap_vals, ratios
        ):
            records.append({
                "Feature": feat_name,
                "Value": round(float(feat_val), 4),
                "SHAP_Value": round(float(s_val), 4),
                "Abs_Impact": abs(float(s_val)),
                "Direction": "Increases Risk" if s_val > 0 else "Lowers Risk",
                "Contribution": get_intensity(ratio),
            })

        df_explanations = pd.DataFrame(records)
        # Sort by absolute SHAP impact
        df_explanations = (
            df_explanations.sort_values(by="Abs_Impact", ascending=False)
            .head(top_k)
            .reset_index(drop=True)
        )

        methodology_note = (
            "SHAP Methodology Note: Exact Shapley feature attributions computed against "
            "benign reference traffic background distribution. Positive contributions push "
            "probability towards attack risk; negative contributions act as mitigating benign indicators."
        )

        return df_explanations[["Feature", "Contribution", "Direction", "SHAP_Value", "Value"]], methodology_note


def build_and_cache_explainer(
    model,
    X_background: np.ndarray,
    feature_names: list[str],
    save_path: Path = MODELS_DIR / "shap_explainer.joblib",
) -> TrafficExplainer:
    """
    Initializes and serializes the SHAP explainer for instant load in the dashboard.
    """
    explainer = TrafficExplainer(model, X_background, feature_names, explainer_type="linear")
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(explainer, save_path)
    print(f"[✓] SHAP explainer saved to: {save_path}")
    return explainer
