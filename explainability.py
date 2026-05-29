#!/usr/bin/env python3
"""
SHAP Explainability Layer for SudoSOC IDS/IPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Provides per-alert SHAP explanations for XGBoost predictions.
"""

import logging
import numpy as np
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("SHAPExplainer")

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    log.warning("shap not installed — explainability disabled (pip install shap)")


class SHAPExplainer:
    def __init__(self, model, feature_names: List[str]):
        self.model = model
        self.feature_names = list(feature_names)
        self.available = SHAP_AVAILABLE
        self._explainer = None
        if self.available:
            try:
                self._explainer = shap.TreeExplainer(model)
                log.info(f"SHAPExplainer initialized ({len(feature_names)} features)")
            except Exception as e:
                log.warning(f"SHAP init failed: {e}")
                self.available = False

    def explain_flow(self, X_scaled: np.ndarray) -> Dict[str, float]:
        if not self.available or self._explainer is None:
            return {}
        try:
            X = np.atleast_2d(X_scaled)
            shap_values = self._explainer.shap_values(X)
            if isinstance(shap_values, list):
                pred_class = int(np.argmax(self.model.predict_proba(X)[0]))
                values = shap_values[pred_class][0]
            else:
                values = shap_values[0]
            return {n: float(v) for n, v in zip(self.feature_names, values)}
        except Exception as e:
            log.debug(f"SHAP error: {e}")
            return {}

    def top_n_features(self, X_scaled: np.ndarray, n: int = 5) -> List[Tuple[str, float]]:
        expl = self.explain_flow(X_scaled)
        if not expl:
            return []
        return sorted(expl.items(), key=lambda x: abs(x[1]), reverse=True)[:n]

    def format_for_llm(self, X_scaled: np.ndarray, raw_values: Optional[Dict[str, float]] = None, n: int = 5) -> str:
        top = self.top_n_features(X_scaled, n)
        if not top:
            return "[SHAP explanations unavailable]"
        lines = ["Key factors driving this classification:"]
        for feat, val in top:
            sign = "+" if val > 0 else ""
            direction = "increases" if val > 0 else "decreases"
            raw = f" (value={raw_values[feat]:.2f})" if raw_values and feat in raw_values else ""
            lines.append(f"  - {feat}{raw}: SHAP {sign}{val:.3f} — {direction} attack likelihood")
        return "\n".join(lines)


class MockExplainer:
    def __init__(self, model=None, feature_names=None):
        self.available = False
        self.feature_names = feature_names or []

    def explain_flow(self, X_scaled) -> Dict[str, float]:
        return {}

    def top_n_features(self, X_scaled, n=5) -> List[Tuple[str, float]]:
        return []

    def format_for_llm(self, X_scaled, raw_values=None, n=5) -> str:
        return "[SHAP not installed — pip install shap]"


def create_explainer(model, feature_names: List[str]):
    if SHAP_AVAILABLE:
        try:
            return SHAPExplainer(model, feature_names)
        except Exception:
            return MockExplainer(model, feature_names)
    return MockExplainer(model, feature_names)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("SHAP Explainer — Self-Test")
    if not SHAP_AVAILABLE:
        print("  [SKIP] shap not installed. pip install shap")
    else:
        print("  [OK] shap module available")
