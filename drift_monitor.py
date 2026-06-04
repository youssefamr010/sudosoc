#!/usr/bin/env python3
"""
Concept Drift Monitor for SudoSOC IDS/IPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detects when live network traffic distributions shift away from
the training-time reference distribution using Population Stability
Index (PSI).

PSI thresholds (industry standard):
  PSI < 0.1   →  No significant drift
  PSI 0.1–0.2 →  Moderate drift (monitor)
  PSI > 0.2   →  Significant drift (retrain recommended)

Usage:
  from drift_monitor import DriftMonitor
  monitor = DriftMonitor(reference_path="ids_output/reference_dist.pkl")
  monitor.update(flow_features_dict)
  report = monitor.get_report()
"""

import os
import time
import logging
import threading
import numpy as np
import joblib
from collections import deque
from typing import Dict, List, Optional, Tuple
from datetime import datetime

log = logging.getLogger("DriftMonitor")

# ── Critical features to monitor for drift ───────────────────────────────────
# These are the features most likely to shift when attack patterns change.
# Monitoring all 30+ features is noisy; focus on the signal-heavy ones.
MONITORED_FEATURES = [
    "bidirectional_bytes",
    "bidirectional_packets",
    "bidirectional_duration_ms",
    "bytes_per_packet",
    "packets_per_sec",
    "bytes_per_sec",
    "dst_port",
    "src_port",
    "payload_entropy",
    "flow_density",
    "packet_to_byte_ratio",
]


class DriftDetector:
    """
    Stateless PSI computation utility.

    PSI (Population Stability Index) measures how much a distribution
    has shifted from a reference. It's the standard metric used in
    credit scoring and anomaly detection for concept drift.

    Formula:
      PSI = Σ (p_i - q_i) * ln(p_i / q_i)
    where p_i = proportion in current bin, q_i = proportion in reference bin.
    """

    @staticmethod
    def compute_psi(reference: np.ndarray, current: np.ndarray,
                    bins: int = 10, epsilon: float = 1e-6) -> float:
        """
        Compute PSI between reference and current distributions.

        Parameters
        ----------
        reference : array-like
            Reference (training-time) feature values.
        current : array-like
            Current (live) feature values.
        bins : int
            Number of bins to discretize into.
        epsilon : float
            Small value added to avoid log(0).

        Returns
        -------
        float
            PSI value. Higher = more drift.
        """
        reference = np.asarray(reference, dtype=float)
        current = np.asarray(current, dtype=float)

        if len(reference) < bins or len(current) < bins:
            return 0.0  # Not enough data to compute meaningful PSI

        # Use reference quantiles as bin edges for consistency
        try:
            breakpoints = np.percentile(reference,
                                        np.linspace(0, 100, bins + 1))
            # Ensure unique breakpoints
            breakpoints = np.unique(breakpoints)
            if len(breakpoints) < 3:
                return 0.0
        except Exception:
            return 0.0

        # Digitize both distributions into the same bins
        ref_counts = np.histogram(reference, bins=breakpoints)[0]
        cur_counts = np.histogram(current, bins=breakpoints)[0]

        # Convert to proportions
        ref_props = (ref_counts + epsilon) / (ref_counts.sum() + epsilon * len(ref_counts))
        cur_props = (cur_counts + epsilon) / (cur_counts.sum() + epsilon * len(cur_counts))

        # PSI formula
        psi = np.sum((cur_props - ref_props) * np.log(cur_props / ref_props))
        return float(psi)

    @staticmethod
    def interpret_psi(psi: float) -> str:
        """Human-readable PSI interpretation."""
        if psi < 0.1:
            return "STABLE"
        elif psi < 0.2:
            return "MODERATE_DRIFT"
        else:
            return "SIGNIFICANT_DRIFT"


class DriftMonitor:
    """
    Monitors live network traffic features for concept drift against
    a saved reference distribution from training time.

    Thread-safe — safe to call update() from the packet processing loop.
    """

    PSI_THRESHOLD = 0.2  # Trigger retrain above this

    def __init__(self, reference_path: str = "ids_output/reference_dist.pkl",
                 window_size: int = 5000):
        """
        Parameters
        ----------
        reference_path : str
            Path to saved reference distributions (created during training).
        window_size : int
            Sliding window size for live feature tracking.
        """
        self.reference_path = reference_path
        self.window_size = window_size
        self._detector = DriftDetector()

        # Sliding windows for each monitored feature: feature_name → deque
        self._windows: Dict[str, deque] = {
            feat: deque(maxlen=window_size)
            for feat in MONITORED_FEATURES
        }

        # Reference distributions: feature_name → np.ndarray
        self._reference: Dict[str, np.ndarray] = {}

        # Latest PSI scores: feature_name → float
        self._psi_scores: Dict[str, float] = {}

        # State
        self._lock = threading.Lock()
        self._samples_since_check = 0
        self._check_interval = 500  # Check drift every N samples
        self._last_check_time = 0.0
        self._drift_detected = False
        self._drift_history: List[Dict] = []  # history of drift events

        # Load reference if available
        self._load_reference()

    def _load_reference(self):
        """Load saved reference distributions from training time."""
        if os.path.exists(self.reference_path):
            try:
                self._reference = joblib.load(self.reference_path)
                log.info(f"DriftMonitor: loaded reference distributions "
                         f"({len(self._reference)} features) from {self.reference_path}")
            except Exception as e:
                log.warning(f"DriftMonitor: could not load reference: {e}")
                self._reference = {}
        else:
            log.info("DriftMonitor: no reference distribution found — "
                     "will build from first window of live data")

    def update(self, flow_features: Dict[str, float]):
        """
        Feed a new flow's features into the monitor.
        Call this for every processed packet/flow.

        Parameters
        ----------
        flow_features : dict
            Feature name → value for a single flow.
        """
        with self._lock:
            for feat in MONITORED_FEATURES:
                val = flow_features.get(feat)
                if val is not None:
                    try:
                        self._windows[feat].append(float(val))
                    except (ValueError, TypeError):
                        pass

            self._samples_since_check += 1

            # Periodic drift check
            if self._samples_since_check >= self._check_interval:
                self._samples_since_check = 0
                self._run_drift_check()

    def _run_drift_check(self):
        """Compute PSI for all monitored features against reference."""
        now = time.time()

        # Build reference from first full window if none loaded
        if not self._reference:
            has_enough = all(
                len(self._windows[f]) >= self.window_size * 0.8
                for f in MONITORED_FEATURES
                if len(self._windows[f]) > 0
            )
            if has_enough:
                self._reference = {
                    feat: np.array(list(window))
                    for feat, window in self._windows.items()
                    if len(window) > 100
                }
                self._save_reference()
                log.info(f"DriftMonitor: built reference from live data "
                         f"({len(self._reference)} features)")
            return

        # Compute PSI per feature
        drift_features = []
        for feat in MONITORED_FEATURES:
            ref = self._reference.get(feat)
            if ref is None or len(self._windows[feat]) < 100:
                continue

            current = np.array(list(self._windows[feat]))
            psi = self._detector.compute_psi(ref, current)
            self._psi_scores[feat] = psi

            if psi > self.PSI_THRESHOLD:
                drift_features.append((feat, psi))

        # Determine overall drift status
        was_drifting = self._drift_detected
        self._drift_detected = len(drift_features) >= 2  # 2+ features drifting

        if self._drift_detected and not was_drifting:
            event = {
                "timestamp": datetime.now().isoformat(),
                "drifted_features": {f: round(p, 4) for f, p in drift_features},
                "action": "RETRAIN_RECOMMENDED",
            }
            self._drift_history.append(event)
            log.warning(f"DRIFT DETECTED — {len(drift_features)} features shifted: "
                        f"{', '.join(f'{f}={p:.3f}' for f, p in drift_features)}")

        self._last_check_time = now

    def _save_reference(self):
        """Persist current reference distributions to disk."""
        try:
            os.makedirs(os.path.dirname(self.reference_path) or ".", exist_ok=True)
            joblib.dump(self._reference, self.reference_path)
            log.info(f"DriftMonitor: saved reference to {self.reference_path}")
        except Exception as e:
            log.error(f"DriftMonitor: save failed: {e}")

    @staticmethod
    def save_training_reference(df, output_path: str = "ids_output/reference_dist.pkl"):
        """
        Call this at training time to save reference distributions.

        Parameters
        ----------
        df : pd.DataFrame
            The training DataFrame (after feature engineering).
        output_path : str
            Path to save the reference .pkl file.
        """
        reference = {}
        for feat in MONITORED_FEATURES:
            if feat in df.columns:
                vals = df[feat].dropna().values
                if len(vals) > 100:
                    # Store a representative sample (max 50K) to keep file small
                    if len(vals) > 50000:
                        rng = np.random.RandomState(42)
                        vals = rng.choice(vals, size=50000, replace=False)
                    reference[feat] = vals.astype(np.float32)

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        joblib.dump(reference, output_path)
        log.info(f"DriftMonitor: saved training reference ({len(reference)} features) "
                 f"to {output_path}")
        return reference

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def is_drifting(self) -> bool:
        """True if significant drift has been detected."""
        return self._drift_detected

    def get_report(self) -> Dict:
        """
        Returns a summary report of drift status.
        Used by the dashboard and scheduler.
        """
        with self._lock:
            return {
                "drift_detected": self._drift_detected,
                "psi_scores": dict(self._psi_scores),
                "interpretations": {
                    feat: DriftDetector.interpret_psi(psi)
                    for feat, psi in self._psi_scores.items()
                },
                "window_sizes": {
                    feat: len(window)
                    for feat, window in self._windows.items()
                },
                "last_check": datetime.fromtimestamp(self._last_check_time).isoformat()
                              if self._last_check_time > 0 else "never",
                "drift_history": list(self._drift_history[-10:]),  # last 10 events
                "reference_loaded": bool(self._reference),
                "threshold": self.PSI_THRESHOLD,
            }

    def reset(self):
        """Clear all windows and rebuild reference from scratch."""
        with self._lock:
            for window in self._windows.values():
                window.clear()
            self._psi_scores.clear()
            self._drift_detected = False
            self._samples_since_check = 0
            log.info("DriftMonitor: reset complete")


# ── CLI test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s  %(name)s  %(levelname)s  %(message)s")

    print("=" * 55)
    print("  Drift Monitor — Self-Test")
    print("=" * 55)

    # Test 1: PSI computation on stable distributions
    det = DriftDetector()
    ref = np.random.normal(100, 15, size=5000)
    cur_stable = np.random.normal(100, 15, size=5000)
    cur_drifted = np.random.normal(130, 25, size=5000)

    psi_stable = det.compute_psi(ref, cur_stable)
    psi_drifted = det.compute_psi(ref, cur_drifted)

    print(f"\n  [1] PSI (stable):  {psi_stable:.4f}  -> {det.interpret_psi(psi_stable)}")
    print(f"  [2] PSI (drifted): {psi_drifted:.4f}  -> {det.interpret_psi(psi_drifted)}")

    assert psi_stable < 0.1, f"Stable PSI too high: {psi_stable}"
    assert psi_drifted > 0.1, f"Drifted PSI too low: {psi_drifted}"

    # Test 2: DriftMonitor with simulated flows
    monitor = DriftMonitor(reference_path="__test_ref.pkl", window_size=500)

    # Feed stable reference
    for _ in range(600):
        monitor.update({
            "bidirectional_bytes": np.random.normal(5000, 1000),
            "bidirectional_packets": np.random.normal(20, 5),
            "dst_port": np.random.choice([80, 443, 8080]),
        })

    report = monitor.get_report()
    print(f"\n  [3] Monitor report (stable): drift={report['drift_detected']}")

    # Cleanup test file
    if os.path.exists("__test_ref.pkl"):
        os.remove("__test_ref.pkl")

    print("\n  All drift monitor tests passed.\n")
