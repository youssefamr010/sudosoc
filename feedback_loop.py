#!/usr/bin/env python3
"""
Feedback Loop & Adaptive Retraining Scheduler for SudoSOC IDS/IPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Captures analyst confirmations/rejections and schedules model retraining.
"""

import os
import csv
import time
import logging
import threading
from datetime import datetime
from typing import Dict, Optional

log = logging.getLogger("FeedbackLoop")

FEEDBACK_FILE = "data/online_learning.csv"
FEEDBACK_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "bidirectional_packets", "bidirectional_bytes", "bidirectional_duration_ms",
    "payload_entropy", "payload_len_var", "is_high_volume",
    "original_label", "analyst_verdict", "analyst_notes", "alert_rule",
    "label",  # final label used for training (= analyst_verdict)
]


class FeedbackCollector:
    """
    Captures analyst feedback on alerts and writes it to CSV
    for the incremental trainer to consume.
    """

    def __init__(self, feedback_path: str = FEEDBACK_FILE):
        self.feedback_path = feedback_path
        self._lock = threading.Lock()
        self._total_feedback = 0
        self._ensure_file()

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.feedback_path) or ".", exist_ok=True)
        if not os.path.exists(self.feedback_path):
            with open(self.feedback_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(FEEDBACK_COLUMNS)
            log.info(f"Created feedback file: {self.feedback_path}")

    def record_feedback(self, flow_features: Dict, original_label: str,
                        analyst_verdict: str, alert_rule: str = "",
                        analyst_notes: str = ""):
        """
        Record an analyst's confirmation or correction of an alert.

        Parameters
        ----------
        flow_features : dict
            The flow's feature dict (from packet processing).
        original_label : str
            What the model predicted (e.g., "EXPLOIT", "NORMAL").
        analyst_verdict : str
            What the analyst says it actually is ("ATTACK", "NORMAL", etc.).
        alert_rule : str
            The rule that triggered the alert.
        analyst_notes : str
            Free-text notes from the analyst.
        """
        with self._lock:
            row = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": flow_features.get("src_ip", ""),
                "dst_ip": flow_features.get("dst_ip", ""),
                "src_port": flow_features.get("src_port", 0),
                "dst_port": flow_features.get("dst_port", 0),
                "protocol": flow_features.get("protocol", 0),
                "bidirectional_packets": flow_features.get("bidirectional_packets", 0),
                "bidirectional_bytes": flow_features.get("bidirectional_bytes", 0),
                "bidirectional_duration_ms": flow_features.get("bidirectional_duration_ms", 0),
                "payload_entropy": flow_features.get("payload_entropy", 0),
                "payload_len_var": flow_features.get("payload_len_var", 0),
                "is_high_volume": flow_features.get("is_high_volume", 0),
                "original_label": original_label,
                "analyst_verdict": analyst_verdict,
                "analyst_notes": analyst_notes,
                "alert_rule": alert_rule,
                "label": analyst_verdict,  # training label
            }

            try:
                with open(self.feedback_path, "a", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=FEEDBACK_COLUMNS)
                    writer.writerow(row)
                self._total_feedback += 1
                log.info(f"Feedback recorded: {original_label} → {analyst_verdict} "
                         f"(total: {self._total_feedback})")
            except Exception as e:
                log.error(f"Failed to write feedback: {e}")

    def record_false_positive(self, flow_features: Dict, original_label: str,
                              alert_rule: str = ""):
        """Shortcut: mark an alert as a false positive (actually NORMAL)."""
        self.record_feedback(
            flow_features, original_label,
            analyst_verdict="NORMAL",
            alert_rule=alert_rule,
            analyst_notes="Analyst confirmed false positive",
        )

    def record_true_positive(self, flow_features: Dict, original_label: str,
                             alert_rule: str = ""):
        """Shortcut: confirm an alert as a true positive."""
        self.record_feedback(
            flow_features, original_label,
            analyst_verdict=original_label,
            alert_rule=alert_rule,
            analyst_notes="Analyst confirmed true positive",
        )

    def get_pending_count(self) -> int:
        """Count unprocessed feedback samples."""
        try:
            if not os.path.exists(self.feedback_path):
                return 0
            with open(self.feedback_path, "r", encoding="utf-8") as f:
                return max(0, sum(1 for _ in f) - 1)  # minus header
        except Exception:
            return 0

    @property
    def total_feedback(self) -> int:
        return self._total_feedback


class AdaptiveScheduler:
    """
    Background daemon that monitors drift signals and feedback volume,
    triggering incremental model retraining when conditions are met.

    Retrain triggers:
      1. 50+ new feedback samples accumulated
      2. Drift detector fires (PSI > 0.2 on 2+ features)
      3. 6 hours since last retrain (scheduled fallback)
    """

    def __init__(self, drift_monitor=None, feedback_collector=None,
                 retrain_callback=None):
        self.drift_monitor = drift_monitor
        self.feedback = feedback_collector
        self.retrain_callback = retrain_callback

        # Keep the loop responsive: a small amount of analyst feedback should
        # change the model quickly in a lab / SOC simulation setting.
        self._min_feedback_samples = 10
        self._max_retrain_interval = 6 * 3600  # 6 hours
        self._check_interval = 30  # check every 30 seconds
        self._last_retrain_time = time.time()
        self._retrain_count = 0
        self._stop_evt = threading.Event()
        self._thread = None

    def start(self):
        """Start the background scheduler thread."""
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="AdaptiveScheduler"
        )
        self._thread.start()
        log.info("AdaptiveScheduler started (checking every "
                 f"{self._check_interval}s)")

    def stop(self):
        self._stop_evt.set()

    def _run_loop(self):
        while not self._stop_evt.is_set():
            time.sleep(self._check_interval)
            try:
                if self._should_retrain():
                    self._trigger_retrain()
            except Exception as e:
                log.error(f"Scheduler error: {e}")

    def _should_retrain(self) -> bool:
        elapsed = time.time() - self._last_retrain_time

        # Check feedback volume
        if self.feedback and self.feedback.get_pending_count() >= self._min_feedback_samples:
            log.info(f"Retrain trigger: {self.feedback.get_pending_count()} "
                     f"feedback samples pending")
            return True

        # Check drift
        if self.drift_monitor and self.drift_monitor.is_drifting:
            log.info("Retrain trigger: concept drift detected")
            return True

        # Scheduled fallback
        if elapsed >= self._max_retrain_interval:
            log.info(f"Retrain trigger: {elapsed/3600:.1f}h since last retrain")
            return True

        return False

    def _trigger_retrain(self):
        log.info("=" * 50)
        log.info("  ADAPTIVE RETRAIN TRIGGERED")
        log.info("=" * 50)

        if self.retrain_callback:
            try:
                self.retrain_callback()
                self._retrain_count += 1
                self._last_retrain_time = time.time()
                log.info(f"Retrain #{self._retrain_count} completed successfully")
                
                # Reset drift monitor after retraining so it can build a new 
                # baseline from the updated model's context.
                if self.drift_monitor:
                    self.drift_monitor.reset()
            except Exception as e:
                log.error(f"Retrain failed: {e}")
        else:
            # Fallback: run advanced_trainer.py as subprocess
            import subprocess
            try:
                result = subprocess.run(
                    ["python", "advanced_trainer.py"],
                    capture_output=True, text=True, timeout=300,
                    cwd=os.path.dirname(os.path.abspath(__file__))
                )
                if result.returncode == 0:
                    self._retrain_count += 1
                    self._last_retrain_time = time.time()
                    log.info(f"Retrain #{self._retrain_count} via subprocess OK")
                    if self.drift_monitor:
                        self.drift_monitor.reset()
                else:
                    log.error(f"Retrain subprocess failed: {result.stderr[:200]}")
            except Exception as e:
                log.error(f"Retrain subprocess error: {e}")

    def get_status(self) -> Dict:
        return {
            "retrain_count": self._retrain_count,
            "last_retrain": datetime.fromtimestamp(self._last_retrain_time).isoformat(),
            "seconds_since_retrain": int(time.time() - self._last_retrain_time),
            "pending_feedback": self.feedback.get_pending_count() if self.feedback else 0,
            "drift_active": self.drift_monitor.is_drifting if self.drift_monitor else False,
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Feedback Loop — Self-Test")

    fc = FeedbackCollector(feedback_path="data/online_learning.csv")
    print(f"  Pending feedback: {fc.get_pending_count()}")
    print("  [OK] FeedbackCollector initialized")
