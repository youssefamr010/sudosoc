"""
Adaptive Policy Layer for the real-time IDS.

Goal:
  - Reduce repeated false positives immediately (no retrain required).
  - Keep the policy simple, explicit, and auditable.

How it works:
  - Reads analyst feedback from `data/online_learning.csv`.
  - Builds suppression rules for (proto, dst_port, original_label) patterns that
    analysts repeatedly mark as NORMAL.
  - The real-time engine can consult this policy before escalating an ML alert.
"""

from __future__ import annotations

import csv
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class SuppressionKey:
    proto: str            # "TCP" / "UDP" / "ICMP"
    dst_port: int
    original_label: str   # model label that was flagged (e.g. "EXPLOIT")


def _proto_num_to_name(proto_num: object) -> str:
    try:
        p = int(proto_num)
    except Exception:
        return "OTHER"
    if p == 6:
        return "TCP"
    if p == 17:
        return "UDP"
    if p == 1:
        return "ICMP"
    return "OTHER"


class AdaptivePolicy:
    """
    Loads false-positive suppressions derived from analyst feedback.

    A suppression activates when we have at least `min_fp` instances of:
      analyst_verdict == "NORMAL" AND original_label == <label>
    for the same (proto, dst_port, original_label).
    """

    def __init__(
        self,
        feedback_csv: str = "data/online_learning.csv",
        min_fp: int = 3,
        reload_interval_s: int = 3,
    ) -> None:
        self.feedback_csv = feedback_csv
        self.min_fp = int(min_fp)
        self.reload_interval_s = int(reload_interval_s)

        self._last_check = 0.0
        self._last_mtime: float = -1.0
        self._fp_counts: Dict[SuppressionKey, int] = {}

    def _maybe_reload(self) -> None:
        now = time.time()
        if now - self._last_check < self.reload_interval_s:
            return
        self._last_check = now

        if not os.path.exists(self.feedback_csv):
            self._fp_counts = {}
            self._last_mtime = -1.0
            return

        try:
            mtime = os.path.getmtime(self.feedback_csv)
        except Exception:
            return

        if mtime == self._last_mtime:
            return

        counts: Dict[SuppressionKey, int] = {}
        try:
            with open(self.feedback_csv, "r", encoding="utf-8", errors="ignore", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    verdict = str(row.get("analyst_verdict", "")).upper().strip()
                    original_label = str(row.get("original_label", "")).upper().strip()
                    if verdict != "NORMAL":
                        continue
                    if not original_label:
                        continue

                    proto = _proto_num_to_name(row.get("protocol", 0))
                    try:
                        dst_port = int(float(row.get("dst_port", 0) or 0))
                    except Exception:
                        dst_port = 0

                    key = SuppressionKey(proto=proto, dst_port=dst_port, original_label=original_label)
                    counts[key] = counts.get(key, 0) + 1
        except Exception:
            return

        self._fp_counts = counts
        self._last_mtime = mtime

    def fp_count(self, proto: str, dst_port: int, original_label: str) -> int:
        self._maybe_reload()
        key = SuppressionKey(
            proto=str(proto).upper().strip(),
            dst_port=int(dst_port),
            original_label=str(original_label).upper().strip(),
        )
        return int(self._fp_counts.get(key, 0))

    def should_suppress(
        self,
        proto: str,
        dst_port: int,
        original_label: str,
        model_conf: float,
        strong_conf_threshold: float = 0.90,
    ) -> Tuple[bool, str]:
        """
        Returns (suppress?, reason).

        We suppress only when:
          - the analyst has marked this pattern NORMAL at least `min_fp` times
          - AND the model is not extremely confident (avoid suppressing true novel attacks)
        """
        n_fp = self.fp_count(proto, dst_port, original_label)
        if n_fp < self.min_fp:
            return False, ""
        if float(model_conf) >= float(strong_conf_threshold):
            return False, ""
        reason = f"FP_SUPPRESS:{proto}/{dst_port}/{original_label} (fp_count={n_fp})"
        return True, reason

