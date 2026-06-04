#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  IDS / IPS  --  Scenario Test Harness + Online Retraining         ║
║                                                                  ║
║   Goals (no core function is changed - only orchestrated):       ║
║     1) Generate realistic attack scenarios:                      ║
║          - Port Scan        (PROBE)                              ║
║          - DDoS / Flood     (DOS)                                ║
║          - Data Exfiltration / C2 beacon  (EXPLOIT)              ║
║     2) Run the current trained IDSPredictor over them and        ║
║        capture BEFORE-training confidence per scenario.          ║
║     3) Inject the labeled scenarios into the online_learning     ║
║        feedback CSV (the trainer already auto-boosts that x10)   ║
║        and rerun the trainer to update the saved model.          ║
║     4) Reload the predictor and capture AFTER-training           ║
║        confidence per scenario.                                  ║
║     5) Persist a JSON + Markdown report with before/after        ║
║        deltas and save model snapshots (.joblib) for             ║
║        rollback / reproducibility.                               ║
║                                                                  ║
║   Run:                                                           ║
║     python test_scenarios.py                  # full pipeline    ║
║     python test_scenarios.py --no-retrain     # only test        ║
║     python test_scenarios.py --quick          # smaller dataset  ║
║                                                                  ║
║   Output files (in test_results/):                               ║
║     - scenarios.csv                  (the generated flows)       ║
║     - before_predictions.csv                                     ║
║     - after_predictions.csv                                      ║
║     - confidence_report.json                                     ║
║     - confidence_report.md                                       ║
║     - model_snapshot_before.joblib                               ║
║     - model_snapshot_after.joblib                                ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import sys
import json
import time
import shutil
import random
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

# Speed up: limit BLAS threads to avoid oversubscription on small jobs
os.environ.setdefault("OMP_NUM_THREADS", str(max(1, (os.cpu_count() or 4) // 2)))
os.environ.setdefault("OPENBLAS_NUM_THREADS", os.environ["OMP_NUM_THREADS"])

import joblib

# ---- Project paths -------------------------------------------------------
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "ids_output"
OUT_DIR = ROOT / "test_results"
OUT_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

# We import lazily so that the script still parses on machines without ML deps.
def _import_predictor():
    from ids_ips_trainer import IDSPredictor  # noqa: WPS433
    return IDSPredictor


# ══════════════════════════════════════════════════════════════════════════
#  1.  SCENARIO GENERATORS
# ══════════════════════════════════════════════════════════════════════════
#
#  Each generator returns a list[dict] of flow records that the predictor's
#  predict_flow() expects:
#       src_ip, dst_ip, src_port, dst_port, protocol,
#       bidirectional_packets, bidirectional_bytes, bidirectional_duration_ms
#
#  We also tag a "scenario" + "label" + "attack_category" so we can both
#  train on them and group results in the report.

INTERNAL_SUBNETS = ["10.10.20.{}", "192.168.1.{}", "172.16.5.{}"]
EXTERNAL_TARGETS = ["149.171.126.{}", "203.0.113.{}", "198.51.100.{}"]


def _ip(pool: List[str], rng: random.Random) -> str:
    return rng.choice(pool).format(rng.randint(2, 254))


def gen_port_scan(n: int = 120, seed: int = 7) -> List[dict]:
    """Many short connections, varying dst_port, from one attacker."""
    rng = random.Random(seed)
    rows: List[dict] = []
    attacker = _ip(INTERNAL_SUBNETS, rng)
    # Mix of common service ports + classic backdoor ports the model knows about
    ports = [22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
             1337, 1433, 2049, 3306, 3389, 4444, 5432, 5555, 5900,
             6379, 8080, 8443, 9200, 9999, 31337]
    for _ in range(n):
        rows.append({
            "src_ip": attacker,
            "dst_ip": _ip(EXTERNAL_TARGETS, rng),
            "src_port": rng.randint(30000, 65000),
            "dst_port": rng.choice(ports),
            "protocol": 6,  # TCP
            "bidirectional_packets": rng.randint(1, 4),
            "bidirectional_bytes": rng.randint(40, 300),
            "bidirectional_duration_ms": rng.choice([0, 0, 0, 5, 12]),
            "payload_entropy": rng.uniform(2.0, 4.5),
            "payload_len_var": rng.uniform(0.0, 5.0),
            "scenario": "port_scan",
            "label": "ATTACK",
            "attack_category": "PROBE",
        })
    return rows


def gen_ddos_flood(n: int = 100, seed: int = 11) -> List[dict]:
    """High packet/byte rate volumetric attack to web ports."""
    rng = random.Random(seed)
    rows: List[dict] = []
    targets = ["149.171.126.{}".format(rng.randint(2, 30)) for _ in range(3)]
    for _ in range(n):
        pkts = rng.randint(1500, 5000)
        bts  = pkts * rng.randint(800, 1500)
        dur  = rng.randint(200, 900)  # ms
        rows.append({
            "src_ip": _ip(["59.166.0.{}", "175.45.176.{}"], rng),
            "dst_ip": rng.choice(targets),
            "src_port": rng.randint(30000, 65000),
            "dst_port": rng.choice([80, 443, 8080]),
            "protocol": 6,
            "bidirectional_packets": pkts,
            "bidirectional_bytes": bts,
            "bidirectional_duration_ms": dur,
            "payload_entropy": rng.uniform(6.5, 7.9),
            "payload_len_var": rng.uniform(20.0, 90.0),
            "scenario": "ddos_flood",
            "label": "ATTACK",
            "attack_category": "DOS",
        })
    return rows


def gen_data_exfiltration(n: int = 100, seed: int = 13) -> List[dict]:
    """
    Internal -> external low-and-slow C2 / exfil beacons.
    The default guardrails BIAS web ports toward NORMAL when pps and bps are
    modest, so this is the most interesting case to retrain on: the model
    should learn to label this EXPLOIT/ATTACK *despite* the guardrail.
    """
    rng = random.Random(seed)
    rows: List[dict] = []
    c2 = "203.0.113.{}".format(rng.randint(10, 50))
    for _ in range(n):
        pkts = rng.randint(210, 450)
        bts  = rng.randint(50_000, 250_000)
        dur  = rng.randint(800, 4_500)  # slow-and-low
        rows.append({
            "src_ip": _ip(INTERNAL_SUBNETS, rng),
            "dst_ip": c2,
            "src_port": rng.randint(40000, 65000),
            "dst_port": rng.choice([443, 8443]),
            "protocol": 6,
            "bidirectional_packets": pkts,
            "bidirectional_bytes": bts,
            "bidirectional_duration_ms": dur,
            "payload_entropy": rng.uniform(7.4, 7.95),  # high entropy = encrypted exfil
            "payload_len_var": rng.uniform(1.0, 8.0),
            "scenario": "exfiltration",
            "label": "ATTACK",
            "attack_category": "EXPLOIT",
        })
    return rows


def gen_benign(n: int = 60, seed: int = 5) -> List[dict]:
    """Sanity control: ordinary web browsing."""
    rng = random.Random(seed)
    rows: List[dict] = []
    for _ in range(n):
        pkts = rng.randint(8, 60)
        rows.append({
            "src_ip": _ip(INTERNAL_SUBNETS, rng),
            "dst_ip": _ip(EXTERNAL_TARGETS, rng),
            "src_port": rng.randint(40000, 65000),
            "dst_port": rng.choice([80, 443]),
            "protocol": 6,
            "bidirectional_packets": pkts,
            "bidirectional_bytes": pkts * rng.randint(180, 600),
            "bidirectional_duration_ms": rng.randint(120, 1500),
            "payload_entropy": rng.uniform(4.0, 6.0),
            "payload_len_var": rng.uniform(10.0, 60.0),
            "scenario": "benign_web",
            "label": "NORMAL",
            "attack_category": "NORMAL",
        })
    return rows


def build_scenarios(quick: bool = False, seed: int = 42) -> pd.DataFrame:
    if quick:
        rows = (gen_port_scan(40) + gen_ddos_flood(30)
                + gen_data_exfiltration(30) + gen_benign(20))
    else:
        rows = (gen_port_scan() + gen_ddos_flood()
                + gen_data_exfiltration() + gen_benign())
    df = pd.DataFrame(rows)
    df.to_csv(OUT_DIR / "scenarios.csv", index=False)
    print(f"[+] Generated {len(df):,} test flows  ({df['scenario'].value_counts().to_dict()})")
    return df


# ══════════════════════════════════════════════════════════════════════════
#  2.  PREDICT + REPORT
# ══════════════════════════════════════════════════════════════════════════

REQUIRED_FLOW_COLS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "bidirectional_packets", "bidirectional_bytes", "bidirectional_duration_ms",
    "payload_entropy", "payload_len_var",
]


def run_predictions(df_flows: pd.DataFrame, predictor) -> pd.DataFrame:
    """Fast per-flow predictions using the existing predict_flow API.
    Intentionally uses the public API so we don't change core behaviour."""
    rows = []
    for r in df_flows.to_dict(orient="records"):
        flow = {k: r[k] for k in REQUIRED_FLOW_COLS if k in r}
        try:
            res = predictor.predict_flow(flow)
        except Exception as e:
            res = {
                "label": "ERROR",
                "confidence": 0.0,
                "action": "ALLOW",
                "is_attack": False,
                "all_probs": {},
                "raw_label": "ERROR",
                "raw_confidence": 0.0,
                "error": str(e),
            }
        rows.append({
            "scenario": r.get("scenario"),
            "true_label": r.get("label"),
            "attack_category": r.get("attack_category"),
            "pred_label": res.get("label"),
            "pred_action": res.get("action"),
            "pred_confidence": float(res.get("confidence", 0.0)),
            "raw_label": res.get("raw_label", res.get("label")),
            "raw_confidence": float(res.get("raw_confidence", res.get("confidence", 0.0))),
            "is_attack": bool(res.get("is_attack", False)),
            **{f"prob_{k}": float(v) for k, v in (res.get("all_probs") or {}).items()},
        })
    return pd.DataFrame(rows)


def summarize(df_pred: pd.DataFrame) -> Dict:
    """Per-scenario summary: avg confidence, detection rate, label distribution."""
    out = {}
    for scenario, g in df_pred.groupby("scenario"):
        is_attack_scenario = (g["true_label"].iloc[0] == "ATTACK")
        if is_attack_scenario:
            detected = (g["is_attack"] == True).mean()
        else:
            detected = (g["is_attack"] == False).mean()  # for benign, "correct" = ALLOW
        out[scenario] = {
            "samples":            int(len(g)),
            "true_label":         g["true_label"].iloc[0],
            "expected_category":  g["attack_category"].iloc[0],
            "avg_confidence":     float(g["pred_confidence"].mean()),
            "avg_raw_confidence": float(g["raw_confidence"].mean()),
            "detection_rate":     float(detected),
            "predicted_labels":   g["pred_label"].value_counts().to_dict(),
        }
    return out


# ══════════════════════════════════════════════════════════════════════════
#  3.  ONLINE RETRAINING
# ══════════════════════════════════════════════════════════════════════════
#
#  The trainer (ids_ips_trainer.py) automatically picks up
#  data/online_learning.csv and boosts each row x10 during training.
#  We don't change that core logic - we just append our labeled scenarios.

ONLINE_CSV = DATA_DIR / "online_learning.csv"

ONLINE_COLS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "bidirectional_packets", "bidirectional_bytes", "bidirectional_duration_ms",
    "payload_entropy", "payload_len_var",
    "is_high_volume", "original_label", "analyst_verdict", "analyst_notes",
    "alert_rule", "label",
]


def append_online_learning(df_flows: pd.DataFrame) -> int:
    ts = pd.Timestamp.utcnow().isoformat()
    rows = []
    for r in df_flows.to_dict(orient="records"):
        rows.append({
            "timestamp": ts,
            "src_ip": r["src_ip"], "dst_ip": r["dst_ip"],
            "src_port": r["src_port"], "dst_port": r["dst_port"],
            "protocol": r["protocol"],
            "bidirectional_packets": r["bidirectional_packets"],
            "bidirectional_bytes": r["bidirectional_bytes"],
            "bidirectional_duration_ms": r["bidirectional_duration_ms"],
            "payload_entropy": r.get("payload_entropy", 0.0),
            "payload_len_var": r.get("payload_len_var", 0.0),
            "is_high_volume": int(r["bidirectional_bytes"] > 1_000_000),
            "original_label": "NORMAL" if r["label"] == "NORMAL" else "ATTACK",
            "analyst_verdict": r["attack_category"],
            "analyst_notes": f"scenario:{r['scenario']}",
            "alert_rule": "test_scenarios.py",
            "label": r["attack_category"],
        })
    df_new = pd.DataFrame(rows, columns=ONLINE_COLS)

    if ONLINE_CSV.exists() and ONLINE_CSV.stat().st_size > 0:
        try:
            old = pd.read_csv(ONLINE_CSV)
            # align columns to avoid pandas FutureWarning
            for c in ONLINE_COLS:
                if c not in old.columns:
                    old[c] = ""
            df_out = pd.concat([old[ONLINE_COLS], df_new], ignore_index=True)
        except Exception:
            df_out = df_new
    else:
        df_out = df_new

    df_out.to_csv(ONLINE_CSV, index=False)
    return len(df_new)


def snapshot_model(suffix: str) -> Path:
    """Copies the current ids_output/*.pkl into a joblib snapshot bundle."""
    snap_path = OUT_DIR / f"model_snapshot_{suffix}.joblib"
    bundle = {}
    for fname in ("ids_model.pkl", "ids_scaler.pkl", "ids_metadata.pkl"):
        f = MODEL_DIR / fname
        if f.exists():
            bundle[fname] = joblib.load(f)
    joblib.dump(bundle, snap_path, compress=3)
    return snap_path


def run_trainer() -> int:
    """Calls ids_ips_trainer.py as a subprocess to keep core function untouched."""
    cmd = [sys.executable, "ids_ips_trainer.py"]
    print(f"[+] Retraining model -> {' '.join(cmd)}")
    t0 = time.time()
    proc = subprocess.run(cmd, cwd=str(ROOT))
    print(f"[+] Trainer finished in {time.time() - t0:.1f}s (returncode={proc.returncode})")
    return proc.returncode


# ══════════════════════════════════════════════════════════════════════════
#  4.  REPORTS
# ══════════════════════════════════════════════════════════════════════════

def build_report(before: Dict, after: Dict, before_df: pd.DataFrame,
                 after_df: pd.DataFrame, retrained: bool) -> Dict:
    rows = []
    scenarios = sorted(set(list(before.keys()) + list(after.keys())))
    for s in scenarios:
        b = before.get(s, {})
        a = after.get(s, {})
        rows.append({
            "scenario": s,
            "samples": b.get("samples"),
            "true_label": b.get("true_label"),
            "expected_category": b.get("expected_category"),
            "before_avg_confidence": round(b.get("avg_confidence", 0.0), 4),
            "after_avg_confidence":  round(a.get("avg_confidence", 0.0), 4),
            "delta_confidence":      round(
                a.get("avg_confidence", 0.0) - b.get("avg_confidence", 0.0), 4),
            "before_detection_rate": round(b.get("detection_rate", 0.0), 4),
            "after_detection_rate":  round(a.get("detection_rate", 0.0), 4),
            "delta_detection_rate":  round(
                a.get("detection_rate", 0.0) - b.get("detection_rate", 0.0), 4),
            "before_top_labels": b.get("predicted_labels", {}),
            "after_top_labels":  a.get("predicted_labels", {}),
        })

    overall = {
        "before_mean_confidence": round(float(before_df["pred_confidence"].mean()), 4),
        "after_mean_confidence":  round(float(after_df["pred_confidence"].mean()), 4) if retrained else None,
        "before_attack_detection_rate": round(float(
            (before_df.loc[before_df["true_label"] == "ATTACK", "is_attack"] == True).mean()), 4),
        "after_attack_detection_rate":  round(float(
            (after_df.loc[after_df["true_label"] == "ATTACK", "is_attack"] == True).mean()), 4) if retrained else None,
        "samples": int(len(before_df)),
        "retrained": retrained,
    }

    return {
        "overall": overall,
        "scenarios": rows,
    }


def write_markdown(report: Dict) -> Path:
    md = OUT_DIR / "confidence_report.md"
    with md.open("w", encoding="utf-8") as fh:
        fh.write("# IDS/IPS — Scenario Test Report\n\n")
        ov = report["overall"]
        fh.write("## Overall\n\n")
        fh.write(f"- Samples: **{ov['samples']:,}**\n")
        fh.write(f"- Retraining performed: **{ov['retrained']}**\n")
        fh.write(f"- Mean confidence (BEFORE): **{ov['before_mean_confidence']:.2%}**\n")
        if ov["after_mean_confidence"] is not None:
            fh.write(f"- Mean confidence (AFTER) : **{ov['after_mean_confidence']:.2%}**\n")
        fh.write(f"- Attack detection rate (BEFORE): **{ov['before_attack_detection_rate']:.2%}**\n")
        if ov["after_attack_detection_rate"] is not None:
            fh.write(f"- Attack detection rate (AFTER) : **{ov['after_attack_detection_rate']:.2%}**\n")
        fh.write("\n## Per scenario\n\n")
        fh.write("| Scenario | Samples | Expected | Before Conf | After Conf | Δ Conf "
                "| Before Det. | After Det. | Δ Det. |\n")
        fh.write("|---|---:|---|---:|---:|---:|---:|---:|---:|\n")
        for r in report["scenarios"]:
            fh.write(
                f"| `{r['scenario']}` | {r['samples']} | {r['expected_category']} "
                f"| {r['before_avg_confidence']:.2%} | {r['after_avg_confidence']:.2%} "
                f"| {r['delta_confidence']:+.2%} | {r['before_detection_rate']:.2%} "
                f"| {r['after_detection_rate']:.2%} | {r['delta_detection_rate']:+.2%} |\n"
            )
        fh.write("\n*Generated by `test_scenarios.py`*\n")
    return md


# ══════════════════════════════════════════════════════════════════════════
#  5.  MAIN
# ══════════════════════════════════════════════════════════════════════════

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true",
                    help="Use a smaller scenario set for fast smoke runs")
    ap.add_argument("--no-retrain", action="store_true",
                    help="Only run BEFORE predictions and skip retraining")
    args = ap.parse_args()

    print("=" * 64)
    print("  IDS/IPS Scenario Test Harness")
    print("=" * 64)

    # 1) Generate scenarios
    df_flows = build_scenarios(quick=args.quick)

    # 2) Load current model + run BEFORE predictions
    IDSPredictor = _import_predictor()
    if not (MODEL_DIR / "ids_model.pkl").exists():
        print("[!] No trained model found at ids_output/. Run ids_ips_trainer.py first.")
        return 1
    predictor = IDSPredictor(str(MODEL_DIR))

    print("\n[+] Running BEFORE predictions ...")
    t0 = time.time()
    before_df = run_predictions(df_flows, predictor)
    print(f"    {len(before_df):,} predictions in {time.time() - t0:.2f}s")
    before_df.to_csv(OUT_DIR / "before_predictions.csv", index=False)
    before_summary = summarize(before_df)

    # Snapshot the current model BEFORE retraining (for rollback / forensics)
    snap_before = snapshot_model("before")
    print(f"[+] Saved snapshot -> {snap_before.name}")

    retrained = False
    after_df = before_df.copy()  # default if not retraining
    after_summary = before_summary

    if not args.no_retrain:
        # 3) Inject labeled scenarios into the online-learning feedback CSV
        n_added = append_online_learning(df_flows)
        print(f"[+] Appended {n_added:,} labeled rows to {ONLINE_CSV.relative_to(ROOT)}")

        # 4) Re-run the trainer (core function untouched)
        rc = run_trainer()
        if rc != 0:
            print(f"[!] Trainer returned code {rc}; AFTER results will reflect the unchanged model.")
        else:
            retrained = True

        # Snapshot the new model
        snap_after = snapshot_model("after")
        print(f"[+] Saved snapshot -> {snap_after.name}")

        # 5) Reload predictor and re-run AFTER predictions
        # Some sklearn/xgboost releases pickle a global cache; safest is a fresh import.
        try:
            import importlib
            import ids_ips_trainer as _t  # noqa: WPS433
            importlib.reload(_t)
            IDSPredictor = _t.IDSPredictor
        except Exception:
            pass

        predictor = IDSPredictor(str(MODEL_DIR))
        print("\n[+] Running AFTER predictions ...")
        t0 = time.time()
        after_df = run_predictions(df_flows, predictor)
        print(f"    {len(after_df):,} predictions in {time.time() - t0:.2f}s")
        after_df.to_csv(OUT_DIR / "after_predictions.csv", index=False)
        after_summary = summarize(after_df)

    # 6) Report
    report = build_report(before_summary, after_summary, before_df, after_df, retrained)
    (OUT_DIR / "confidence_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True))
    md_path = write_markdown(report)

    # Console summary
    print("\n" + "=" * 64)
    print("  RESULTS  (mean confidence per scenario)")
    print("=" * 64)
    print(f"{'Scenario':<18} {'Before':>10} {'After':>10} {'Delta':>10} {'Det Delta':>10}")
    for r in report["scenarios"]:
        print(f"{r['scenario']:<18} "
              f"{r['before_avg_confidence']:>9.2%}  "
              f"{r['after_avg_confidence']:>9.2%}  "
              f"{r['delta_confidence']:>+9.2%}  "
              f"{r['delta_detection_rate']:>+9.2%}")
    print("-" * 64)
    print(f"Wrote: {md_path.relative_to(ROOT)}")
    print(f"Wrote: {(OUT_DIR / 'confidence_report.json').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
