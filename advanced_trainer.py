#!/usr/bin/env python3
"""
Incremental / Online XGBoost Trainer for SudoSOC IDS/IPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Supports:
  1. Incremental XGBoost training (continue from existing booster)
  2. Mini-batch updates with replay to prevent catastrophic forgetting
  3. Concept drift detection integration (triggers full retrain)
  4. Model versioning with timestamped snapshots

Usage:
  python advanced_trainer.py                # Run incremental update
  python advanced_trainer.py --full         # Force full retrain
  python advanced_trainer.py --status       # Show training status
"""

import os
import sys
import shutil
import pandas as pd
import numpy as np
import joblib
import logging
import glob
from datetime import datetime
import xgboost as xgb
from ids_ips_trainer import engineer_features, BASE_FEATURES, IP_FEATURES, normalize_label
from sklearn.preprocessing import RobustScaler, LabelEncoder
from drift_monitor import DriftMonitor

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [ONLINE_LEARNING] %(message)s")
log = logging.getLogger("Retrainer")

CFG = {
    "feedback_file": "data/online_learning.csv",
    "base_data_dir": "data",
    "output_dir": "ids_output",
    "archive_dir": "data/archive",
    "snapshot_dir": "ids_output/snapshots",
    "min_samples_to_retrain": 5,
    "replay_fraction": 0.1,           # Fraction of base data to replay
    "incremental_rounds": 50,         # Additional boosting rounds per update
    "max_replay_rows": 10_000,        # Cap replay data for speed
}


class IncrementalTrainer:
    """
    Continues XGBoost training from existing booster weights using
    xgb_model parameter (warm start). Mixes in a replay buffer
    of base training data to prevent catastrophic forgetting.
    """

    def __init__(self):
        self.model_path = os.path.join(CFG["output_dir"], "ids_model.pkl")
        self.scaler_path = os.path.join(CFG["output_dir"], "ids_scaler.pkl")
        self.meta_path = os.path.join(CFG["output_dir"], "ids_metadata.pkl")
        self.ref_path = os.path.join(CFG["output_dir"], "reference_dist.pkl")

        os.makedirs(CFG["archive_dir"], exist_ok=True)
        os.makedirs(CFG["snapshot_dir"], exist_ok=True)

    def _load_existing_model(self):
        """Load existing model, scaler, and metadata."""
        if not os.path.exists(self.model_path):
            return None, None, None
        try:
            model = joblib.load(self.model_path)
            scaler = joblib.load(self.scaler_path)
            meta = joblib.load(self.meta_path)
            return model, scaler, meta
        except Exception as e:
            log.error(f"Could not load existing model: {e}")
            return None, None, None

    def _snapshot_model(self):
        """Save a timestamped copy of the current model before updating."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        for fname in ["ids_model.pkl", "ids_scaler.pkl", "ids_metadata.pkl"]:
            src = os.path.join(CFG["output_dir"], fname)
            if os.path.exists(src):
                dst = os.path.join(CFG["snapshot_dir"], f"{ts}_{fname}")
                shutil.copy2(src, dst)
        log.info(f"Model snapshot saved: {ts}")

    def _load_feedback(self) -> pd.DataFrame:
        """Load new feedback samples."""
        if not os.path.exists(CFG["feedback_file"]):
            return pd.DataFrame()
        try:
            df = pd.read_csv(CFG["feedback_file"])
            if len(df) == 0:
                return pd.DataFrame()
            log.info(f"Loaded {len(df)} feedback samples")
            return df
        except Exception as e:
            log.error(f"Could not load feedback: {e}")
            return pd.DataFrame()

    def _load_replay_buffer(self, feature_cols) -> pd.DataFrame:
        """Load a subset of base training data to prevent forgetting."""
        base_files = glob.glob(os.path.join(CFG["base_data_dir"], "processed_*.csv"))
        if not base_files:
            return pd.DataFrame()

        # Take a random sample from the first 2 files
        dfs = []
        for f in base_files[:2]:
            try:
                df = pd.read_csv(f)
                n_sample = min(
                    int(len(df) * CFG["replay_fraction"]),
                    CFG["max_replay_rows"] // len(base_files[:2])
                )
                if n_sample > 0:
                    dfs.append(df.sample(n=n_sample, random_state=42))
            except Exception as e:
                log.warning(f"Could not load replay file {f}: {e}")

        if dfs:
            replay = pd.concat(dfs, ignore_index=True)
            log.info(f"Replay buffer: {len(replay)} samples from {len(dfs)} files")
            return replay
        return pd.DataFrame()

    def _archive_feedback(self):
        """Move processed feedback to archive."""
        if not os.path.exists(CFG["feedback_file"]):
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = os.path.join(CFG["archive_dir"], f"feedback_{ts}.csv")
        shutil.copy2(CFG["feedback_file"], dst)

        # Reset feedback file with just the header
        with open(CFG["feedback_file"], "r", encoding="utf-8") as f:
            header = f.readline()
        with open(CFG["feedback_file"], "w", encoding="utf-8") as f:
            f.write(header)
        log.info(f"Feedback archived to {dst}")

    def incremental_update(self):
        """
        Run an incremental XGBoost update:
        1. Load feedback data
        2. Load replay buffer from base data
        3. Continue training from existing booster
        4. Save updated model
        """
        new_data = self._load_feedback()
        if len(new_data) < CFG["min_samples_to_retrain"]:
            log.info(f"Only {len(new_data)} feedback samples — "
                     f"need {CFG['min_samples_to_retrain']}. Skipping.")
            return False

        model, scaler, meta = self._load_existing_model()
        if model is None:
            log.warning("No existing model — running full retrain instead")
            return self.full_retrain()

        # Snapshot before modifying
        self._snapshot_model()

        feature_cols = meta.get("feature_cols", [f for f in (BASE_FEATURES + IP_FEATURES)])
        le = meta.get("label_encoder", LabelEncoder())

        # Load replay buffer
        replay = self._load_replay_buffer(feature_cols)

        # Combine feedback + replay
        if len(replay) > 0:
            combined = pd.concat([replay, new_data], ignore_index=True)
        else:
            combined = new_data

        log.info(f"Training on {len(combined)} samples "
                 f"({len(new_data)} new + {len(replay)} replay)")

        # Feature engineering
        combined = engineer_features(combined, verbose=False)

        # Ensure label column exists
        if "label" not in combined.columns:
            log.error("No 'label' column in combined data")
            return False

        # Prepare features
        available_cols = [c for c in feature_cols if c in combined.columns]
        X = combined[available_cols].fillna(0)

        # Refit scaler on combined distribution
        scaler = RobustScaler()
        scaler.fit(X)
        X_scaled = scaler.transform(X)

        # Encode labels — keep classes consistent with original model for warm-start
        combined["label"] = combined["label"].apply(normalize_label)
        
        # We MUST use the original LabelEncoder to keep indices consistent
        # If there are new labels in feedback, map them to 'ATTACK' or the nearest known class
        known_classes = set(le.classes_)
        combined["label"] = combined["label"].apply(
            lambda x: x if x in known_classes else ("ATTACK" if "ATTACK" in known_classes else le.classes_[0])
        )
        
        y = le.transform(combined["label"])
        le_new = le # Maintain consistency

        # Incremental XGBoost training
        log.info(f"Continuing XGBoost training (+{CFG['incremental_rounds']} rounds)...")

        try:
            # Use xgb_model for warm-start continuation
            new_model = xgb.XGBClassifier(
                n_estimators=CFG["incremental_rounds"],
                learning_rate=0.05,
                max_depth=6,
                tree_method="hist",
                random_state=42,
            )
            new_model.fit(X_scaled, y, xgb_model=model.get_booster())
        except Exception as e:
            log.warning(f"Warm-start failed ({e}), falling back to fresh fit")
            new_model = xgb.XGBClassifier(
                n_estimators=100, learning_rate=0.1, max_depth=6
            )
            new_model.fit(X_scaled, y)

        # Save updated artifacts
        joblib.dump(new_model, self.model_path)
        joblib.dump(scaler, self.scaler_path)

        meta.update({
            "feature_cols": available_cols,
            "label_encoder": le_new,
            "last_retrain": datetime.now().isoformat(),
            "sample_count": len(X_scaled),
            "model_name": "XGBoost (incremental)",
            "mode": "supervised",
            "retrain_type": "incremental",
        })
        joblib.dump(meta, self.meta_path)

        # Update drift reference
        DriftMonitor.save_training_reference(combined, self.ref_path)

        # Archive processed feedback
        self._archive_feedback()

        log.info(f"Incremental update complete! Model saved to {CFG['output_dir']}")
        return True

    def full_retrain(self):
        """
        Full retrain from all base data + feedback.
        Called when drift is too severe for incremental updates.
        """
        log.info("Running FULL RETRAIN...")

        # Snapshot
        if os.path.exists(self.model_path):
            self._snapshot_model()

        # Load all base data
        base_files = glob.glob(os.path.join(CFG["base_data_dir"], "processed_*.csv"))
        if not base_files:
            log.error("No base data files found!")
            return False

        dfs = []
        # Load up to 5 base files, prioritizing the wired synth data if it exists
        wired_file = os.path.join(CFG["base_data_dir"], "processed_wired_synth.csv")
        if wired_file in base_files:
            base_files.remove(wired_file)
            base_files.insert(0, wired_file)
            
        for f in base_files[:5]:
            try:
                dfs.append(pd.read_csv(f))
            except Exception:
                pass

        # Add feedback
        feedback = self._load_feedback()
        if len(feedback) > 0:
            dfs.append(feedback)

        combined = pd.concat(dfs, ignore_index=True)
        log.info(f"Full retrain on {len(combined)} total samples")

        # Feature engineering
        combined = engineer_features(combined, verbose=False)

        if "label" not in combined.columns:
            log.error("No 'label' column!")
            return False

        feature_cols = [f for f in (BASE_FEATURES + IP_FEATURES)
                        if f in combined.columns]
        X = combined[feature_cols].fillna(0)

        scaler = RobustScaler()
        X_scaled = scaler.fit_transform(X)

        combined["label"] = combined["label"].apply(normalize_label)
        le = LabelEncoder()
        y = le.fit_transform(combined["label"])

        log.info("Training full XGBoost model...")
        model = xgb.XGBClassifier(
            n_estimators=100, learning_rate=0.06, max_depth=8,
            subsample=0.85, colsample_bytree=0.85,
            tree_method="hist", random_state=42, n_jobs=-1,
        )
        model.fit(X_scaled, y)

        # Save
        joblib.dump(model, self.model_path)
        joblib.dump(scaler, self.scaler_path)

        meta = {
            "feature_cols": feature_cols,
            "label_encoder": le,
            "last_retrain": datetime.now().isoformat(),
            "sample_count": len(X_scaled),
            "model_name": "XGBoost (full retrain)",
            "mode": "supervised",
            "retrain_type": "full",
        }
        joblib.dump(meta, self.meta_path)

        DriftMonitor.save_training_reference(combined, self.ref_path)
        self._archive_feedback()

        log.info(f"Full retrain complete! {len(X_scaled)} samples, "
                 f"{len(feature_cols)} features")
        return True

    def get_status(self) -> dict:
        """Return current training status."""
        model, scaler, meta = self._load_existing_model()
        feedback_count = 0
        if os.path.exists(CFG["feedback_file"]):
            try:
                with open(CFG["feedback_file"], "r") as f:
                    feedback_count = max(0, sum(1 for _ in f) - 1)
            except Exception:
                pass

        snapshots = sorted(glob.glob(
            os.path.join(CFG["snapshot_dir"], "*_ids_model.pkl")
        ))

        return {
            "model_loaded": model is not None,
            "last_retrain": meta.get("last_retrain", "never") if meta else "never",
            "retrain_type": meta.get("retrain_type", "unknown") if meta else "unknown",
            "sample_count": meta.get("sample_count", 0) if meta else 0,
            "model_name": meta.get("model_name", "unknown") if meta else "unknown",
            "pending_feedback": feedback_count,
            "snapshot_count": len(snapshots),
        }


# ── CLI Entry Point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    trainer = IncrementalTrainer()

    if "--full" in sys.argv:
        trainer.full_retrain()
    elif "--status" in sys.argv:
        import json
        print(json.dumps(trainer.get_status(), indent=2))
    else:
        trainer.incremental_update()
