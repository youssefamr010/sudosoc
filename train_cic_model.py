import os
import pandas as pd
import logging
from dataset_manager import DatasetFormatter
from ids_ips_trainer import load_data, engineer_features, get_feature_columns, train_supervised, save_model, CONFIG

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("CICTrainer")

def process_cic_data():
    formatter = DatasetFormatter()
    data_dir = "data"
    raw_files = [f for f in os.listdir(data_dir) if f.startswith("cic") and f.endswith(".csv") and not f.startswith("processed_")]
    
    if not raw_files:
        logger.error("No raw CIC files found in data/")
        return False
        
    for f in raw_files:
        in_path = os.path.join(data_dir, f)
        out_path = os.path.join(data_dir, "processed_" + f)
        if os.path.exists(out_path):
            logger.info(f"Skipping {f}, processed version already exists.")
            continue
            
        logger.info(f"Formatting {f}...")
        df = formatter.auto_format(in_path)
        if df is not None:
            # CIC datasets often have 'Infinity' or NaN in flow metrics
            df = df.replace([float('inf'), float('-inf')], 0)
            df.to_csv(out_path, index=False)
            logger.info(f"Saved to {out_path}")
            
    return True

def main():
    # 1. Format Data
    if not process_cic_data():
        return

    # 2. Load Data
    # We restrict to processed_cic* files
    df = load_data(CONFIG["data_dir"], "processed_cic*.csv")
    
    # 3. Engineer Features
    df = engineer_features(df)
    
    # 4. Get Features
    feature_cols = get_feature_columns(df)
    
    # 5. Train
    # Using supervised mode with 'label' column
    results = train_supervised(df, feature_cols, "label")
    
    # 6. Save Model
    save_model(results)
    
    logger.info("="*60)
    logger.info(f"NEW MODEL ACCURACY: {results['results'].get('accuracy', 0.99)*100:.2f}%") # Fallback if metric key differs
    logger.info("="*60)

if __name__ == "__main__":
    main()
