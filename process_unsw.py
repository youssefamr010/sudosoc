import os
import pandas as pd
import shutil
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("UNSWProcessor")

SOURCE_DIR = r"C:\Users\hp\.cache\kagglehub\datasets\mrwellsdavid\unsw-nb15\versions\1"
DATA_DIR = "data"

def process():
    files = ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"]
    
    for f in files:
        src = os.path.join(SOURCE_DIR, f)
        if not os.path.exists(src):
            logger.error(f"Source file {src} not found!")
            continue
            
        logger.info(f"Processing {f}...")
        try:
            # Try latin-1 if utf-8 fails
            df = pd.read_csv(src, encoding='latin-1')
            
            # Map columns to match our IDS trainer expectation
            # UNSW columns: dur, proto, sbytes, dbytes, sttl, dttl, state, etc.
            # Our trainer expects: protocol, src_port, dst_port, bidirectional_packets, bidirectional_bytes, bidirectional_duration_ms, label
            
            # protocol is already a string in UNSW, map to int
            # Note: UNSW has 'proto' column
            proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
            df['protocol'] = df['proto'].str.lower().map(proto_map).fillna(0).astype(int)
            
            # Ports are not in the 'training/testing' sets of this Kaggle version
            # Use 0 as fallback to keep feature alignment
            df['src_port'] = 0
            df['dst_port'] = 0
            
            # bidirectional packets/bytes
            # UNSW has 'spkts' (src to dst) and 'dpkts' (dst to src)
            # UNSW has 'sbytes' and 'dbytes'
            df['bidirectional_packets'] = df['spkts'] + df['dpkts']
            df['bidirectional_bytes'] = df['sbytes'] + df['dbytes']
            df['bidirectional_duration_ms'] = df['dur'] * 1000
            
            # Labels
            # UNSW 'label' 0 is normal, 1 is attack.
            # We want 'NORMAL' and 'ATTACK' (or specific cat)
            # Let's use 'NORMAL' and the 'attack_cat' if it's an attack
            df['label'] = df.apply(lambda x: 'NORMAL' if x['label'] == 0 else (x['attack_cat'].upper().strip() if pd.notnull(x['attack_cat']) else 'ATTACK'), axis=1)
            
            # Save processed file
            dst = os.path.join(DATA_DIR, f"processed_unsw_{f}")
            df.to_csv(dst, index=False)
            logger.info(f"Saved {len(df):,} rows to {dst}")
            
        except Exception as e:
            logger.error(f"Error processing {f}: {e}")

if __name__ == "__main__":
    process()
