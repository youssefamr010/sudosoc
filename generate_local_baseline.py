import json
import pandas as pd
import os

ALERTS_FILE = "ids_alerts.jsonl"
OUTPUT_CSV = "data/processed_local_baseline.csv"

def generate_local_data():
    if not os.path.exists(ALERTS_FILE):
        print(f"File {ALERTS_FILE} not found.")
        return

    flows = []
    with open(ALERTS_FILE, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                # Treat everything except port 4444 as NORMAL for baseline learning
                # especially if it's port 443, 80, 53, or 5353
                src_port = data.get("src_port")
                dst_port = data.get("dst_port")
                
                label = "NORMAL"
                if dst_port == 4444 or src_port == 4444:
                    label = "ATTACK"
                
                flow = {
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": data.get("protocol"),
                    "bidirectional_packets": data.get("packets"),
                    "bidirectional_bytes": data.get("bytes"),
                    "bidirectional_duration_ms": data.get("duration_ms"),
                    "label": label
                }
                flows.append(flow)
            except:
                continue

    if not flows:
        print("No flows found in alerts log.")
        return

    df = pd.DataFrame(flows)
    
    # Merge with some original training data to ensure variety
    # but we'll prioritize these local labels
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved {len(df)} local baseline flows to {OUTPUT_CSV}")

if __name__ == "__main__":
    generate_local_data()
