import os
import pandas as pd
from dataset_manager import DatasetFormatter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LargeDataImporter")

def main():
    # Source path in Kaggle cache
    source_dir = r"C:\Users\hp\.cache\kagglehub\datasets\mrwellsdavid\unsw-nb15\versions\1"
    target_file = os.path.join(source_dir, "UNSW-NB15_4.csv")
    output_dir = "data"
    output_file = os.path.join(output_dir, "processed_unsw_large.csv")
    
    if not os.path.exists(target_file):
        logger.error(f"Source file {target_file} not found!")
        return

    formatter = DatasetFormatter()
    
    # We want to add about 150,000 rows to reach 500k+ total
    # UNSW-NB15_4.csv has hundreds of thousands of rows
    logger.info("Reading and formatting 150,000 rows from UNSW-NB15_4.csv...")
    
    try:
        # Load only 150k rows for efficiency
        df = pd.read_csv(target_file, header=None, nrows=150000, encoding='latin-1')
        # We need to pass has_header=False to auto_format
        # Since auto_format expects a path, we'll modify it slightly or use a temp file
        # Actually, let's just use the df we loaded
        
        # Manually trigger the formatting logic for the DF
        cols_49 = [
            'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl',
            'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
            'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt',
            'Dintpkt', 'Tcprtt', 'Synack', 'Ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd',
            'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm',
            'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'Label'
        ]
        df.columns = cols_49
        
        # Apply standard transformations
        df = df.rename(columns={
            'srcip': 'src_ip', 'sport': 'src_port', 'dstip': 'dst_ip', 'dsport': 'dst_port',
            'proto': 'protocol', 'Spkts': 'src_packets', 'Dpkts': 'dst_packets',
            'sbytes': 'src_bytes', 'dbytes': 'dst_bytes'
        })
        
        # Standardize protocol
        proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
        df['protocol'] = df['protocol'].str.lower().map(proto_map).fillna(0).astype(int)
        
        # Unified columns
        df['bidirectional_packets'] = df['src_packets'] + df['dst_packets']
        df['bidirectional_bytes'] = df['src_bytes'] + df['dst_bytes']
        df['bidirectional_duration_ms'] = df['dur'] * 1000
        
        # Label standardization
        df['label'] = df.apply(
            lambda x: 'NORMAL' if x['Label'] == 0 else (x['attack_cat'].upper().strip() if pd.notnull(x['attack_cat']) and str(x['attack_cat']).strip() != '' else 'ATTACK'),
            axis=1
        )
        
        # Clean
        df = formatter.clean(df)
        
        # Save
        os.makedirs(output_dir, exist_ok=True)
        df.to_csv(output_file, index=False)
        logger.info(f"Successfully processed and saved {len(df):,} rows to {output_file}")
        
    except Exception as e:
        logger.error(f"Failed to import large data: {e}")

if __name__ == "__main__":
    main()
