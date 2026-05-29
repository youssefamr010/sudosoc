import os
import pandas as pd
import numpy as np
import glob
import logging
import argparse

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("DatasetManager")

class DatasetValidator:
    """Checks the health, cleanliness, and consistency of datasets."""
    
    REQUIRED_COLS = [
        'protocol', 'src_port', 'dst_port', 
        'bidirectional_packets', 'bidirectional_bytes', 
        'bidirectional_duration_ms', 'label'
    ]

    def __init__(self, data_dir="data"):
        self.data_dir = data_dir

    def check_health(self):
        files = glob.glob(os.path.join(self.data_dir, "*.csv"))
        results = []
        
        for f in files:
            basename = os.path.basename(f)
            report = {"file": basename, "readable": False, "clean": False, "consistent": False, "rows": 0, "issues": []}
            
            try:
                # Try reading with common encodings
                df = None
                used_enc = None
                for enc in ['utf-8', 'latin-1', 'cp1252']:
                    try:
                        df = pd.read_csv(f, nrows=100, encoding=enc)
                        used_enc = enc
                        break
                    except:
                        continue
                
                if df is None:
                    report["issues"].append("Could not determine encoding")
                    results.append(report)
                    continue
                
                report["readable"] = True
                
                # Check consistency
                missing_cols = [c for c in self.REQUIRED_COLS if c not in df.columns]
                if not missing_cols:
                    report["consistent"] = True
                else:
                    report["issues"].append(f"Missing columns: {', '.join(missing_cols)}")
                
                # Check cleanliness (SAMPLE ONLY).
                # Full-file scans can be extremely slow on large datasets (1M+ rows) and block training.
                # We sample a few thousand rows and report nulls as an indicator rather than a guarantee.
                try:
                    df_samp = pd.read_csv(f, nrows=5000, encoding=used_enc)
                    report["rows"] = int(len(df_samp))
                    null_count = int(df_samp.isnull().sum().sum())
                    if null_count == 0:
                        report["clean"] = True
                    else:
                        report["issues"].append(f"Found {null_count} null values in 5k-row sample")
                except Exception as e:
                    report["issues"].append(f"Could not sample for cleanliness: {e}")
                
                results.append(report)
                
            except Exception as e:
                report["issues"].append(str(e))
                results.append(report)
                
        return results

    def print_report(self, results):
        print("\n" + "="*80)
        print(f"{'FILE':<40} | {'READ':<5} | {'CLEAN':<5} | {'CONSIST':<8} | {'ROWS':>8}")
        print("-" * 80)
        for r in results:
            print(f"{r['file']:<40} | {'Yes' if r['readable'] else 'No':<5} | {'Yes' if r['clean'] else 'No':<5} | {'Yes' if r['consistent'] else 'No':<8} | {r['rows']:>8,}")
            if r["issues"]:
                for issue in r["issues"]:
                    print(f"  [!] {issue}")
        print("="*80 + "\n")

class DatasetFormatter:
    """Formats and standardizes datasets for the IDS trainer."""
    
    COLUMN_MAPS = {
        # UNSW mapping
        'proto': 'protocol',
        'spkts': 'src_packets',
        'dpkts': 'dst_packets',
        'sbytes': 'src_bytes',
        'dbytes': 'dst_bytes',
        'dur': 'duration_sec',
        'attack_cat': 'attack_category',
        
        # KDD mapping
        'protocol_type': 'protocol_str',
        'src_bytes': 'src_bytes',
        'dst_bytes': 'dst_bytes',
        'duration': 'duration_sec',
        
        # Large UNSW mapping (49 columns)
        'srcip': 'src_ip',
        'sport': 'src_port',
        'dstip': 'dst_ip',
        'dsport': 'dst_port',
        'Spkts': 'src_packets',
        'Dpkts': 'dst_packets',
        'smeansz': 'src_mean_size',
        'dmeansz': 'dst_mean_size',
        # CIC-IDS mappings (common variations with spaces)
        ' Destination Port': 'dst_port',
        ' Destination IP': 'dst_ip',
        ' Source Port': 'src_port',
        ' Source IP': 'src_ip',
        ' Protocol': 'protocol',
        ' Flow Duration': 'duration_ms',
        ' Total Fwd Packets': 'src_packets',
        ' Total Backward Packets': 'dst_packets',
        'Total Length of Fwd Packets': 'src_bytes',
        ' Total Length of Bwd Packets': 'dst_bytes',
        ' Label': 'label',
        
        # 2018 variations
        'Dst Port': 'dst_port',
        'Protocol': 'protocol',
        'Flow Duration': 'duration_ms',
        'Tot Fwd Pkts': 'src_packets',
        'Tot Bwd Pkts': 'dst_packets',
        'TotLen Fwd Pkts': 'src_bytes',
        'TotLen Bwd Pkts': 'dst_bytes',
        'Label': 'label'
    }

    PROTOCOL_MAP = {'tcp': 6, 'udp': 17, 'icmp': 1}

    def __init__(self):
        pass

    def clean(self, df):
        """Fills missing values and removes duplicates."""
        initial_rows = len(df)
        df = df.fillna(0) # Default to 0 for numeric
        # For object columns, fill with 'UNKNOWN' or empty
        for col in df.select_dtypes(include=['object']).columns:
            df[col] = df[col].replace(0, 'UNKNOWN')
        
        df = df.drop_duplicates()
        if len(df) < initial_rows:
            logger.info(f"Removed {initial_rows - len(df)} duplicate rows.")
        return df

    def auto_format(self, input_path, has_header=None):
        """Attempts to format a raw CSV into the standard unified schema."""
        logger.info(f"Auto-formatting {input_path}...")
        
        try:
            # Load
            df = None
            # If has_header is not specified, try to detect
            for enc in ['utf-8', 'latin-1']:
                try:
                    if has_header is False:
                        # Raw UNSW 49 columns case
                        cols_49 = [
                            'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl',
                            'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
                            'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt',
                            'Dintpkt', 'Tcprtt', 'Synack', 'Ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd',
                            'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm',
                            'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'Label'
                        ]
                        df = pd.read_csv(input_path, encoding=enc, names=cols_49, header=None)
                    else:
                        df = pd.read_csv(input_path, encoding=enc)
                    break
                except Exception as e: 
                    continue
            
            if df is None: raise ValueError("Could not read file.")

            # 1. Map columns if they exist
            df = df.rename(columns={k: v for k, v in self.COLUMN_MAPS.items() if k in df.columns})

            # 2. Derive Standard Columns
            
            # Protocol
            if 'protocol' not in df.columns:
                if 'protocol_str' in df.columns:
                    df['protocol'] = df['protocol_str'].str.lower().map(self.PROTOCOL_MAP).fillna(0).astype(int)
                else:
                    df['protocol'] = 0 # Fallback
            
            # Packets
            if 'bidirectional_packets' not in df.columns:
                if 'src_packets' in df.columns and 'dst_packets' in df.columns:
                    df['bidirectional_packets'] = df['src_packets'] + df['dst_packets']
                elif 'src_packets' in df.columns:
                    df['bidirectional_packets'] = df['src_packets']
                else:
                    df['bidirectional_packets'] = 1 # Fallback
            
            # Bytes
            if 'bidirectional_bytes' not in df.columns:
                if 'src_bytes' in df.columns and 'dst_bytes' in df.columns:
                    df['bidirectional_bytes'] = df['src_bytes'] + df['dst_bytes']
                elif 'src_bytes' in df.columns:
                    df['bidirectional_bytes'] = df['src_bytes']
                else:
                    df['bidirectional_bytes'] = 0
            
            # Duration (assume ms)
            if 'bidirectional_duration_ms' not in df.columns:
                if 'duration_sec' in df.columns:
                    df['bidirectional_duration_ms'] = df['duration_sec'] * 1000
                else:
                    df['bidirectional_duration_ms'] = 0
            
            # Ports (often missing in simplified datasets)
            if 'src_port' not in df.columns: df['src_port'] = 0
            if 'dst_port' not in df.columns: df['dst_port'] = 0
            
            # Labels
            if 'label' not in df.columns:
                df['label'] = 'NORMAL' # Default
            else:
                # Standardize labels
                df['label'] = df.apply(
                    lambda x: 'NORMAL' if str(x['label']).upper() in ['0', 'NORMAL', 'BENIGN'] 
                    else (str(x['attack_category']).upper() if 'attack_category' in df.columns and pd.notnull(x['attack_category']) else 'ATTACK'),
                    axis=1
                )

            # 3. Clean
            df = self.clean(df)

            # 4. Final selection (keep original columns too, but ensure standard ones exist)
            logger.info(f"Successfully formatted {len(df):,} rows.")
            return df

        except Exception as e:
            logger.error(f"Formatting failed: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(description="IDS/IPS Dataset Manager")
    parser.add_argument("--check", action="store_true", help="Run health check on all CSVs in data/")
    parser.add_argument("--format", type=str, help="Auto-format a specific raw CSV file")
    parser.add_argument("--clean", type=str, help="Clean a specific CSV file (fix nulls/duplicates)")
    parser.add_argument("--output", type=str, default=None, help="Output path for formatted/cleaned file")
    
    args = parser.parse_args()
    
    validator = DatasetValidator()
    formatter = DatasetFormatter()
    
    if args.check:
        results = validator.check_health()
        validator.print_report(results)
        
    elif args.format:
        df = formatter.auto_format(args.format)
        if df is not None:
            out_path = args.output or os.path.join("data", "processed_" + os.path.basename(args.format))
            df.to_csv(out_path, index=False)
            logger.info(f"Saved formatted dataset to: {out_path}")
            
    elif args.clean:
        logger.info(f"Cleaning {args.clean}...")
        try:
            df = pd.read_csv(args.clean)
            df = formatter.clean(df)
            out_path = args.output or args.clean
            df.to_csv(out_path, index=False)
            logger.info(f"Saved cleaned dataset to: {out_path}")
        except Exception as e:
            logger.error(f"Cleaning failed: {e}")

if __name__ == "__main__":
    main()
