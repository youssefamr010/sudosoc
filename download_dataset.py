import os
import requests
import pandas as pd
import logging
import urllib3
import shutil

try:
    import kagglehub
    KAGGEHUB_AVAILABLE = True
except ImportError:
    KAGGEHUB_AVAILABLE = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DatasetDownloader")

def download_file(url, filename):
    if os.path.exists(filename):
        logger.info(f"File {filename} already exists. Skipping download.")
        return True
    
    logger.info(f"Downloading {url}...")
    try:
        # verify=False is used to bypass potential proxy SSL issues during setup
        response = requests.get(url, stream=True, verify=False)
        response.raise_for_status()
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info(f"Successfully downloaded {filename}")
        return True
    except Exception as e:
        logger.error(f"Failed to download {url}: {e}")
        return False

def download_unsw_nb15(data_dir):
    """Downloads UNSW-NB15 from Kaggle using kagglehub."""
    if not KAGGEHUB_AVAILABLE:
        logger.error("kagglehub not installed. Run 'pip install kagglehub' first.")
        return
    
    logger.info("Downloading UNSW-NB15 from Kaggle...")
    try:
        path = kagglehub.dataset_download("mrwellsdavid/unsw-nb15")
        logger.info(f"Kaggle files downloaded to: {path}")
        for item in os.listdir(path):
            if item.endswith(".csv"):
                src = os.path.join(path, item)
                dst = os.path.join(data_dir, f"unsw_{item}")
                shutil.copy(src, dst)
                logger.info(f"Copied {item} to {dst}")
        logger.info("UNSW-NB15 preparation complete.")
    except Exception as e:
        logger.error(f"Failed to download UNSW-NB15: {e}")

def download_cic_ids(data_dir, version="2017"):
    """Downloads CIC-IDS2017 or 2018 from Kaggle."""
    if not KAGGEHUB_AVAILABLE:
        logger.error("kagglehub not installed.")
        return
    
    slug = "cic-ids2017/cicids2017" if version == "2017" else "solarmind/ids-intrusion-csv"
    logger.info(f"Downloading CIC-IDS{version} from Kaggle (Slug: {slug})...")
    
    try:
        path = kagglehub.dataset_download(slug)
        logger.info(f"Files downloaded to: {path}")
        
        # We only want a few representative files to keep it manageable
        target_files = []
        if version == "2017":
            # Monday (Benign) and Wednesday (DoS/DDoS) are usually good
            target_files = ["Monday-WorkingHours.pcap_ISCX.csv", "Wednesday-workingHours.pcap_ISCX.csv"]
        else:
            # 2018 files are often named by date
            target_files = os.listdir(path)[:2] # Just take first two for now
            
        for item in os.listdir(path):
            if item.endswith(".csv") and (not target_files or item in target_files):
                src = os.path.join(path, item)
                dst = os.path.join(data_dir, f"cic{version}_{item}")
                shutil.copy(src, dst)
                logger.info(f"Copied {item} to {dst}")
                
        logger.info(f"CIC-IDS{version} preparation complete.")
    except Exception as e:
        logger.error(f"Failed to download CIC-IDS{version}: {e}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Download IDS datasets")
    parser.add_argument("--cic", action="store_true", help="Download CIC-IDS2017/2018")
    parser.add_argument("--unsw", action="store_true", help="Download UNSW-NB15")
    parser.add_argument("--kdd", action="store_true", help="Download NSL-KDD")
    parser.add_argument("--all", action="store_true", help="Download all datasets")
    args = parser.parse_args()

    data_dir = "data"
    os.makedirs(data_dir, exist_ok=True)
    
    if args.kdd or args.all or (not args.cic and not args.unsw):
        # 1. Download NSL-KDD (Standard)
        logger.info("--- Step 1: NSL-KDD ---")
        datasets = {
            "KDDTrain+.csv": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.csv",
            "KDDTest+.csv": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.csv"
        }
        
        columns = [
            "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", 
            "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", 
            "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", 
            "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", 
            "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", 
            "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", 
            "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
            "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", 
            "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level"
        ]

        for name, url in datasets.items():
            path = os.path.join(data_dir, name)
            if download_file(url, path):
                df = pd.read_csv(path, names=columns)
                proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
                df['protocol'] = df['protocol_type'].map(proto_map).fillna(0).astype(int)
                df['src_port'] = 0
                df['dst_port'] = 0
                df['bidirectional_packets'] = df['count']
                df['bidirectional_bytes'] = df['src_bytes'] + df['dst_bytes']
                df['bidirectional_duration_ms'] = df['duration'] * 1000
                processed_path = os.path.join(data_dir, f"processed_{name}")
                df.to_csv(processed_path, index=False)

    if args.unsw or args.all:
        # 2. Download UNSW-NB15 (Advanced)
        logger.info("\n--- Step 2: UNSW-NB15 ---")
        download_unsw_nb15(data_dir)

    if args.cic or args.all:
        # 3. Download CIC-IDS
        logger.info("\n--- Step 3: CIC-IDS2017 ---")
        download_cic_ids(data_dir, "2017")
        logger.info("\n--- Step 4: CIC-IDS2018 ---")
        download_cic_ids(data_dir, "2018")

    logger.info("\nDataset download and preparation complete!")
    logger.info(f"You can now point your trainer CONFIG['data_dir'] to '{os.path.abspath(data_dir)}'")

if __name__ == "__main__":
    main()
