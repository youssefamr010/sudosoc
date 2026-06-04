import os
import subprocess
import time
import sys

def main():
    print("==================================================")
    print(" SudoSOC - TLS Session Key Extractor (SSLKEYLOGFILE)")
    print("==================================================")
    print("[*] This script will launch Google Chrome with the SSLKEYLOGFILE environment variable set.")
    print("[*] This allows SudoSOC to decrypt TLS traffic out-of-band.")
    
    # Define the path where the keys will be saved
    key_log_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "sudosoc_tls_keys.log")
    
    # Set the environment variable for the current process and its children
    os.environ["SSLKEYLOGFILE"] = key_log_path
    
    # Common paths for Chrome on Windows
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    ]
    
    chrome_exe = None
    for path in chrome_paths:
        if os.path.exists(path):
            chrome_exe = path
            break
            
    if not chrome_exe:
        print("[!] Could not find Google Chrome installation. Please ensure it is installed.")
        print("[*] You can manually run your browser with: set SSLKEYLOGFILE=sudosoc_tls_keys.log && start chrome")
        sys.exit(1)

    print(f"[*] Found Chrome at: {chrome_exe}")
    print(f"[*] Keys will be logged to: {key_log_path}")
    print("[*] Launching browser in 3 seconds...")
    time.sleep(3)
    
    try:
        # Launch Chrome. We use --ignore-certificate-errors to allow the SudoSOC mitmproxy to intercept seamlessly
        subprocess.Popen([
            chrome_exe,
            "--ignore-certificate-errors",
            "--incognito", # Launch in incognito to avoid messing with user's main session
            "http://example.com" # Open a test page
        ])
        print("[+] Chrome launched successfully.")
        print("[*] Browse any HTTPS website. The symmetric keys will be appended to the log file.")
        print("[*] You can configure Wireshark or the SudoSOC sniffer to use this file for decryption.")
        print("[*] Press Ctrl+C to exit this script (Chrome will stay open).")
        
        # Keep script running to monitor file size
        while True:
            if os.path.exists(key_log_path):
                size = os.path.getsize(key_log_path)
                print(f"\r[*] Current key log file size: {size} bytes", end="")
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[*] Exiting.")
    except Exception as e:
        print(f"\n[!] Error launching Chrome: {e}")

if __name__ == "__main__":
    main()
