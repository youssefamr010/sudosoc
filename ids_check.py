#!/usr/bin/env python3
"""
IDS Environment Diagnostic  –  run this FIRST to find problems
  python ids_check.py
"""
import sys, os, platform, socket, subprocess, ctypes

SEP = "-" * 58
ok  = lambda m: print(f"  [OK]  {m}")
warn= lambda m: print(f"  [!]   {m}")
err = lambda m: print(f"  [ERR] {m}")

print(f"\n{'='*58}")
print("  IDS Environment Diagnostic")
print(f"{'='*58}\n")

# ── 1. Admin check ────────────────────────────────────────────────────────────
print("[1] Administrator / root privileges")
is_windows = platform.system() == "Windows"
if is_windows:
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
else:
    is_admin = os.geteuid() == 0

if is_admin:
    ok("Running as Administrator")
else:
    err("NOT running as Administrator  <- BLOCKING WILL NOT WORK")
    print("     -> Right-click PowerShell -> 'Run as administrator'")
print()

# -- 2. Python version ---------------------------------------------------------
print("[2] Python version")
v = sys.version_info
if v.major == 3 and v.minor >= 9:
    ok(f"Python {v.major}.{v.minor}.{v.micro}")
else:
    warn(f"Python {v.major}.{v.minor} - recommend 3.9+")
print()

# -- 3. Npcap / WinPcap (Windows only) ----------------------------------------
if is_windows:
    print("[3] Npcap installation (required for Scapy on Windows)")
    npcap_path = r"C:\Windows\System32\Npcap"
    npcap_dll  = r"C:\Windows\System32\wpcap.dll"
    if os.path.isdir(npcap_path) or os.path.isfile(npcap_dll):
        ok("Npcap detected")
    else:
        err("Npcap NOT found  <- Scapy cannot capture packets without it")
        print("     -> Download from https://npcap.com/#download")
        print("       Install with 'WinPcap API compatibility' checked!")
    print()

# -- 4. Package availability ---------------------------------------------------
print("[4] Python packages")
packages = {
    "scapy"   : "packet capture",
    "requests": "HF API calls",
    "numpy"   : "ML feature extraction",
    "joblib"  : "ML model loading",
    "xgboost" : "Advanced ML classification",
    "pandas"  : "Data processing",
}
missing = []
for pkg, purpose in packages.items():
    try:
        __import__(pkg)
        ok(f"{pkg:<12} ({purpose})")
    except ImportError:
        err(f"{pkg:<12} MISSING  ->  pip install {pkg}")
        missing.append(pkg)
if missing:
    print(f"\n  -> Fix: pip install {' '.join(missing)}")
print()

# -- 5. Scapy interface list ---------------------------------------------------
print("[5] Network interfaces visible to Scapy")
try:
    from scapy.all import get_if_list, conf
    if is_windows:
        conf.use_pcap = True
    ifaces = get_if_list()
    if ifaces:
        for i in ifaces:
            ok(i)
    else:
        err("No interfaces found  <- Npcap likely not installed or not in WinPcap compat mode")
except Exception as e:
    err(f"Scapy interface listing failed: {e}")
print()

# -- 6. HF API key -------------------------------------------------------------
print("[6] HuggingFace API key")
hf_key = os.environ.get("HF_API_KEY", "")

# Also check for hf_token.txt
if not hf_key and os.path.exists("hf_token.txt"):
    try:
        with open("hf_token.txt", "r") as f:
            hf_key = f.read().strip()
            if hf_key:
                ok("Found API key in 'hf_token.txt'")
    except: pass

if not hf_key:
    warn("HF_API_KEY not set  <- LLM analysis disabled (IDS still works!)")
    print("     -> Option A: $env:HF_API_KEY='hf_xxxx'")
    print("     -> Option B: Create 'hf_token.txt' file with the key inside")
elif not hf_key.startswith("hf_"):
    warn("HF_API_KEY doesn't look like a valid token (should start with hf_)")
else:
    if not os.environ.get("HF_API_KEY"):
         # Already printed the "Found in file" message if it came from file
         pass
    else:
         ok(f"HF_API_KEY set in environment ({hf_key[:8]}...)")

    # Test API
    print("   Testing LLM API call (Direct)...")
    try:
        import requests
        model_id = "mistralai/Mixtral-8x7B-Instruct-v0.1"
        url = f"https://api-inference.huggingface.co/models/{model_id}"
        r   = requests.post(
            url,
            headers={"Authorization": f"Bearer {hf_key}", "Content-Type": "application/json"},
            json={"inputs": "Reply with OK"},
            timeout=20
        )
        if r.status_code == 200:
            ok(f"API responded: {r.text[:50]}...")
        else:
            warn(f"API returned HTTP {r.status_code}: {r.text[:100]}")
    except Exception as e:
        warn(f"LLM API test failed: {e}")
print()

# -- 7. ML model files ---------------------------------------------------------
print("[7] ML model files (ids_output/)")
required = ["ids_model.pkl", "ids_scaler.pkl", "ids_metadata.pkl"]
model_dir = "ids_output"
found_all = True
for f in required:
    path = os.path.join(model_dir, f)
    if os.path.isfile(path):
        ok(f"{path}")
    else:
        warn(f"{path}  NOT FOUND  (IDS will run in heuristic-only mode)")
        found_all = False
if not found_all:
    print("   -> IDS still works! Heuristics catch attacks independently.")
print()

# -- 8. Firewall test ----------------------------------------------------------
if is_windows and is_admin:
    print("[8] Windows Firewall (netsh) test")
    try:
        r = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, timeout=5
        )
        if "ON" in r.stdout.upper() or "State" in r.stdout:
            ok("Windows Firewall accessible via netsh")
        else:
            warn(f"Unexpected response: {r.stdout[:80]}")
    except Exception as e:
        err(f"netsh test failed: {e}")
    print()

# -- Summary -------------------------------------------------------------------
print("="*58)
print("  DIAGNOSIS COMPLETE")
print("="*58)
if is_admin and not missing:
    print("\n  [OK]  System looks ready.  Run:")
    print("      python realtime_ids.py")
    print("\n  To test detection (from ANOTHER machine or phone):")
    my_ip = socket.gethostbyname(socket.gethostname())
    print(f"      Test-NetConnection -ComputerName {my_ip} -Port 4444")
    print(f"\n  [!]  Using YOUR OWN IP ({my_ip}) as source won't work on Windows!")
    print("     Windows routes self-traffic internally. Use another device.\n")
else:
    if not is_admin:
        print("\n  [ERR]  Re-run PowerShell as Administrator")
    if missing:
        print(f"\n  [ERR]  Install missing packages:  pip install {' '.join(missing)}")
