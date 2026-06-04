#!/usr/bin/env python3
"""
Generate a small synthetic training dataset for "wired/weird" attack payload scenarios.

Why:
  The wired_attack_sim sends obfuscated payloads that can evade literal signatures.
  This script creates labeled flow rows with the SAME schema used by ids_ips_trainer.py,
  so the supervised model learns these patterns and produces higher confidence.

Output:
  data/processed_wired_synth.csv
"""

import os
import math
import random
from collections import Counter
from datetime import datetime

import numpy as np
import pandas as pd


def shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    probs = [c / n for c in counts.values()]
    return float(-sum(p * math.log2(p) for p in probs))


def make_flow(payload: bytes, proto: int, dst_port: int, label: str, packets: int, duration_ms: float) -> dict:
    # Approximate "flow" stats to match real-time features used by the model.
    payload_entropy = shannon_entropy_bytes(payload[:2048])
    payload_len_var = float(np.var([len(payload)] * max(2, min(6, packets))))  # small stable var proxy
    bidir_bytes = int(len(payload) + random.randint(60, 200) * max(1, packets))
    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "src_ip": "10.0.0.9",
        "dst_ip": "192.168.100.5",
        "src_port": random.randint(20000, 65000),
        "dst_port": int(dst_port),
        "protocol": int(proto),
        "bidirectional_packets": int(packets),
        "bidirectional_bytes": int(bidir_bytes),
        "bidirectional_duration_ms": float(duration_ms),
        "payload_entropy": float(payload_entropy),
        "payload_len_var": float(payload_len_var),
        "attack_category": str(label),
        "label": str(label),
    }


def main():
    out_dir = "data"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "processed_wired_synth.csv")

    rows = []

    # "Weird/wired" web attacks (TCP/80) - obfuscation patterns
    sqli_variants = [
        b"UNI/**/ON SEL/**/ECT 1,2,3--",
        b"' OR '1'='1' /*",
        b"1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
        b"%55%4e%49%4f%4e %53%45%4c%45%43%54",
    ]
    xss_variants = [
        b"<svg/onload=alert(1)>",
        b"<details open ontoggle=alert(1)>",
        b"<img src=x onmouseover=alert(1)>",
        b"<iframe src=\"javascript:alert(1)\">",
    ]
    traversal_variants = [
        b"..%2f..%2f..%2fetc%2fpasswd",
        b"....//....//....//etc/passwd",
        b"/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ]
    cmd_variants = [
        b"c^m^d.e^x^e /c whoami",
        b"pow\"\"ershell -ExecutionPolicy Bypass",
        b"echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash",
    ]

    for _ in range(250):
        p = random.choice(sqli_variants)
        rows.append(make_flow(p, proto=6, dst_port=80, label="EXPLOIT", packets=6, duration_ms=120))
    for _ in range(250):
        p = random.choice(xss_variants)
        rows.append(make_flow(p, proto=6, dst_port=80, label="EXPLOIT", packets=5, duration_ms=90))
    for _ in range(200):
        p = random.choice(traversal_variants)
        rows.append(make_flow(p, proto=6, dst_port=80, label="EXPLOIT", packets=4, duration_ms=80))
    for _ in range(200):
        p = random.choice(cmd_variants)
        rows.append(make_flow(p, proto=6, dst_port=80, label="EXPLOIT", packets=6, duration_ms=140))

    # "High entropy UDP anomaly" (proto=17, high port)
    for _ in range(400):
        payload = os.urandom(2048)
        rows.append(make_flow(payload, proto=17, dst_port=random.randint(20000, 60000), label="PROBE", packets=2, duration_ms=30))

    # Benign baseline (HTTP-ish + DNS-ish)
    benign_payloads = [
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>ok</html>",
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"example\x03com\x00\x00\x01\x00\x01",
        b"ping",
    ]
    for _ in range(700):
        p = random.choice(benign_payloads)
        proto = 6 if p.startswith((b"GET", b"HTTP")) else 17
        dst_port = 80 if proto == 6 else 53
        rows.append(make_flow(p, proto=proto, dst_port=dst_port, label="NORMAL", packets=random.randint(3, 25), duration_ms=random.randint(50, 600)))

    df = pd.DataFrame(rows)
    df.to_csv(out_path, index=False)
    print(f"[+] Wrote synthetic wired training data: {out_path} ({len(df):,} rows)")


if __name__ == "__main__":
    main()

