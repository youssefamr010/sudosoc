#!/usr/bin/env python3
"""
Generate many synthetic "realistic" attack scenarios NOT tied to any single public dataset.

Purpose
-------
You asked for many different patterns (weird payloads, beacons, bursts, floods, tunneling-like)
so the supervised model becomes more confident on these behaviors.

This writes a `processed_*.csv` file with the same core schema used by `ids_ips_trainer.py`.

Output
------
  data/processed_attack_scenarios.csv
"""

from __future__ import annotations

import os
import math
import random
from collections import Counter
from datetime import datetime

import numpy as np
import pandas as pd


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    ps = [v / n for v in c.values()]
    return float(-sum(p * math.log2(p) for p in ps))


def b64ish_bytes(n: int) -> bytes:
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    return bytes(random.choice(alphabet) for _ in range(n))


def dnsish_bytes(n_labels: int = 3) -> bytes:
    # Not a real DNS packet, but creates low-entropy, structured payload
    labels = []
    for _ in range(n_labels):
        ln = random.randint(3, 8)
        labels.append(bytes(random.choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(ln)))
    name = b".".join(labels)
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x00\x01\x00\x01"


def make_row(
    *,
    proto: int,
    dst_port: int,
    label: str,
    payload: bytes,
    packets: int,
    duration_ms: float,
    src_ip: str = "10.0.0.9",
    dst_ip: str = "192.168.100.5",
) -> dict:
    payload_entropy = entropy(payload[:2048])
    # payload_len_var proxy: simulate multi-packet variability
    lens = []
    for _ in range(max(2, min(8, int(packets)))):
        jitter = random.randint(-50, 120)
        lens.append(max(1, len(payload) + jitter))
    payload_len_var = float(np.var(lens))

    # bytes: include headers + payloads
    pkts = int(max(1, packets))
    bpp = max(60, int(len(payload) / max(1, pkts))) + random.randint(40, 220)
    bidir_bytes = int(pkts * bpp + random.randint(0, 400))

    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(20000, 65000),
        "dst_port": int(dst_port),
        "protocol": int(proto),
        "bidirectional_packets": int(pkts),
        "bidirectional_bytes": int(bidir_bytes),
        "bidirectional_duration_ms": float(duration_ms),
        "payload_entropy": float(payload_entropy),
        "payload_len_var": float(payload_len_var),
        "attack_category": str(label),
        "label": str(label),
    }


def main():
    random.seed(42)
    out_path = os.path.join("data", "processed_attack_scenarios.csv")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    rows: list[dict] = []

    # ── NORMAL baselines ────────────────────────────────────────────────────
    normal_payloads = [
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>ok</html>",
        dnsish_bytes(3),
        b"ping",
        b"\x16\x03\x01" + os.urandom(200),  # TLS-ish handshake fragment (binary but short)
    ]
    for _ in range(6000):
        p = random.choice(normal_payloads)
        proto = 6 if p.startswith((b"GET", b"HTTP")) else 17
        dst_port = 80 if proto == 6 else (53 if p.startswith(b"\x12\x34") else random.choice([123, 5353, 1900]))
        rows.append(
            make_row(
                proto=proto,
                dst_port=dst_port,
                label="NORMAL",
                payload=p,
                packets=random.randint(3, 40),
                duration_ms=random.randint(30, 1500),
            )
        )

    # ── C2 beacons (tiny periodic TCP to suspicious ports) ──────────────────
    suspicious_ports = [4444, 1337, 31337, 5555, 6667, 9001, 4899]
    for _ in range(2500):
        port = random.choice(suspicious_ports)
        p = random.choice([b"ping", b"hello", b"\x01\x00\x00\x00", b"\xff\xfe\x00\x01"])
        rows.append(
            make_row(proto=6, dst_port=port, label="PROBE", payload=p, packets=random.randint(1, 4), duration_ms=random.randint(50, 3000))
        )

    # ── Slow scan / probe (few packets, many destinations simulated by ports) ─
    for _ in range(2500):
        port = random.choice([21, 22, 23, 25, 80, 445, 3389, 5900, 8080, 8443])
        p = b"SYN"
        rows.append(make_row(proto=6, dst_port=port, label="PROBE", payload=p, packets=random.randint(1, 3), duration_ms=random.randint(5, 120)))

    # ── UDP flood / amplification-ish (high pps, small payload) ──────────────
    for _ in range(2500):
        p = os.urandom(random.randint(10, 40))
        rows.append(make_row(proto=17, dst_port=random.choice([53, 123, 1900, 11211]), label="DOS", payload=p, packets=random.randint(800, 5000), duration_ms=random.randint(300, 3000)))

    # ── Exfil burst (short duration, big bytes, base64-ish) ──────────────────
    for _ in range(2000):
        p = b64ish_bytes(random.randint(800, 5000))
        rows.append(make_row(proto=6, dst_port=random.choice([443, 8443, 8080]), label="ATTACK", payload=p, packets=random.randint(10, 80), duration_ms=random.randint(100, 1200)))

    # ── Tunneling-like (structured + high packet/byte ratio) ─────────────────
    for _ in range(2000):
        p = dnsish_bytes(random.randint(4, 8)) + b"|" + b64ish_bytes(random.randint(200, 800))
        rows.append(make_row(proto=17, dst_port=53, label="ATTACK", payload=p, packets=random.randint(60, 600), duration_ms=random.randint(500, 8000)))

    # ── “Weird payload” anomalies (high entropy UDP high ports) ──────────────
    for _ in range(2500):
        p = os.urandom(random.randint(900, 4096))
        rows.append(make_row(proto=17, dst_port=random.randint(20000, 60000), label="PROBE", payload=p, packets=random.randint(1, 5), duration_ms=random.randint(5, 200)))

    df = pd.DataFrame(rows)
    df.to_csv(out_path, index=False)
    print(f"[+] Wrote {out_path} with {len(df):,} rows")


if __name__ == "__main__":
    main()

