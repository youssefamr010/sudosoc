"""
Enhanced MITM Addon for SudoSOC IDS/IPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Captures decrypted HTTPS flows with:
  - Payload entropy calculation (Shannon entropy)
  - Payload length variance tracking
  - TLS metadata (SNI, cipher, version)
  - IDS-aligned feature output
"""

import json
import math
import logging
from mitmproxy import http, tls
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO, filename="mitm_sniffer.log", filemode="a",
                    format="%(asctime)s %(levelname)s %(message)s")


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


class IDSSnifferAddon:
    def __init__(self):
        self.output_file = "decrypted_flows.jsonl"
        self.flow_count = 0
        self._payload_sizes = defaultdict(list)  # host → [sizes]
        logging.info("Enhanced IDS Sniffer Addon Initialized")

    def request(self, flow: http.HTTPFlow):
        """Analyze requests for suspicious patterns."""
        pass

    def response(self, flow: http.HTTPFlow):
        """
        Capture decrypted flow with enriched IDS features.
        """
        try:
            self.flow_count += 1

            # Extract payload data
            req_content = flow.request.content or b""
            resp_content = flow.response.content or b""
            combined_payload = req_content + resp_content

            # Compute entropy
            req_entropy = shannon_entropy(req_content)
            resp_entropy = shannon_entropy(resp_content)
            combined_entropy = shannon_entropy(combined_payload)

            # Track payload sizes for variance calculation
            host = flow.request.pretty_host
            req_size = len(req_content)
            resp_size = len(resp_content)
            self._payload_sizes[host].append(req_size + resp_size)

            # Compute payload length variance (last 10 flows to same host)
            recent_sizes = self._payload_sizes[host][-10:]
            if len(recent_sizes) >= 2:
                mean_size = sum(recent_sizes) / len(recent_sizes)
                variance = sum((s - mean_size) ** 2 for s in recent_sizes) / len(recent_sizes)
            else:
                variance = 0.0

            # TLS metadata
            tls_version = ""
            cipher_suite = ""
            try:
                if flow.server_conn and hasattr(flow.server_conn, "tls_version"):
                    tls_version = str(flow.server_conn.tls_version or "")
                if flow.server_conn and hasattr(flow.server_conn, "cipher"):
                    cipher_info = flow.server_conn.cipher
                    if cipher_info:
                        cipher_suite = str(cipher_info[0]) if isinstance(cipher_info, tuple) else str(cipher_info)
            except Exception:
                pass

            # Build IDS-aligned flow record
            flow_data = {
                # Timestamps
                "timestamp": datetime.utcnow().isoformat() + "Z",

                # Network identifiers
                "src_ip": flow.client_conn.address[0],
                "dst_ip": flow.server_conn.address[0] if flow.server_conn else "0.0.0.0",
                "src_port": flow.client_conn.address[1],
                "dst_port": flow.server_conn.address[1] if flow.server_conn else 0,
                "protocol": 6,  # TCP

                # HTTP metadata
                "method": flow.request.method,
                "host": host,
                "path": flow.request.path,
                "status_code": flow.response.status_code,
                "content_type": flow.response.headers.get("Content-Type", ""),
                "user_agent": flow.request.headers.get("User-Agent", ""),

                # IDS-aligned features
                "request_size": req_size,
                "response_size": resp_size,
                "bidirectional_bytes": req_size + resp_size,
                "bidirectional_packets": max(1, (req_size + resp_size) // 1460 + 1),

                # Entropy features (key for detecting encrypted/obfuscated payloads)
                "payload_entropy": round(combined_entropy, 4),
                "request_entropy": round(req_entropy, 4),
                "response_entropy": round(resp_entropy, 4),
                "payload_len_var": round(variance, 2),

                # TLS metadata
                "sni": flow.client_conn.sni or "",
                "tls_version": tls_version,
                "cipher_suite": cipher_suite,

                # Flags
                "is_https": flow.request.scheme == "https",
                "is_high_volume": int((req_size + resp_size) > 1_000_000),

                # Decrypted content for heuristic scanning
                "payload_snippet": combined_payload[:1024].decode("utf-8", errors="ignore"),
            }

            # Write to JSONL for IDS ingestion
            with open(self.output_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(flow_data, ensure_ascii=False) + "\n")

            logging.info(
                f"Flow #{self.flow_count}: {host} {flow.request.method} "
                f"{flow.response.status_code} entropy={combined_entropy:.2f} "
                f"size={req_size + resp_size}"
            )

        except Exception as e:
            logging.error(f"Error capturing flow: {e}")


addons = [
    IDSSnifferAddon()
]
