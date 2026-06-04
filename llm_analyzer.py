#!/usr/bin/env python3
"""
LLM Analyzer for SudoSOC IDS/IPS — Enhanced with Rule Generation & MITRE Mapping
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Integrates Generative AI (Llama 3.3 / Qwen) into the IDS pipeline for:
  1. Alert contextualization with SHAP explainability
  2. MITRE ATT&CK tactic/technique mapping
  3. Sigma detection rule generation
  4. Suricata/Snort rule generation
  5. Trusted agency verification
"""

import os
import json
import logging
import threading
from typing import Dict, Any, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LLMAnalyzer")

# Ensure rules directories exist
SIGMA_DIR = "rules/sigma"
SURICATA_DIR = "rules/suricata"
os.makedirs(SIGMA_DIR, exist_ok=True)
os.makedirs(SURICATA_DIR, exist_ok=True)

# ── MITRE ATT&CK Mapping Table ──────────────────────────────────────────────
# Pre-built mapping for common IDS attack types to ATT&CK tactics/techniques.
# The LLM can refine this, but we have a fast local fallback.
MITRE_MAP = {
    "Port Scan":          {"tactic": "TA0043", "tactic_name": "Reconnaissance",
                           "technique": "T1046", "technique_name": "Network Service Scanning"},
    "SYN Flood":          {"tactic": "TA0040", "tactic_name": "Impact",
                           "technique": "T1498.001", "technique_name": "Direct Network Flood"},
    "ICMP Flood":         {"tactic": "TA0040", "tactic_name": "Impact",
                           "technique": "T1498.001", "technique_name": "Direct Network Flood"},
    "SQL Injection":      {"tactic": "TA0001", "tactic_name": "Initial Access",
                           "technique": "T1190", "technique_name": "Exploit Public-Facing App"},
    "XSS Attempt":        {"tactic": "TA0001", "tactic_name": "Initial Access",
                           "technique": "T1190", "technique_name": "Exploit Public-Facing App"},
    "Path Traversal":     {"tactic": "TA0009", "tactic_name": "Collection",
                           "technique": "T1005", "technique_name": "Data from Local System"},
    "Directory Traversal":{"tactic": "TA0009", "tactic_name": "Collection",
                           "technique": "T1005", "technique_name": "Data from Local System"},
    "Shell Injection":    {"tactic": "TA0002", "tactic_name": "Execution",
                           "technique": "T1059", "technique_name": "Command and Scripting Interpreter"},
    "Netcat Reverse Shell":{"tactic":"TA0011", "tactic_name": "Command and Control",
                           "technique": "T1095", "technique_name": "Non-Application Layer Protocol"},
    "Encoded PowerShell": {"tactic": "TA0002", "tactic_name": "Execution",
                           "technique": "T1059.001", "technique_name": "PowerShell"},
    "NOP-Sled / Shellcode":{"tactic":"TA0002", "tactic_name": "Execution",
                           "technique": "T1203", "technique_name": "Exploitation for Client Execution"},
    "UDP Amplification":  {"tactic": "TA0040", "tactic_name": "Impact",
                           "technique": "T1498.002", "technique_name": "Reflection Amplification"},
    "DOS":                {"tactic": "TA0040", "tactic_name": "Impact",
                           "technique": "T1498", "technique_name": "Network Denial of Service"},
    "PROBE":              {"tactic": "TA0043", "tactic_name": "Reconnaissance",
                           "technique": "T1046", "technique_name": "Network Service Scanning"},
    "EXPLOIT":            {"tactic": "TA0001", "tactic_name": "Initial Access",
                           "technique": "T1190", "technique_name": "Exploit Public-Facing App"},
    "ACCESS":             {"tactic": "TA0006", "tactic_name": "Credential Access",
                           "technique": "T1110", "technique_name": "Brute Force"},
}


class LLMAnalyzer:
    """
    Multi-provider LLM with MITRE mapping, Sigma/Suricata rule generation,
    and SHAP-enriched analysis prompts.
    """

    def __init__(self, provider: str = None, api_key: Optional[str] = None,
                 model: str = None, ollama_base_url: str = None):
        self.provider = (provider or os.environ.get("LLM_PROVIDER", "auto")).lower()
        self.ollama_base_url = (ollama_base_url or os.environ.get("OLLAMA_BASE_URL")
                                or "http://localhost:11434").rstrip("/")

        self.groq_key = api_key or os.environ.get("GROQ_API_KEY") or ""
        self.hf_key = os.environ.get("HF_API_KEY") or ""

        # Load keys from files
        for fname, attr in [("groq_key.txt", "groq_key"), ("hf_token.txt", "hf_key")]:
            if not getattr(self, attr) and os.path.exists(fname):
                try:
                    with open(fname, "r", encoding="utf-8") as f:
                        setattr(self, attr, f.read().strip())
                except Exception:
                    pass

        self.model = model or os.environ.get("LLM_MODEL") or "llama3.3"

        import requests
        self.session = requests.Session()
        self.enabled = True
        self._resolved = None
        self._rule_count = 0
        self._lock = threading.Lock()
        self._resolve_provider()

        if self._resolved == "mock":
            logger.warning("LLMAnalyzer running in MOCK mode (no provider available).")
        else:
            logger.info(f"LLMAnalyzer provider={self._resolved} model={self.model}")

    def _resolve_provider(self):
        if self.provider in {"ollama", "groq", "hf", "mock"}:
            self._resolved = self.provider
            return
        if self._probe_ollama():
            self._resolved = "ollama"
            return
        if self.groq_key.strip().startswith("gsk_"):
            self._resolved = "groq"
            return
        if self.hf_key.strip().startswith("hf_"):
            self._resolved = "hf"
            return
        self._resolved = "mock"

    def _probe_ollama(self) -> bool:
        try:
            r = self.session.get(f"{self.ollama_base_url}/api/tags", timeout=2)
            return r.status_code == 200
        except Exception:
            return False

    # ── Core Chat Completion ─────────────────────────────────────────────────
    def _chat(self, prompt: str, max_tokens: int = 280) -> str:
        """Send a chat completion to the active provider. Returns raw text."""
        if self._resolved == "ollama":
            return self._ollama_chat(prompt, max_tokens)
        if self._resolved == "groq":
            return self._groq_chat(prompt, max_tokens)
        if self._resolved == "hf":
            return self._hf_chat(prompt, max_tokens)
        return ""

    def _ollama_chat(self, prompt: str, max_tokens: int) -> str:
        try:
            body = {"model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False, "options": {"temperature": 0.1}}
            r = self.session.post(f"{self.ollama_base_url}/api/chat",
                                  json=body, timeout=30)
            if r.status_code == 200:
                return (r.json().get("message") or {}).get("content", "")
        except Exception:
            pass
        return ""

    def _groq_chat(self, prompt: str, max_tokens: int) -> str:
        try:
            headers = {"Authorization": f"Bearer {self.groq_key}",
                       "Content-Type": "application/json"}
            body = {"model": "llama-3.3-70b-versatile",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens, "temperature": 0.1}
            r = self.session.post("https://api.groq.com/openai/v1/chat/completions",
                                  headers=headers, json=body, timeout=25)
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception:
            pass
        return ""

    def _hf_chat(self, prompt: str, max_tokens: int) -> str:
        try:
            headers = {"Authorization": f"Bearer {self.hf_key}",
                       "Content-Type": "application/json"}
            payload = {"inputs": f"<s>[INST] {prompt} [/INST]",
                       "parameters": {"max_new_tokens": max_tokens, "temperature": 0.1}}
            url = f"https://api-inference.huggingface.co/models/{os.environ.get('HF_MODEL', 'HuggingFaceH4/zephyr-7b-beta')}"
            r = self.session.post(url, headers=headers, json=payload, timeout=30)
            if r.status_code == 200:
                res = r.json()
                return res[0].get("generated_text", "") if isinstance(res, list) else str(res)
        except Exception:
            pass
        return ""

    # ── Flow Analysis ────────────────────────────────────────────────────────
    def analyze_flow(self, flow_data: Dict[str, Any],
                     metadata: Dict[str, Any]) -> Dict[str, Any]:
        prompt = (
            "Analyze this network flow and respond ONLY with JSON:\n"
            '{"verdict":"MALICIOUS"|"NORMAL","confidence":0-1,'
            '"explanation":"...","recommended_action":"BLOCK"|"ALLOW"}\n\n'
            f"flow={json.dumps(flow_data, ensure_ascii=False)}\n"
            f"meta={json.dumps(metadata, ensure_ascii=False)}\n"
        )
        text = self._chat(prompt)
        if text:
            return self._extract_json(text, flow_data)
        return self._mock_analysis(flow_data)

    def analyze(self, flow: Any, attack_type: str, rule: str,
                shap_context: str = "") -> str:
        """Enhanced analysis with SHAP context and MITRE mapping."""
        try:
            k = flow.key
            flow_data = {
                "src_ip": k.src_ip, "src_port": k.src_port,
                "dst_ip": k.dst_ip, "dst_port": k.dst_port,
                "proto": k.proto, "pkts": flow.pkt_count,
                "bytes": flow.byte_count,
            }

            # Get local MITRE mapping
            mitre = self.map_mitre_attack(attack_type)
            mitre_str = (f"MITRE ATT&CK: {mitre['tactic']} ({mitre['tactic_name']}) / "
                         f"{mitre['technique']} ({mitre['technique_name']})")

            prompt = (
                "You are a SOC analyst. An IDS alert fired.\n"
                "Write exactly 3 sentences:\n"
                "1: Threat assessment with confidence (low/medium/high)\n"
                "2: MITRE ATT&CK context\n"
                "3: Recommended immediate action\n\n"
                f"Attack: {attack_type}\n"
                f"Rule: {rule}\n"
                f"Flow: {k.src_ip}:{k.src_port} → {k.dst_ip}:{k.dst_port} [{k.proto}]\n"
                f"Stats: {flow.pkt_count} pkts, {flow.byte_count} bytes\n"
                f"{mitre_str}\n"
            )
            if shap_context:
                prompt += f"\n{shap_context}\n"

            text = self._chat(prompt, max_tokens=200)
            if text:
                return text.strip()
            return f"Heuristic: {rule} | {mitre_str}"
        except Exception:
            return f"Heuristic match: {rule}"

    # ── MITRE ATT&CK Mapping ────────────────────────────────────────────────
    def map_mitre_attack(self, attack_type: str) -> Dict[str, str]:
        """
        Map an attack type to MITRE ATT&CK tactic/technique.
        Uses local lookup table first, then LLM for unknown types.
        """
        # Check local mapping (fast)
        for key, mapping in MITRE_MAP.items():
            if key.lower() in attack_type.lower():
                return mapping

        # Check by partial match on common keywords
        attack_upper = attack_type.upper()
        if "SCAN" in attack_upper or "PROBE" in attack_upper:
            return MITRE_MAP["PROBE"]
        if "FLOOD" in attack_upper or "DOS" in attack_upper or "DDOS" in attack_upper:
            return MITRE_MAP["DOS"]
        if "SHELL" in attack_upper or "EXEC" in attack_upper:
            return MITRE_MAP["Shell Injection"]
        if "BRUTE" in attack_upper or "PASSWD" in attack_upper:
            return MITRE_MAP["ACCESS"]

        # Default fallback
        return {
            "tactic": "TA0001", "tactic_name": "Initial Access",
            "technique": "T1190", "technique_name": "Exploit Public-Facing App",
        }

    # ── Sigma Rule Generation ────────────────────────────────────────────────
    def generate_sigma_rule(self, alert_data: Dict[str, Any]) -> Optional[str]:
        """
        Generate a Sigma detection rule from alert features using LLM.
        Saves to rules/sigma/ directory.
        """
        prompt = (
            "Generate a Sigma detection rule in YAML format for this alert.\n"
            "Output ONLY the YAML rule, no explanation.\n\n"
            f"Attack: {alert_data.get('attack_type', 'Unknown')}\n"
            f"Source: {alert_data.get('src_ip', '?')}:{alert_data.get('src_port', '?')}\n"
            f"Dest: {alert_data.get('dst_ip', '?')}:{alert_data.get('dst_port', '?')}\n"
            f"Proto: {alert_data.get('proto', '?')}\n"
            f"Rule: {alert_data.get('rule', '?')}\n"
            f"Confidence: {alert_data.get('confidence', 0):.2f}\n"
        )

        text = self._chat(prompt, max_tokens=400)
        if not text:
            text = self._generate_sigma_fallback(alert_data)

        # Save to file
        with self._lock:
            self._rule_count += 1
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"sigma_{ts}_{self._rule_count}.yml"
            fpath = os.path.join(SIGMA_DIR, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(text)
            logger.info(f"Sigma rule saved: {fpath}")
        return text

    def _generate_sigma_fallback(self, alert: Dict) -> str:
        """Generate a basic Sigma rule without LLM."""
        attack = alert.get("attack_type", "Unknown").replace(" ", "_")
        mitre = self.map_mitre_attack(alert.get("attack_type", ""))
        return (
            f"title: SudoSOC Detection - {attack}\n"
            f"id: sudosoc-{datetime.now().strftime('%Y%m%d%H%M%S')}\n"
            f"status: experimental\n"
            f"description: Auto-generated by SudoSOC IDS\n"
            f"author: SudoSOC Adaptive Engine\n"
            f"date: {datetime.now().strftime('%Y/%m/%d')}\n"
            f"tags:\n"
            f"  - attack.{mitre['tactic_name'].lower().replace(' ', '_')}\n"
            f"  - {mitre['technique']}\n"
            f"logsource:\n"
            f"  category: network_connection\n"
            f"  product: zeek\n"
            f"detection:\n"
            f"  selection:\n"
            f"    dst_port: {alert.get('dst_port', 'any')}\n"
            f"  condition: selection\n"
            f"level: high\n"
        )

    # ── Suricata Rule Generation ─────────────────────────────────────────────
    def generate_suricata_rule(self, alert_data: Dict[str, Any]) -> Optional[str]:
        """Generate a Suricata/Snort rule from alert features."""
        prompt = (
            "Generate a single Suricata/Snort IDS rule for this alert.\n"
            "Output ONLY the rule line, no explanation.\n\n"
            f"Attack: {alert_data.get('attack_type', 'Unknown')}\n"
            f"Dest port: {alert_data.get('dst_port', 'any')}\n"
            f"Proto: {alert_data.get('proto', 'tcp')}\n"
            f"Rule: {alert_data.get('rule', '?')}\n"
        )

        text = self._chat(prompt, max_tokens=200)
        if not text:
            text = self._generate_suricata_fallback(alert_data)

        with self._lock:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"suricata_{ts}.rules"
            fpath = os.path.join(SURICATA_DIR, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(text.strip() + "\n")
            logger.info(f"Suricata rule saved: {fpath}")
        return text

    def _generate_suricata_fallback(self, alert: Dict) -> str:
        """Generate a basic Suricata rule without LLM."""
        proto = alert.get("proto", "tcp").lower()
        dst_port = alert.get("dst_port", "any")
        attack = alert.get("attack_type", "Unknown")
        sid = abs(hash(f"{attack}{dst_port}")) % 9000000 + 1000000
        return (
            f'alert {proto} any any -> any {dst_port} '
            f'(msg:"SudoSOC: {attack}"; '
            f'sid:{sid}; rev:1; '
            f'classtype:attempted-attack; priority:1;)'
        )

    # ── Agency Verification ──────────────────────────────────────────────────
    def verify_agency(self, sni: str, ip: str,
                      cert_info: Dict[str, Any]) -> Dict[str, Any]:
        if self._resolved == "mock":
            return {"is_trusted": False, "agency": None, "reason": "MOCK mode"}
        prompt = (
            "Is this a known trusted agency domain/cert?\n"
            'Respond JSON: {"is_trusted":true|false,"agency":"..."|null,"reason":"..."}\n\n'
            f"sni={sni}\nip={ip}\ncert={json.dumps(cert_info)}\n"
        )
        text = self._chat(prompt, max_tokens=150)
        if text:
            parsed = self._extract_json(text, {})
            return {
                "is_trusted": parsed.get("is_trusted", False),
                "agency": parsed.get("agency"),
                "reason": parsed.get("reason", parsed.get("explanation", ""))
            }
        return {"is_trusted": False, "agency": None, "reason": "LLM unavailable"}

    def query_json(self, prompt: str) -> Dict:
        text = self._chat(prompt, max_tokens=300)
        if text:
            return self._extract_json(text, {})
        return {}

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _extract_json(self, text: str, fallback_data: Dict) -> Dict:
        try:
            if "{" in text and "}" in text:
                text = "{" + text.split("{", 1)[1].rsplit("}", 1)[0] + "}"
            return json.loads(text)
        except Exception:
            return self._mock_analysis(fallback_data)

    def _mock_analysis(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        dst_port = flow_data.get("dst_port")
        if dst_port in [4444, 1337, 31337]:
            return {"verdict": "MALICIOUS", "confidence": 0.95,
                    "explanation": "Mock: Suspicious port detected.",
                    "recommended_action": "BLOCK", "agency_name": None}
        return {"verdict": "NORMAL", "confidence": 0.8,
                "explanation": "Mock: Standard traffic pattern.",
                "recommended_action": "ALLOW", "agency_name": None}

    def get_stats(self) -> Dict:
        return {
            "provider": self._resolved,
            "model": self.model,
            "enabled": self.enabled,
            "rules_generated": self._rule_count,
        }


if __name__ == "__main__":
    analyzer = LLMAnalyzer()
    test_flow = {"src_ip": "192.168.1.5", "dst_ip": "8.8.8.8",
                 "dst_port": 443, "protocol": 6}
    print(analyzer.analyze_flow(test_flow, {}))
    print(analyzer.map_mitre_attack("Port Scan"))
