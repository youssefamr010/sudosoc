import sys
import os
import re

# Mock the globals and dependencies so we don't trigger the whole IDS engine
PAYLOAD_SIGS = {
    b"\x90" * 8     : ("NOP-Sled / Shellcode",        False),
    b"UNION SELECT" : ("SQL Injection",                True ),
    b"../../"       : ("Directory Traversal",          True ),
}

# Add the regexes we just added
PAYLOAD_SIGS[b"REGEX:UNI[\\s/\\*\\+]+ON[\\s/\\*\\+]+SEL[\\s/\\*\\+]+ECT"] = ("Obfuscated SQLi", False)
PAYLOAD_SIGS[b"REGEX:<[\\s/]*script"] = ("XSS Attempt (Obfuscated)", True)
PAYLOAD_SIGS[b"REGEX:p[\\^]o[\\^]w[\\^]e[\\^]r"] = ("Obfuscated PowerShell", False)
PAYLOAD_SIGS[b"REGEX:\\.\\.[/%\\\\].*\\.\\.[/%\\\\]"] = ("Obfuscated Traversal", True)

WEB_SERVER_PORTS = {80, 443}

class MockCC:
    def payload_sig(self, *args): return 0.99

class HeuristicEngineLite:
    def __init__(self):
        self._compiled_sigs = []
        for sig, (name, web_safe) in PAYLOAD_SIGS.items():
            if sig.startswith(b"REGEX:"):
                pattern = sig[6:].decode("utf-8", "ignore")
                self._compiled_sigs.append((re.compile(pattern, re.IGNORECASE | re.DOTALL | re.MULTILINE), name, web_safe))
            else:
                self._compiled_sigs.append((sig.lower(), name, web_safe))

    def check(self, payload_bytes):
        payload_str = payload_bytes.decode("utf-8", "ignore")
        payload_lower = payload_bytes.lower()
        
        for sig_obj, name, web_safe in self._compiled_sigs:
            match = False
            if hasattr(sig_obj, "search"):
                if sig_obj.search(payload_str): match = True
            elif sig_obj in payload_lower:
                match = True
            
            if match: return name
        return None

def test(name, payload):
    engine = HeuristicEngineLite()
    res = engine.check(payload if isinstance(payload, bytes) else payload.encode())
    print(f"{'[OK]' if res else '[FAIL]'} {name:<25} -> {res}")

print("\n--- Diagnostic Test (Regex/Signature Layer) ---")
test("Obfuscated SQLi", "UNI/**/ON SEL/**/ECT 1,2,3")
test("Obfuscated XSS", "<svg/onload=alert(1)>")
test("Obfuscated Traversal", "..%2f..%2f..%2fetc/passwd")
test("Literal SQLi", "UNION SELECT 1,2,3")
test("NOP Sled", b"\x90" * 10)
print("----------------------------------------------\n")
