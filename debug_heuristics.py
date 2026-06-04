import sys
import os
from scapy.all import IP, TCP, Raw

# Add current dir to path to import realtime_ids
sys.path.append(os.getcwd())

try:
    from realtime_ids import HeuristicEngine, Flow, FlowKey
    print("[+] Successfully imported HeuristicEngine")
except ImportError as e:
    print(f"[-] Import failed: {e}")
    sys.exit(1)

def test_attack(name, payload, dport=80):
    engine = HeuristicEngine()
    pkt = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=12345, dport=dport) / Raw(load=payload)
    
    # Create a dummy flow
    fkey = FlowKey("127.0.0.1", "127.0.0.1", 12345, dport, "TCP")
    flow = Flow(key=fkey)
    flow.pkt_count = 1
    
    result = engine.check(pkt, flow)
    
    if result:
        print(f"[MATCH] {name:<25} -> Detected as: {result[0]} (Rule: {result[1]}, Conf: {result[2]:.2f})")
    else:
        print(f"[FAIL ] {name:<25} -> NOT DETECTED")

print("\n--- Running Heuristic Diagnostic Suite ---")
test_attack("Wired SQLi (Union)", "UNI/**/ON SEL/**/ECT 1,2,3--")
test_attack("Wired XSS (svg)", "<svg/onload=alert(1)>")
test_attack("Wired Traversal (..%2f)", "..%2f..%2f..%2fetc%2fpasswd")
test_attack("Wired Cmd (c^m^d)", "c^m^d.e^x^e /c whoami")
test_attack("NOP Sled", b"\x90" * 10)
print("-------------------------------------------\n")
